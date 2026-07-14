"""AD and UniFi report enrichment, diagram, and redaction tests."""

from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest

from field_discovery import platform_reporting
from field_discovery.platform_reporting import (
    PlatformReportingError,
    build_platform_report_model,
)
from field_discovery.redaction import REDACTED, Redactor
from field_discovery.reporting import build_report_model, deterministic_docx, deterministic_json
from field_discovery.repository import Repository

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
OBSERVED = "2026-07-14T00:00:00+00:00"


def repository(tmp_path: Path) -> tuple[Repository, int]:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    repo = Repository.open(root / "discovery.db", data_root=root)
    deployment = repo.upsert_deployment("fixture", "Fixture Site", OBSERVED)
    return repo, deployment


def populate_platforms(repo: Repository, deployment: int) -> None:
    unifi_run = repo.start_run(deployment, "unifi", OBSERVED)
    repo.connection.execute(
        "INSERT INTO collector_errors"
        "(collector_run_id,category,detail,retryable,source,observed_at) "
        "VALUES (?, 'permission_denied', 'alarms unavailable', 0, 'unifi', ?)",
        (unifi_run, OBSERVED),
    )
    repo.finish_run(unifi_run, "partial", OBSERVED, 2)
    ad_run = repo.start_run(deployment, "ad", OBSERVED)
    repo.connection.execute(
        "INSERT INTO collector_errors"
        "(collector_run_id,category,detail,retryable,source,observed_at) "
        "VALUES (?, 'ad_partial_query', 'trust read unavailable', 0, 'ad_ldap', ?)",
        (ad_run, OBSERVED),
    )
    repo.finish_run(ad_run, "partial", OBSERVED, 3)

    site_id = repo.connection.execute(
        "INSERT INTO unifi_sites"
        "(deployment_id,controller_key,site_key,display_name,source,observed_at) "
        "VALUES (?, 'controller.invalid:443', 'site-a', 'Synthetic Alpha', 'unifi', ?)",
        (deployment, OBSERVED),
    ).lastrowid
    assert site_id is not None
    switch_id = repo.connection.execute(
        "INSERT INTO unifi_entities"
        "(unifi_site_id,entity_kind,controller_entity_id,display_name,state,active,"
        "attributes_json,source,observed_at) "
        "VALUES (?, 'switch', 'sw-1', 'Switch One', 'connected', 1, '{}', 'unifi', ?)",
        (site_id, OBSERVED),
    ).lastrowid
    network_id = repo.connection.execute(
        "INSERT INTO unifi_entities"
        "(unifi_site_id,entity_kind,controller_entity_id,display_name,state,active,"
        "attributes_json,source,observed_at) "
        "VALUES (?, 'network', 'net-1', 'LAN', NULL, 1, "
        '\'{"vlan":20,"purpose":"corporate","credential":"omitted"}\', '
        "'unifi', ?)",
        (site_id, OBSERVED),
    ).lastrowid
    assert switch_id is not None and network_id is not None
    repo.connection.execute(
        "INSERT INTO unifi_relationships"
        "(unifi_site_id,local_entity_id,remote_entity_id,relationship_kind,source,observed_at) "
        "VALUES (?, ?, ?, 'uplink', 'unifi', ?)",
        (site_id, switch_id, network_id, OBSERVED),
    )
    repo.connection.execute(
        "INSERT INTO unifi_relationships"
        "(unifi_site_id,local_entity_id,remote_identifier,relationship_kind,source,observed_at) "
        "VALUES (?, ?, 'site-a:device:unknown', 'uplink', 'unifi', ?)",
        (site_id, network_id, OBSERVED),
    )
    other_deployment = repo.upsert_deployment("other", "Other Site", OBSERVED)
    other_site = repo.connection.execute(
        "INSERT INTO unifi_sites"
        "(deployment_id,controller_key,site_key,display_name,source,observed_at) "
        "VALUES (?, 'other.invalid:443', 'other', 'Other', 'unifi', ?)",
        (other_deployment, OBSERVED),
    ).lastrowid
    assert other_site is not None
    cross_deployment_entity = repo.connection.execute(
        "INSERT INTO unifi_entities"
        "(unifi_site_id,entity_kind,controller_entity_id,display_name,state,active,"
        "attributes_json,source,observed_at) "
        "VALUES (?, 'switch', 'other-sw', 'Other Switch', NULL, 1, '{}', 'unifi', ?)",
        (other_site, OBSERVED),
    ).lastrowid
    assert cross_deployment_entity is not None
    repo.connection.execute(
        "INSERT INTO unifi_relationships"
        "(unifi_site_id,local_entity_id,remote_entity_id,relationship_kind,source,observed_at) "
        "VALUES (?, ?, ?, 'reported_remote', 'unifi', ?)",
        (site_id, switch_id, cross_deployment_entity, OBSERVED),
    )
    repo.connection.execute(
        "INSERT INTO observations"
        "(deployment_id,subject_type,fact_type,fact_value_json,confidence,inferred,"
        "source,observed_at) "
        "VALUES (?, 'unifi_coverage', 'endpoint_omitted', "
        '\'{"site":"site-a","resource":"events","detail":"not supported"}\', '
        "1.0, 0, 'unifi', ?)",
        (deployment, OBSERVED),
    )

    domain_id = repo.connection.execute(
        "INSERT INTO ad_domains"
        "(deployment_id,domain_key,dns_name,forest_name,functional_level,source,observed_at) "
        "VALUES (?, 'example.invalid', 'example.invalid', 'example.invalid', '7', 'ad_ldap', ?)",
        (deployment, OBSERVED),
    ).lastrowid
    assert domain_id is not None
    site_dn = "CN=Site-A,CN=Sites,CN=Configuration,DC=example,DC=invalid"
    entity_rows = (
        ("site-guid", "site", "Site-A", None, None, {"distinguishedName": [site_dn]}),
        (
            "subnet-guid",
            "subnet",
            "192.0.2.0/24",
            None,
            None,
            {"siteObject": [site_dn], "unicodePwd": "not-reportable"},
        ),
        ("subnet-orphan", "subnet", "198.51.100.0/24", None, None, {}),
        (
            "dc-guid",
            "domain_controller",
            "DC1",
            "dc1.example.invalid",
            "Synthetic Server",
            {},
        ),
        ("dc-guid:dns", "server_role", "dns_server", None, None, {}),
    )
    for key, kind, name, dns_name, operating_system, attributes in entity_rows:
        repo.connection.execute(
            "INSERT INTO ad_entities"
            "(ad_domain_id,entity_key,entity_kind,display_name,dns_name,operating_system,"
            "attributes_json,source,observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'ad_ldap', ?)",
            (
                domain_id,
                key,
                kind,
                name,
                dns_name,
                operating_system,
                json.dumps(attributes, sort_keys=True),
                OBSERVED,
            ),
        )
    repo.connection.execute(
        "INSERT INTO observations"
        "(deployment_id,subject_type,fact_type,fact_value_json,confidence,inferred,"
        "source,observed_at) "
        "VALUES (?, 'ad_directory', 'ad.trust', "
        '\'{"name":["other.invalid"],"trustDirection":[3],"trustType":[2],'
        '"supplementalCredentials":"not-reportable"}\', 1.0, 0, \'ad_ldap\', ?)',
        (deployment, OBSERVED),
    )


def test_platform_model_is_deterministic_source_labelled_and_allowlisted(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    populate_platforms(repo, deployment)
    first = build_platform_report_model(repo, deployment, generated_at=NOW)
    second = build_platform_report_model(repo, deployment, generated_at=NOW)
    assert first == second
    unifi = first["unifi"]
    active_directory = first["active_directory"]
    assert len(unifi["sites"]) == 1
    assert {edge["source"] for edge in unifi["diagram"]["edges"]} == {"unifi"}
    assert {node["source"] for node in unifi["diagram"]["nodes"]} == {"unifi"}
    assert {node["age_days"] for node in unifi["diagram"]["nodes"]} == {1.5}
    assert {note["category"] for note in unifi["coverage_notes"]} == {
        "permission_denied",
        "endpoint_omitted",
    }
    assert active_directory["domains"][0]["entities"][0]["age_days"] == 1.5
    assert {node["source"] for node in active_directory["diagram"]["nodes"]} == {"ad_ldap"}
    assert active_directory["trusts"][0]["direction"] == ("3",)
    assert "site_subnet" in {edge["kind"] for edge in active_directory["diagram"]["edges"]}
    payload = json.dumps(first, sort_keys=True)
    assert "unicodePwd" not in payload
    assert "supplementalCredentials" not in payload
    assert "credential" not in payload
    assert first["unifi"]["diagram"]["mermaid"].startswith("flowchart LR\n")
    repo.close()


def test_json_docx_diagrams_and_coverage_share_redaction_boundary(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    populate_platforms(repo, deployment)
    repo.connection.execute(
        "UPDATE unifi_sites SET display_name='Site synthetic-secret' WHERE deployment_id=?",
        (deployment,),
    )
    repo.redactor = Redactor(["synthetic-secret"])
    model = build_report_model(repo, deployment, generated_at=NOW)
    json_payload = deterministic_json(model).decode()
    assert "synthetic-secret" not in json_payload
    assert REDACTED in json_payload
    assert "UniFi topology" not in json_payload
    docx = deterministic_docx(model)
    with zipfile.ZipFile(BytesIO(docx)) as archive:
        xml = archive.read("word/document.xml").decode()
        assert "UniFi topology and inventory" in xml
        assert "Active Directory structure and trusts" in xml
        assert "Coverage and permissions" in xml
        assert "site_subnet" in xml
        assert "synthetic-secret" not in xml
        assert REDACTED in xml
        assert "unicodePwd" not in xml
        assert "supplementalCredentials" not in xml
    repo.close()


def test_empty_platforms_and_trust_without_domain_are_disclosed_safely(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    empty = build_platform_report_model(repo, deployment, generated_at=NOW)
    assert empty["unifi"]["sites"] == []
    assert empty["active_directory"]["domains"] == []
    repo.connection.execute(
        "INSERT INTO observations"
        "(deployment_id,subject_type,fact_type,fact_value_json,confidence,inferred,"
        "source,observed_at) "
        "VALUES (?, 'ad_directory', 'ad.trust', '{}', 1.0, 0, 'ad_ldap', ?)",
        (deployment, OBSERVED),
    )
    trust_only = build_platform_report_model(repo, deployment, generated_at=NOW)
    assert trust_only["active_directory"]["trusts"][0]["name"] == "Undisclosed trust"
    assert trust_only["active_directory"]["diagram"]["edges"] == []
    repo.close()


def test_platform_helpers_reject_malformed_repository_values() -> None:
    with pytest.raises(PlatformReportingError, match="invalid JSON"):
        platform_reporting._json_object("{")
    with pytest.raises(PlatformReportingError, match="must be an object"):
        platform_reporting._json_object("[]")
    with pytest.raises(PlatformReportingError, match="invalid timestamp"):
        platform_reporting._age("invalid", NOW)
    with pytest.raises(PlatformReportingError, match="timezone"):
        platform_reporting._age("2026-01-01T00:00:00", NOW)
    assert platform_reporting._values({"name": "one"}, "name") == ("one",)
    assert platform_reporting._values({"name": [None, "", "two"]}, "name") == ("two",)
    diagram = platform_reporting._diagram(
        [
            {
                "id": "n1",
                "kind": "site",
                "label": 'Site "A"\nLine',
                "source": "fixture",
                "observed_at": OBSERVED,
                "age_days": 1.5,
            },
            {
                "id": "n1",
                "kind": "site",
                "label": "Site A",
                "source": "fixture",
                "observed_at": OBSERVED,
                "age_days": 1.5,
            },
        ],
        [],
    )
    assert len(diagram["nodes"]) == 1
    assert "Site A<br/>" in diagram["mermaid"]
