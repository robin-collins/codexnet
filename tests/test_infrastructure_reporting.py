"""Mixed SNMP/SSH infrastructure report correlation tests."""

from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from field_discovery.infrastructure_reporting import (
    _first,
    _rows,
    _snmp_record,
    _ssh_records,
    _timestamp,
    build_infrastructure_model,
)
from field_discovery.reporting import build_report_model, deterministic_docx, deterministic_json
from field_discovery.repository import Repository

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)


def populated(tmp_path: Path) -> tuple[Repository, int]:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    repository = Repository.open(root / "discovery.db", data_root=root)
    deployment = repository.upsert_deployment("mixed", "Mixed Fixture", NOW.isoformat())
    for key, address in (
        ("switch-a", "192.0.2.10"),
        ("ambiguous-a", "192.0.2.20"),
        ("ambiguous-b", "192.0.2.20"),
        ("asset-a", "192.0.2.40"),
    ):
        device = repository.upsert_device(deployment, key, NOW.isoformat())
        repository.connection.execute(
            "INSERT INTO device_aliases(device_id, alias_kind, alias_value, confidence, source, "
            "observed_at) VALUES (?, 'ipv4', ?, 1.0, 'fixture', ?)",
            (device, address, NOW.isoformat()),
        )
        if key == "switch-a":
            repository.connection.execute(
                "INSERT INTO device_aliases(device_id, alias_kind, alias_value, confidence, "
                "source, observed_at) VALUES (?, 'ipv4', ?, 1.0, 'fixture-repeat', ?)",
                (device, address, "2026-07-15T12:00:01+00:00"),
            )
    fixture = json.loads(
        (Path(__file__).parent / "fixtures/reporting/mixed-switch-infrastructure.json").read_text()
    )
    for fact_type, value, source, observed_at, confidence in fixture["observations"]:
        repository.record_observation(
            deployment,
            subject_type="network_device_target",
            subject_id=None,
            fact_type=fact_type,
            fact_value=value,
            confidence=confidence,
            inferred=False,
            source=source,
            observed_at=observed_at,
        )
    return repository, deployment


def test_mixed_fixture_correlates_unique_targets_and_preserves_conflicts(tmp_path: Path) -> None:
    repository, deployment = populated(tmp_path)
    first = build_infrastructure_model(repository, deployment, generated_at=NOW)
    second = build_infrastructure_model(repository, deployment, generated_at=NOW)
    assert first == second

    port = next(item for item in first["switch_ports"] if item["key"] == "7")
    assert port["device_key"] == "switch-a"
    description = port["fields"]["description"]
    assert description["conflict"] is True
    assert description["alternatives"] == ["Fixture old uplink", "Fixture new uplink"]
    assert description["evidence"][0]["stale"] is True
    assert description["evidence"][1]["source"] == "ssh:cisco_ios"
    assert port["fields"]["learned_mac"]["value"] == "02:00:00:00:00:50"
    assert port["fields"]["poe_power_watts"]["value"] == 8.4

    bridge = next(item for item in first["switch_ports"] if item["key"] == "bridge:7")
    assert bridge["fields"]["mapping_status"]["value"] == "unresolved_bridge_port"
    assert any(issue["kind"] == "incomplete_bridge_entry" for issue in first["data_quality"])
    assert any(issue["kind"] == "ambiguous_target" for issue in first["data_quality"])
    assert any(issue["kind"] == "unmatched_target" for issue in first["data_quality"])
    assert any(
        issue["kind"] == "malformed_collector_observation" for issue in first["data_quality"]
    )
    assert any(issue["kind"] == "unmapped_ssh_fact" for issue in first["data_quality"])

    vlan = first["vlans"][0]["fields"]["name"]
    assert vlan["conflict"] is True
    assert len(first["neighbors"]) == 2
    assert first["printers"][0]["fields"]["supply.level"]["value"] == {
        "raw_value": "-2",
        "status": "unknown",
    }
    assert (
        first["ups"][0]["fields"]["battery.estimated_minutes_remaining"]["evidence"][0]["unit"]
        == "minutes"
    )
    assert first["environment"]
    assert first["firmware"]
    assert "vulnerability status was not assessed" in first["limitations"][1]
    repository.close()


def test_report_json_and_docx_expose_infrastructure_evidence(tmp_path: Path) -> None:
    repository, deployment = populated(tmp_path)
    model = build_report_model(repository, deployment, generated_at=NOW)
    assert model["schema_version"] == 2
    assert model["summary"]["infrastructure_conflict_count"] == 2
    assert deterministic_json(model) == deterministic_json(
        build_report_model(repository, deployment, generated_at=NOW)
    )
    with zipfile.ZipFile(__import__("io").BytesIO(deterministic_docx(model))) as archive:
        xml = archive.read("word/document.xml").decode()
    for heading in (
        "Switch port maps",
        "VLAN inventory",
        "Switch neighbors",
        "Printer inventory",
        "UPS inventory",
        "Environment readings",
        "Firmware versions",
        "Infrastructure data quality",
        "Source",
        "Age (days)",
        "Stale",
        "Conflict",
    ):
        assert heading in xml
    assert "vulnerability status was not assessed" in xml
    repository.close()


@pytest.mark.parametrize(
    ("fact_type", "expected"),
    [
        ("snmp.interface.mac", ("switch_ports", "3", "mac")),
        ("snmp.poe.port.class", ("switch_ports", "poe:3", "class")),
        ("snmp.vlan.name", ("vlans", "3", "name")),
        ("snmp.neighbor.mac", ("neighbors", "3", "mac")),
        ("snmp.lldp.remote.port_id", ("neighbors", "3", "remote.port_id")),
        ("snmp.printer.serial", ("printers", "3", "serial")),
        ("snmp.ups.battery", ("ups", "3", "battery")),
        ("snmp.environment.value", ("environment", "3", "value")),
        ("snmp.software.revision", ("firmware", "3", "software.revision")),
        ("snmp.system.name", None),
    ],
)
def test_snmp_fact_routing(fact_type: str, expected: tuple[str, str, str] | None) -> None:
    assert _snmp_record(fact_type, {"index": "3"}) == expected


@pytest.mark.parametrize(
    ("fact_type", "payload", "section"),
    [
        ("ssh.show_mac_address_table", {"value": {"port": "1", "mac": "aa"}}, "switch_ports"),
        ("ssh.show_cdp_neighbors", {"value": {"port": "1", "neighbor": "edge"}}, "neighbors"),
        ("ssh.show_poe", {"value": {"port": "1", "status": "on"}}, "switch_ports"),
        ("ssh.show_interfaces", {"value": {"interface": "1", "state": "up"}}, "switch_ports"),
        ("ssh.show_vlans", {"value": {"vid": 10, "name": "users"}}, "vlans"),
        ("ssh.show_temperature", {"value": {"index": 1, "value": 20}}, "environment"),
        ("ssh.show_inventory", {"value": {"serial": "synthetic"}}, "firmware"),
    ],
)
def test_ssh_command_adapters(fact_type: str, payload: dict[str, object], section: str) -> None:
    assert _ssh_records(fact_type, payload)[0][0] == section


def test_adapter_helpers_reject_unknown_shapes_and_timestamp_without_zone() -> None:
    assert _rows("raw") == ()
    assert _rows([{"a": 1}, "bad"]) == ({"a": 1},)
    assert _first({"a": "", "b": 2}, ("a", "b")) == 2
    assert _first({}, ("missing",)) is None
    assert _ssh_records("ssh.show_mac", {"value": {"port": "1"}}) == []
    assert _ssh_records("ssh.show_lldp", {"value": {"port": "1"}}) == []
    assert _ssh_records("ssh.show_vlans", {"value": {"name": "none"}}) == []
    assert _ssh_records("ssh.show_version", {"value": {"ignored": "value"}}) == []
    assert _ssh_records("ssh.show_unknown", {"value": {"ignored": "value"}}) == []
    with pytest.raises(ValueError, match="timezone"):
        _timestamp("2026-07-15T12:00:00")


def test_stale_boundary_and_future_observation_are_not_stale(tmp_path: Path) -> None:
    repository, deployment = populated(tmp_path)
    model = build_infrastructure_model(
        repository, deployment, generated_at=NOW, stale_after=timedelta(days=14, hours=12)
    )
    port = next(item for item in model["switch_ports"] if item["key"] == "7")
    assert port["fields"]["description"]["evidence"][0]["stale"] is False
    repository.close()
