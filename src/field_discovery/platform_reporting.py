"""Deterministic UniFi and Active Directory report enrichment."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime

from field_discovery.repository import Repository
from field_discovery.topology import node_id


class PlatformReportingError(ValueError):
    """Normalized platform data cannot be represented safely."""


def _json_object(raw: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PlatformReportingError("platform inventory contains invalid JSON") from exc
    if not isinstance(value, dict):
        raise PlatformReportingError("platform inventory attributes must be an object")
    return {str(key): item for key, item in value.items()}


def _age(observed_at: str, generated_at: datetime) -> float:
    try:
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlatformReportingError("platform inventory contains an invalid timestamp") from exc
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise PlatformReportingError("platform inventory timestamp must include a timezone")
    return round(max(0.0, (generated_at - observed.astimezone(UTC)).total_seconds()) / 86_400, 3)


def _values(attributes: Mapping[str, object], name: str) -> tuple[str, ...]:
    value = attributes.get(name)
    items = value if isinstance(value, list) else [value]
    return tuple(str(item) for item in items if item not in {None, ""})


def _edge(
    source: str, target: str, kind: str, source_name: str, observed_at: str
) -> dict[str, object]:
    return {
        "from": source,
        "to": target,
        "kind": kind,
        "source": source_name,
        "observed_at": observed_at,
    }


def _diagram(nodes: list[dict[str, object]], edges: list[dict[str, object]]) -> dict[str, object]:
    unique_nodes = {item["id"]: item for item in nodes}
    ordered_nodes = sorted(unique_nodes.values(), key=lambda item: str(item["id"]))
    ordered_edges = sorted(
        edges,
        key=lambda item: (
            str(item["from"]),
            str(item["to"]),
            str(item["kind"]),
            str(item["observed_at"]),
        ),
    )
    lines = ["flowchart LR"]
    for item in ordered_nodes:
        label = str(item["label"]).replace('"', "'").replace("\n", " ")
        lines.append(f'  {item["id"]}["{label}<br/>[{item["kind"]}]"]')
    for edge_item in ordered_edges:
        label = f"{edge_item['kind']}; {edge_item['source']}; {edge_item['observed_at']}"
        lines.append(f"  {edge_item['from']} -->|{label}| {edge_item['to']}")
    return {"nodes": ordered_nodes, "edges": ordered_edges, "mermaid": "\n".join(lines) + "\n"}


def _coverage_notes(
    repository: Repository, deployment_id: int, collector: str
) -> list[dict[str, object]]:
    rows = repository.connection.execute(
        "SELECT e.category, e.detail, e.retryable, e.source, e.observed_at "
        "FROM collector_errors e JOIN collector_runs r ON r.id=e.collector_run_id "
        "WHERE r.deployment_id=? AND r.collector=? "
        "ORDER BY e.observed_at,e.category,e.id",
        (deployment_id, collector),
    ).fetchall()
    return [
        {
            "category": str(row["category"]),
            "detail": str(row["detail"]),
            "retryable": bool(row["retryable"]),
            "source": str(row["source"]),
            "observed_at": str(row["observed_at"]),
        }
        for row in rows
    ]


def _unifi_model(
    repository: Repository, deployment_id: int, generated_at: datetime
) -> dict[str, object]:
    sites = repository.connection.execute(
        "SELECT * FROM unifi_sites WHERE deployment_id=? "
        "ORDER BY controller_key,site_key,observed_at,id",
        (deployment_id,),
    ).fetchall()
    site_items: list[dict[str, object]] = []
    nodes: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    entity_ids: dict[int, str] = {}
    for site in sites:
        site_ref = node_id("unifi_site", f"{site['controller_key']}:{site['site_key']}")
        nodes.append(
            {
                "id": site_ref,
                "kind": "unifi_site",
                "label": str(site["display_name"] or site["site_key"]),
                "source": str(site["source"]),
                "observed_at": str(site["observed_at"]),
                "age_days": _age(str(site["observed_at"]), generated_at),
            }
        )
        entities: list[dict[str, object]] = []
        rows = repository.connection.execute(
            "SELECT * FROM unifi_entities WHERE unifi_site_id=? "
            "ORDER BY entity_kind,controller_entity_id,observed_at,id",
            (int(site["id"]),),
        ).fetchall()
        for row in rows:
            attributes = _json_object(str(row["attributes_json"]))
            entity_ref = node_id(
                f"unifi_{row['entity_kind']}",
                f"{site['controller_key']}:{site['site_key']}:{row['controller_entity_id']}",
            )
            entity_ids[int(row["id"])] = entity_ref
            nodes.append(
                {
                    "id": entity_ref,
                    "kind": str(row["entity_kind"]),
                    "label": str(row["display_name"] or row["controller_entity_id"]),
                    "source": str(row["source"]),
                    "observed_at": str(row["observed_at"]),
                    "age_days": _age(str(row["observed_at"]), generated_at),
                }
            )
            edges.append(
                _edge(site_ref, entity_ref, "contains", str(row["source"]), str(row["observed_at"]))
            )
            entities.append(
                {
                    "kind": str(row["entity_kind"]),
                    "name": row["display_name"],
                    "state": row["state"],
                    "active": bool(row["active"]),
                    "vlan": attributes.get("vlan"),
                    "purpose": attributes.get("purpose"),
                    "source": str(row["source"]),
                    "observed_at": str(row["observed_at"]),
                    "age_days": _age(str(row["observed_at"]), generated_at),
                }
            )
        site_items.append(
            {
                "controller": str(site["controller_key"]),
                "site": str(site["site_key"]),
                "name": site["display_name"],
                "source": str(site["source"]),
                "observed_at": str(site["observed_at"]),
                "entities": entities,
            }
        )
    relationship_rows = repository.connection.execute(
        "SELECT r.*,s.controller_key,s.site_key FROM unifi_relationships r "
        "JOIN unifi_sites s ON s.id=r.unifi_site_id WHERE s.deployment_id=? "
        "ORDER BY s.controller_key,s.site_key,r.relationship_kind,r.id",
        (deployment_id,),
    ).fetchall()
    for row in relationship_rows:
        local = entity_ids.get(int(row["local_entity_id"]))
        if local is None:  # pragma: no cover - JOIN and foreign-key invariant
            continue
        if row["remote_entity_id"] is not None:
            remote = entity_ids.get(int(row["remote_entity_id"]))
            if remote is None:
                remote = node_id("unifi_remote", f"entity:{row['remote_entity_id']}")
                nodes.append(
                    {
                        "id": remote,
                        "kind": "unresolved",
                        "label": "Unresolved endpoint",
                        "source": str(row["source"]),
                        "observed_at": str(row["observed_at"]),
                        "age_days": _age(str(row["observed_at"]), generated_at),
                    }
                )
        else:
            remote = node_id("unifi_remote", str(row["remote_identifier"]))
            nodes.append(
                {
                    "id": remote,
                    "kind": "unresolved",
                    "label": "Unresolved endpoint",
                    "source": str(row["source"]),
                    "observed_at": str(row["observed_at"]),
                    "age_days": _age(str(row["observed_at"]), generated_at),
                }
            )
        edges.append(
            _edge(
                local,
                remote,
                str(row["relationship_kind"]),
                str(row["source"]),
                str(row["observed_at"]),
            )
        )
    notes = _coverage_notes(repository, deployment_id, "unifi")
    observation_rows = repository.connection.execute(
        "SELECT fact_type,fact_value_json,source,observed_at FROM observations "
        "WHERE deployment_id=? AND subject_type='unifi_coverage' "
        "ORDER BY fact_type,observed_at,id",
        (deployment_id,),
    ).fetchall()
    for row in observation_rows:
        detail = _json_object(str(row["fact_value_json"]))
        notes.append(
            {
                "category": str(row["fact_type"]),
                "detail": detail.get("detail", "Coverage unavailable"),
                "resource": detail.get("resource"),
                "site": detail.get("site"),
                "retryable": False,
                "source": str(row["source"]),
                "observed_at": str(row["observed_at"]),
            }
        )
    return {"sites": site_items, "diagram": _diagram(nodes, edges), "coverage_notes": notes}


def _ad_model(
    repository: Repository, deployment_id: int, generated_at: datetime
) -> dict[str, object]:
    domains = repository.connection.execute(
        "SELECT * FROM ad_domains WHERE deployment_id=? ORDER BY domain_key,observed_at,id",
        (deployment_id,),
    ).fetchall()
    domain_items: list[dict[str, object]] = []
    nodes: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    for domain in domains:
        domain_ref = node_id("ad_domain", str(domain["domain_key"]))
        nodes.append(
            {
                "id": domain_ref,
                "kind": "domain",
                "label": str(domain["dns_name"]),
                "source": str(domain["source"]),
                "observed_at": str(domain["observed_at"]),
                "age_days": _age(str(domain["observed_at"]), generated_at),
            }
        )
        entities: list[dict[str, object]] = []
        entity_rows = repository.connection.execute(
            "SELECT * FROM ad_entities WHERE ad_domain_id=? "
            "ORDER BY entity_kind,entity_key,observed_at,id",
            (int(domain["id"]),),
        ).fetchall()
        site_dns: dict[str, str] = {}
        for row in entity_rows:
            if row["entity_kind"] != "site":
                continue
            attributes = _json_object(str(row["attributes_json"]))
            site_ref = node_id("ad_site", f"{domain['domain_key']}:{row['entity_key']}")
            for distinguished_name in _values(attributes, "distinguishedName"):
                site_dns[distinguished_name.casefold()] = site_ref
        for row in entity_rows:
            attributes = _json_object(str(row["attributes_json"]))
            entity_ref = node_id(
                f"ad_{row['entity_kind']}",
                f"{domain['domain_key']}:{row['entity_key']}",
            )
            label = str(row["display_name"] or row["dns_name"] or row["entity_kind"])
            nodes.append(
                {
                    "id": entity_ref,
                    "kind": str(row["entity_kind"]),
                    "label": label,
                    "source": str(row["source"]),
                    "observed_at": str(row["observed_at"]),
                    "age_days": _age(str(row["observed_at"]), generated_at),
                }
            )
            if row["entity_kind"] == "subnet":
                targets = _values(attributes, "siteObject")
                target = site_dns.get(targets[0].casefold()) if targets else None
                edges.append(
                    _edge(
                        target or domain_ref,
                        entity_ref,
                        "site_subnet",
                        str(row["source"]),
                        str(row["observed_at"]),
                    )
                )
            else:
                edges.append(
                    _edge(
                        domain_ref,
                        entity_ref,
                        "directory_contains",
                        str(row["source"]),
                        str(row["observed_at"]),
                    )
                )
            entities.append(
                {
                    "kind": str(row["entity_kind"]),
                    "name": row["display_name"],
                    "dns_name": row["dns_name"],
                    "operating_system": row["operating_system"],
                    "source": str(row["source"]),
                    "observed_at": str(row["observed_at"]),
                    "age_days": _age(str(row["observed_at"]), generated_at),
                }
            )
        domain_items.append(
            {
                "domain": str(domain["dns_name"]),
                "forest": domain["forest_name"],
                "functional_level": domain["functional_level"],
                "source": str(domain["source"]),
                "observed_at": str(domain["observed_at"]),
                "entities": entities,
            }
        )
    trust_rows = repository.connection.execute(
        "SELECT fact_value_json,source,observed_at FROM observations "
        "WHERE deployment_id=? AND subject_type='ad_directory' AND fact_type='ad.trust' "
        "ORDER BY observed_at,id",
        (deployment_id,),
    ).fetchall()
    trusts: list[dict[str, object]] = []
    for row in trust_rows:
        attributes = _json_object(str(row["fact_value_json"]))
        names = _values(attributes, "name")
        trust_name = names[0] if names else "Undisclosed trust"
        trust_ref = node_id("ad_trust", trust_name)
        nodes.append(
            {
                "id": trust_ref,
                "kind": "trust",
                "label": trust_name,
                "source": str(row["source"]),
                "observed_at": str(row["observed_at"]),
                "age_days": _age(str(row["observed_at"]), generated_at),
            }
        )
        if domains:
            edges.append(
                _edge(
                    node_id("ad_domain", str(domains[0]["domain_key"])),
                    trust_ref,
                    "trust",
                    str(row["source"]),
                    str(row["observed_at"]),
                )
            )
        trusts.append(
            {
                "name": trust_name,
                "direction": _values(attributes, "trustDirection"),
                "type": _values(attributes, "trustType"),
                "source": str(row["source"]),
                "observed_at": str(row["observed_at"]),
                "age_days": _age(str(row["observed_at"]), generated_at),
            }
        )
    return {
        "domains": domain_items,
        "trusts": trusts,
        "diagram": _diagram(nodes, edges),
        "coverage_notes": _coverage_notes(repository, deployment_id, "ad"),
    }


def build_platform_report_model(
    repository: Repository, deployment_id: int, *, generated_at: datetime
) -> dict[str, object]:
    """Build source-labelled platform sections and self-contained diagram sources."""
    generated = generated_at.astimezone(UTC)
    return {
        "unifi": _unifi_model(repository, deployment_id, generated),
        "active_directory": _ad_model(repository, deployment_id, generated),
    }
