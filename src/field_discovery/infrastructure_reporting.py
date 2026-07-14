"""Deterministic, evidence-preserving infrastructure report normalization."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta

from field_discovery.repository import Repository

_SECTIONS = (
    "switch_ports",
    "vlans",
    "neighbors",
    "printers",
    "ups",
    "environment",
    "firmware",
)
_PORT_KEYS = ("port", "interface", "local_interface", "destination_port")


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("infrastructure observation timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _age(observed_at: str, generated_at: datetime) -> float:
    return round(max(0.0, (generated_at - _timestamp(observed_at)).total_seconds()) / 86_400, 3)


def _field(
    value: object,
    *,
    unit: object,
    source: str,
    observed_at: str,
    confidence: float,
    generated_at: datetime,
    stale_after: timedelta,
) -> dict[str, object]:
    age_days = _age(observed_at, generated_at)
    result: dict[str, object] = {
        "value": value,
        "source": source,
        "observed_at": observed_at,
        "age_days": age_days,
        "stale": age_days > stale_after.total_seconds() / 86_400,
        "confidence": confidence,
    }
    if unit is not None:
        result["unit"] = unit
    return result


def _target_devices(repository: Repository, deployment_id: int) -> dict[str, tuple[str, ...]]:
    rows = repository.connection.execute(
        "SELECT a.alias_value, d.canonical_key FROM device_aliases a "
        "JOIN devices d ON d.id = a.device_id WHERE d.deployment_id = ? "
        "AND a.alias_kind = 'ipv4' ORDER BY a.alias_value, d.canonical_key",
        (deployment_id,),
    ).fetchall()
    grouped: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        key = str(row["canonical_key"])
        if key not in grouped[str(row["alias_value"])]:
            grouped[str(row["alias_value"])].append(key)
    return {target: tuple(keys) for target, keys in grouped.items()}


def _rows(value: object) -> tuple[Mapping[str, object], ...]:
    if isinstance(value, dict):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, dict))
    return ()


def _first(row: Mapping[str, object], names: Iterable[str]) -> object | None:
    return next((row[name] for name in names if name in row and row[name] not in (None, "")), None)


def _ssh_records(
    fact_type: str, payload: Mapping[str, object]
) -> list[tuple[str, str, str, object, object]]:
    """Adapt only known read-only command families into report records."""
    command = fact_type.removeprefix("ssh.")
    records: list[tuple[str, str, str, object, object]] = []
    for row in _rows(payload.get("value")):
        port = _first(row, _PORT_KEYS)
        if "mac" in command and port is not None:
            mac = _first(row, ("mac", "mac_address", "destination_address"))
            if mac is not None:
                records.append(("switch_ports", str(port), "learned_mac", mac, None))
        elif any(token in command for token in ("lldp", "cdp", "neighbor")) and port is not None:
            neighbor = _first(row, ("neighbor", "system_name", "device_id", "neighbor_id"))
            if neighbor is not None:
                records.append(("neighbors", str(port), "neighbor", neighbor, None))
        elif any(token in command for token in ("power", "poe")) and port is not None:
            for name, value in sorted(row.items()):
                if name not in _PORT_KEYS:
                    records.append(("switch_ports", str(port), f"poe_{name}", value, None))
        elif "interface" in command and port is not None:
            for name, value in sorted(row.items()):
                if name not in _PORT_KEYS:
                    records.append(("switch_ports", str(port), name, value, None))
        elif "vlan" in command:
            vlan = _first(row, ("vlan", "vlan_id", "vid"))
            if vlan is not None:
                for name, value in sorted(row.items()):
                    if name not in {"vlan", "vlan_id", "vid"}:
                        records.append(("vlans", str(vlan), name, value, None))
        elif "environment" in command or "temperature" in command:
            key = str(_first(row, ("sensor", "name", "index")) or "system")
            for name, value in sorted(row.items()):
                records.append(("environment", key, name, value, row.get("unit")))
        elif any(token in command for token in ("version", "system", "inventory", "module")):
            for name in ("firmware", "version", "software_version", "model", "serial"):
                if name in row:
                    records.append(("firmware", "system", name, row[name], None))
    return records


def _snmp_record(fact_type: str, payload: Mapping[str, object]) -> tuple[str, str, str] | None:
    suffix = fact_type.removeprefix("snmp.")
    index = str(payload.get("index") or "system")
    if suffix.startswith("interface."):
        return "switch_ports", index, suffix.removeprefix("interface.")
    if suffix.startswith("poe.port."):
        return "switch_ports", f"poe:{index}", suffix.removeprefix("poe.port.")
    if suffix.startswith("vlan."):
        return "vlans", index, suffix.removeprefix("vlan.")
    if suffix.startswith("neighbor.") or suffix.startswith("lldp.remote."):
        return "neighbors", index, suffix.split(".", 1)[1]
    if suffix.startswith("printer."):
        return "printers", index, suffix.removeprefix("printer.")
    if suffix.startswith("ups."):
        return "ups", index, suffix.removeprefix("ups.")
    if suffix.startswith("environment."):
        return "environment", index, suffix.removeprefix("environment.")
    if suffix.startswith(("firmware.", "software.", "inventory.")):
        return "firmware", index, suffix
    return None


def build_infrastructure_model(
    repository: Repository,
    deployment_id: int,
    *,
    generated_at: datetime,
    stale_after: timedelta = timedelta(days=7),
) -> dict[str, object]:
    """Build mixed SNMP/SSH sections without hiding stale or conflicting evidence."""
    generated = generated_at.astimezone(UTC)
    aliases = _target_devices(repository, deployment_id)
    grouped: dict[tuple[str, str, str, str | None], dict[str, list[dict[str, object]]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    quality: list[dict[str, object]] = []
    bridge: dict[tuple[str, str, str], dict[str, object]] = defaultdict(dict)
    rows = repository.connection.execute(
        "SELECT fact_type, fact_value_json, confidence, source, observed_at FROM observations "
        "WHERE deployment_id = ? AND (fact_type LIKE 'snmp.%' OR fact_type LIKE 'ssh.%') "
        "ORDER BY observed_at, source, fact_type, id",
        (deployment_id,),
    ).fetchall()
    for row in rows:
        payload = json.loads(str(row["fact_value_json"]))
        if not isinstance(payload, dict) or not isinstance(payload.get("target"), str):
            quality.append(
                {"kind": "malformed_collector_observation", "fact_type": row["fact_type"]}
            )
            continue
        target = str(payload["target"])
        devices = aliases.get(target, ())
        device_key = devices[0] if len(devices) == 1 else None
        if len(devices) != 1:
            quality.append(
                {
                    "kind": "unmatched_target" if not devices else "ambiguous_target",
                    "target": target,
                    "candidate_devices": list(devices),
                }
            )
        fact_type = str(row["fact_type"])
        records: list[tuple[str, str, str, object, object]] = []
        if fact_type.startswith("ssh."):
            records = _ssh_records(fact_type, payload)
            if not records:
                quality.append(
                    {"kind": "unmapped_ssh_fact", "target": target, "fact_type": fact_type}
                )
        elif fact_type.startswith("snmp.bridge."):
            bridge[(target, str(row["source"]), str(row["observed_at"]))][
                f"{fact_type}:{payload.get('index', '')}"
            ] = payload.get("value")
        else:
            mapped = _snmp_record(fact_type, payload)
            if mapped is not None:
                section, key, field_name = mapped
                value = payload.get("value")
                if value is None and "value_status" in payload:
                    value = {
                        "status": payload["value_status"],
                        "raw_value": payload.get("raw_value"),
                    }
                records = [(section, key, field_name, value, payload.get("unit"))]
        for section, key, field_name, value, unit in records:
            grouped[(section, target, key, device_key)][field_name].append(
                _field(
                    value,
                    unit=unit,
                    source=str(row["source"]),
                    observed_at=str(row["observed_at"]),
                    confidence=float(row["confidence"]),
                    generated_at=generated,
                    stale_after=stale_after,
                )
            )

    for (target, source, observed_at), facts in sorted(bridge.items()):
        for name, value in sorted(facts.items()):
            if ".mac:" not in name:
                continue
            index = name.split(":", 1)[1]
            port = facts.get(f"snmp.bridge.port:{index}")
            if port is None:
                quality.append(
                    {"kind": "incomplete_bridge_entry", "target": target, "index": index}
                )
                continue
            devices = aliases.get(target, ())
            device_key = devices[0] if len(devices) == 1 else None
            grouped[("switch_ports", target, f"bridge:{port}", device_key)]["learned_mac"].append(
                _field(
                    value,
                    unit=None,
                    source=source,
                    observed_at=observed_at,
                    confidence=1.0,
                    generated_at=generated,
                    stale_after=stale_after,
                )
            )
            grouped[("switch_ports", target, f"bridge:{port}", device_key)][
                "mapping_status"
            ].append(
                _field(
                    "unresolved_bridge_port",
                    unit=None,
                    source=source,
                    observed_at=observed_at,
                    confidence=1.0,
                    generated_at=generated,
                    stale_after=stale_after,
                )
            )

    output: dict[str, list[dict[str, object]]] = {section: [] for section in _SECTIONS}
    conflicts: list[dict[str, object]] = []
    for (section, target, key, device_key), fields in sorted(grouped.items()):
        rendered: dict[str, object] = {}
        for name, evidence in sorted(fields.items()):
            ordered = sorted(
                evidence, key=lambda item: (str(item["observed_at"]), str(item["source"]))
            )
            values = {json.dumps(item["value"], sort_keys=True) for item in ordered}
            cell: dict[str, object] = {
                "value": ordered[-1]["value"],
                "evidence": ordered,
                "conflict": len(values) > 1,
            }
            if len(values) > 1:
                cell["alternatives"] = [item["value"] for item in ordered]
                conflicts.append(
                    {
                        "target": target,
                        "section": section,
                        "key": key,
                        "field": name,
                        "evidence": ordered,
                    }
                )
            rendered[name] = cell
        output[section].append(
            {"device_key": device_key, "target": target, "key": key, "fields": rendered}
        )
    return {
        **output,
        "conflicts": conflicts,
        "data_quality": sorted(quality, key=lambda item: json.dumps(item, sort_keys=True)),
        "stale_after_days": stale_after.total_seconds() / 86_400,
        "limitations": [
            "Bridge and PoE port identifiers remain unresolved unless an explicit interface "
            "mapping exists.",
            "Firmware versions are inventory observations only; vulnerability status was not "
            "assessed.",
        ],
    }
