"""Normalize bounded UniFi API snapshots into canonical historical inventory."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CollectorIssue,
    CollectorResult,
    CredentialReference,
)
from field_discovery.correlation import (
    DeviceObservation,
    FactEvidence,
    IdentifierKind,
    IdentityEvidence,
    InterfaceEvidence,
    NormalizationError,
    correlate,
)
from field_discovery.repository import Repository
from field_discovery.unifi import (
    ClientFactory,
    UniFiClient,
    UniFiCredentials,
    UniFiEndpoint,
    UniFiError,
)

UNIFI_RESOURCES = (
    "devices",
    "clients",
    "networks",
    "wlans",
    "profiles",
    "alarms",
    "events",
)
_DEVICE_ROLES = {"ugw": "gateway", "usw": "switch", "uap": "access_point"}
_ENTITY_KINDS = frozenset(
    {
        "gateway",
        "switch",
        "access_point",
        "client",
        "network",
        "wlan",
        "port_profile",
        "port",
        "alarm",
        "event",
    }
)
_ATTRIBUTE_FIELDS = (
    "model",
    "version",
    "adopted",
    "disabled",
    "vlan",
    "vlan_enabled",
    "purpose",
    "security",
    "channel",
    "radio",
    "poe_mode",
    "speed",
    "duplex",
    "message",
    "category",
    "severity",
)


@dataclass(frozen=True)
class UniFiCoverageIssue:
    site_key: str
    resource: str
    category: str
    detail: str


@dataclass(frozen=True)
class UniFiSnapshot:
    controller_key: str
    sites: tuple[dict[str, object], ...]
    resources: dict[tuple[str, str], tuple[object, ...]]
    coverage_issues: tuple[UniFiCoverageIssue, ...] = ()


@dataclass(frozen=True)
class UniFiEntity:
    site_key: str
    kind: str
    controller_id: str
    display_name: str | None
    state: str | None
    active: bool
    last_seen_at: datetime | None
    attributes: dict[str, object]
    observation_id: str | None = None

    @property
    def scoped_id(self) -> str:
        return f"{self.site_key}:{self.kind}:{self.controller_id}"


@dataclass(frozen=True)
class UniFiRelationship:
    site_key: str
    local_scoped_id: str
    remote_scoped_id: str
    kind: str


@dataclass(frozen=True)
class NormalizedUniFiInventory:
    controller_key: str
    observed_at: datetime
    sites: tuple[tuple[str, str | None], ...]
    entities: tuple[UniFiEntity, ...]
    relationships: tuple[UniFiRelationship, ...]
    devices: tuple[DeviceObservation, ...]
    coverage_issues: tuple[UniFiCoverageIssue, ...]


def _text(value: object, *, maximum: int = 512) -> str | None:
    if not isinstance(value, str):
        return None
    result = value.strip()
    return result[:maximum] if result else None


def _identifier(record: dict[str, object]) -> str:
    for field in ("_id", "id", "mac"):
        value = _text(record.get(field), maximum=256)
        if value:
            return value.casefold()
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode()
    return f"anonymous-{hashlib.sha256(encoded).hexdigest()[:16]}"


def _last_seen(value: object) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return None
    try:
        return datetime.fromtimestamp(float(value), UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _safe_attributes(record: dict[str, object]) -> dict[str, object]:
    return {
        field: value
        for field in _ATTRIBUTE_FIELDS
        if (value := record.get(field)) is not None and isinstance(value, str | int | float | bool)
    }


def _identity(
    kind: IdentifierKind,
    value: object,
    source: str,
    observed_at: datetime,
    *,
    namespace: str | None = None,
    confidence: float = 1.0,
) -> IdentityEvidence | None:
    text = _text(value)
    if text is None:
        return None
    try:
        return IdentityEvidence(kind, text, source, observed_at, confidence, namespace)
    except NormalizationError:
        return None


def _device_observation(
    record: dict[str, object],
    *,
    controller_key: str,
    site_key: str,
    kind: str,
    observed_at: datetime,
    active: bool,
    stale: bool,
) -> DeviceObservation:
    source = "unifi"
    controller_id = _identifier(record)
    namespace = f"unifi:{controller_key}:{site_key}"
    identifiers = [
        _identity(
            IdentifierKind.SOURCE_ID, controller_id, source, observed_at, namespace=namespace
        ),
        _identity(
            IdentifierKind.MAC,
            record.get("mac"),
            source,
            observed_at,
            confidence=0.7 if stale else 1.0,
        ),
        _identity(IdentifierKind.SERIAL, record.get("serial"), source, observed_at),
        _identity(
            IdentifierKind.HOSTNAME, record.get("hostname"), source, observed_at, confidence=0.7
        ),
        _identity(IdentifierKind.IPV4, record.get("ip"), source, observed_at, confidence=0.6),
    ]
    interface_mac = _text(record.get("mac"))
    interfaces: tuple[InterfaceEvidence, ...] = ()
    if interface_mac:
        with suppress(NormalizationError):
            interfaces = (
                InterfaceEvidence(
                    "primary", source, observed_at, name="primary", mac_address=interface_mac
                ),
            )
    facts = [
        FactEvidence("role", kind, source, observed_at),
        FactEvidence("site", site_key, source, observed_at),
        FactEvidence(
            "connection_state", "active" if active else "disconnected", source, observed_at
        ),
    ]
    if stale:
        facts.append(FactEvidence("stale", "true", source, observed_at))
    for field in ("name", "model", "version"):
        if value := _text(record.get(field)):
            facts.append(FactEvidence(field, value, source, observed_at))
    return DeviceObservation(
        f"unifi:{controller_key}:{site_key}:{kind}:{controller_id}",
        source,
        observed_at,
        tuple(item for item in identifiers if item is not None),
        interfaces,
        tuple(facts),
    )


def normalize_snapshot(
    snapshot: UniFiSnapshot,
    *,
    observed_at: datetime,
    stale_after: timedelta = timedelta(days=7),
) -> NormalizedUniFiInventory:
    """Normalize only allowlisted fields; controller/site scope prevents ID collisions."""
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("UniFi observation time must include a timezone")
    sites: list[tuple[str, str | None]] = []
    entities: list[UniFiEntity] = []
    relationships: list[UniFiRelationship] = []
    devices: list[DeviceObservation] = []
    seen_entities: set[str] = set()
    for site_record in snapshot.sites:
        site_key = _identifier(site_record)
        sites.append((site_key, _text(site_record.get("desc")) or _text(site_record.get("name"))))
        device_ids: dict[str, str] = {}
        for resource in UNIFI_RESOURCES:
            for raw in snapshot.resources.get((site_key, resource), ()):
                if not isinstance(raw, dict):
                    continue
                record = {str(key): value for key, value in raw.items()}
                controller_id = _identifier(record)
                if resource == "devices":
                    kind = _DEVICE_ROLES.get(str(record.get("type", "")).casefold())
                    if kind is None:
                        continue
                else:
                    kind = {
                        "clients": "client",
                        "networks": "network",
                        "wlans": "wlan",
                        "profiles": "port_profile",
                        "alarms": "alarm",
                        "events": "event",
                    }[resource]
                scoped = f"{site_key}:{kind}:{controller_id}"
                if scoped in seen_entities:
                    continue
                seen_entities.add(scoped)
                last_seen = _last_seen(record.get("last_seen"))
                stale = last_seen is not None and observed_at - last_seen > stale_after
                connected = record.get("connected", record.get("state", 1)) not in {
                    False,
                    "0",
                    "disconnected",
                }
                active = bool(connected and not stale and not record.get("disabled", False))
                observation_id: str | None = None
                if kind in {*_DEVICE_ROLES.values(), "client"}:
                    observation = _device_observation(
                        record,
                        controller_key=snapshot.controller_key,
                        site_key=site_key,
                        kind=kind,
                        observed_at=observed_at,
                        active=active,
                        stale=stale,
                    )
                    devices.append(observation)
                    observation_id = observation.observation_id
                    device_ids[controller_id] = scoped
                entities.append(
                    UniFiEntity(
                        site_key,
                        kind,
                        controller_id,
                        _text(record.get("name")) or _text(record.get("hostname")),
                        _text(record.get("state")) or ("active" if active else "disconnected"),
                        active,
                        last_seen,
                        _safe_attributes(record),
                        observation_id,
                    )
                )
                if resource == "devices":
                    for port in (
                        record.get("port_table", ())
                        if isinstance(record.get("port_table"), list)
                        else ()
                    ):
                        if not isinstance(port, dict):
                            continue
                        port_id = str(port.get("port_idx", port.get("name", "unknown")))
                        port_scoped = f"{site_key}:port:{controller_id}:{port_id}"
                        if port_scoped in seen_entities:
                            continue
                        seen_entities.add(port_scoped)
                        entities.append(
                            UniFiEntity(
                                site_key,
                                "port",
                                f"{controller_id}:{port_id}",
                                _text(port.get("name")) or f"Port {port_id}",
                                "up" if port.get("up", False) else "down",
                                bool(port.get("up", False)),
                                None,
                                _safe_attributes({str(key): value for key, value in port.items()}),
                            )
                        )
                remote = _text(record.get("uplink_device")) or _text(record.get("uplink_remote_id"))
                if remote and kind in {*_DEVICE_ROLES.values(), "client"}:
                    remote_scoped = device_ids.get(remote, f"{site_key}:device:{remote.casefold()}")
                    relationships.append(
                        UniFiRelationship(site_key, scoped, remote_scoped, "uplink")
                    )
    return NormalizedUniFiInventory(
        snapshot.controller_key,
        observed_at,
        tuple(sorted(set(sites))),
        tuple(sorted(entities, key=lambda item: item.scoped_id)),
        tuple(sorted(relationships, key=lambda item: (item.site_key, item.local_scoped_id))),
        tuple(sorted(devices, key=lambda item: item.observation_id)),
        snapshot.coverage_issues,
    )


def persist_inventory(
    repository: Repository, deployment_id: int, inventory: NormalizedUniFiInventory
) -> int:
    """Persist one normalized snapshot transactionally and return its entity count."""
    result = correlate(inventory.devices)
    observed = inventory.observed_at.isoformat()
    canonical_by_observation: dict[str, int] = {}
    connection = repository.connection
    with repository.transaction():
        for device in result.devices:
            connection.execute(
                "INSERT INTO devices(deployment_id, canonical_key, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(deployment_id, canonical_key) DO NOTHING",
                (deployment_id, device.canonical_key, observed),
            )
            device_id = int(
                connection.execute(
                    "SELECT id FROM devices WHERE deployment_id = ? AND canonical_key = ?",
                    (deployment_id, device.canonical_key),
                ).fetchone()[0]
            )
            for observation_id in device.observation_ids:
                canonical_by_observation[observation_id] = device_id
            for identifier in device.identifiers:
                connection.execute(
                    "INSERT OR IGNORE INTO device_aliases"
                    "(device_id, alias_kind, alias_value, confidence, source, observed_at) "
                    "VALUES (?, ?, ?, ?, 'unifi', ?)",
                    (
                        device_id,
                        identifier.kind.value,
                        identifier.value,
                        identifier.confidence,
                        observed,
                    ),
                )
            for fact in device.facts:
                connection.execute(
                    "INSERT OR IGNORE INTO observations"
                    "(deployment_id, subject_type, subject_id, fact_type, fact_value_json, "
                    "confidence, inferred, source, observed_at) "
                    "VALUES (?, 'device', ?, ?, ?, ?, 0, 'unifi', ?)",
                    (
                        deployment_id,
                        device_id,
                        fact.field,
                        json.dumps(fact.value),
                        fact.confidence,
                        observed,
                    ),
                )
        site_ids: dict[str, int] = {}
        for site_key, display_name in inventory.sites:
            connection.execute(
                "INSERT OR IGNORE INTO unifi_sites"
                "(deployment_id, controller_key, site_key, display_name, source, observed_at) "
                "VALUES (?, ?, ?, ?, 'unifi', ?)",
                (deployment_id, inventory.controller_key, site_key, display_name, observed),
            )
            site_ids[site_key] = int(
                connection.execute(
                    "SELECT id FROM unifi_sites WHERE deployment_id = ? AND controller_key = ? "
                    "AND site_key = ? AND source = 'unifi' AND observed_at = ?",
                    (deployment_id, inventory.controller_key, site_key, observed),
                ).fetchone()[0]
            )
        entity_ids: dict[str, int] = {}
        for entity in inventory.entities:
            if entity.kind not in _ENTITY_KINDS:
                continue
            canonical_id = (
                canonical_by_observation.get(entity.observation_id)
                if entity.observation_id
                else None
            )
            connection.execute(
                "INSERT OR IGNORE INTO unifi_entities"
                "(unifi_site_id, canonical_device_id, entity_kind, controller_entity_id, "
                "display_name, state, active, last_seen_at, attributes_json, source, observed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'unifi', ?)",
                (
                    site_ids[entity.site_key],
                    canonical_id,
                    entity.kind,
                    entity.controller_id,
                    entity.display_name,
                    entity.state,
                    int(entity.active),
                    entity.last_seen_at.isoformat() if entity.last_seen_at else None,
                    json.dumps(
                        repository.redactor.value(entity.attributes),
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    observed,
                ),
            )
            entity_ids[entity.scoped_id] = int(
                connection.execute(
                    "SELECT id FROM unifi_entities WHERE unifi_site_id = ? AND entity_kind = ? "
                    "AND controller_entity_id = ? AND source = 'unifi' AND observed_at = ?",
                    (site_ids[entity.site_key], entity.kind, entity.controller_id, observed),
                ).fetchone()[0]
            )
        for relation in inventory.relationships:
            local_id = entity_ids.get(relation.local_scoped_id)
            if local_id is None:
                continue
            remote_id = entity_ids.get(relation.remote_scoped_id)
            connection.execute(
                "INSERT OR IGNORE INTO unifi_relationships"
                "(unifi_site_id, local_entity_id, remote_entity_id, remote_identifier, "
                "relationship_kind, attributes_json, source, observed_at) "
                "VALUES (?, ?, ?, ?, ?, '{}', 'unifi', ?)",
                (
                    site_ids[relation.site_key],
                    local_id,
                    remote_id,
                    None if remote_id else relation.remote_scoped_id,
                    relation.kind,
                    observed,
                ),
            )
        for issue in inventory.coverage_issues:
            connection.execute(
                "INSERT OR IGNORE INTO observations"
                "(deployment_id, subject_type, subject_id, fact_type, fact_value_json, "
                "confidence, inferred, source, observed_at) "
                "VALUES (?, 'unifi_coverage', NULL, ?, ?, 1.0, 0, 'unifi', ?)",
                (
                    deployment_id,
                    issue.category,
                    json.dumps(
                        repository.redactor.value(
                            {
                                "site": issue.site_key,
                                "resource": issue.resource,
                                "detail": issue.detail,
                            }
                        ),
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    observed,
                ),
            )
    return len(inventory.entities)


InventorySink = Callable[[NormalizedUniFiInventory], int]
InventoryCredentialLoader = Callable[[CredentialReference], UniFiCredentials]


@dataclass
class UniFiInventoryCollector:
    """Read every supported resource independently and persist normalized facts."""

    endpoint: UniFiEndpoint
    credential_loader: InventoryCredentialLoader
    inventory_sink: InventorySink
    observed_at: datetime
    client_factory: ClientFactory = UniFiClient
    name: str = "unifi"

    async def collect(self, context: CollectorContext) -> CollectorResult:
        if context.credential_ref is None:
            raise UniFiError("UniFi collection requires a credential reference")
        credentials = self.credential_loader(context.credential_ref)
        client = self.client_factory(self.endpoint)
        try:
            await client.login(credentials)
            site_values = await client.get_pages("sites")
            sites = tuple(
                {str(key): value for key, value in site.items()}
                for site in site_values
                if isinstance(site, dict)
            )
            resources: dict[tuple[str, str], tuple[object, ...]] = {}
            coverage: list[UniFiCoverageIssue] = []
            for site in sites:
                site_key = _identifier(site)
                for resource in UNIFI_RESOURCES:
                    if context.cancellation.is_set():
                        raise asyncio.CancelledError
                    try:
                        resources[(site_key, resource)] = await client.get_pages(
                            resource, site=site_key
                        )
                    except CollectorAuthenticationError:
                        coverage.append(
                            UniFiCoverageIssue(
                                site_key,
                                resource,
                                "permission_denied",
                                "controller account cannot read this resource",
                            )
                        )
                    except UniFiError:
                        coverage.append(
                            UniFiCoverageIssue(
                                site_key,
                                resource,
                                "endpoint_omitted",
                                "controller omitted or does not support this resource",
                            )
                        )
            inventory = normalize_snapshot(
                UniFiSnapshot(
                    controller_key=_controller_key(self.endpoint),
                    sites=sites,
                    resources=resources,
                    coverage_issues=tuple(coverage),
                ),
                observed_at=self.observed_at,
            )
            item_count = self.inventory_sink(inventory)
            issues = tuple(
                CollectorIssue(issue.category, issue.detail, False) for issue in coverage
            )
            return CollectorResult(item_count=item_count, issues=issues)
        finally:
            credentials = UniFiCredentials("", "")


def _controller_key(endpoint: UniFiEndpoint) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(endpoint.url)
    port = parsed.port or 443
    return f"{parsed.hostname}:{port}"
