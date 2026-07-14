"""Synthetic UniFi normalization, correlation, coverage, and persistence tests."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CredentialReference,
)
from field_discovery.database import available_migrations
from field_discovery.repository import Repository
from field_discovery.unifi import UniFiCredentials, UniFiEndpoint, UniFiError
from field_discovery.unifi_inventory import (
    UNIFI_RESOURCES,
    NormalizedUniFiInventory,
    UniFiCoverageIssue,
    UniFiEntity,
    UniFiInventoryCollector,
    UniFiRelationship,
    UniFiSnapshot,
    normalize_snapshot,
    persist_inventory,
)

FIXTURE = Path(__file__).parent / "fixtures/unifi/inventory.json"
NOW = datetime(2026, 7, 15, 3, 30, tzinfo=UTC)


def snapshot() -> UniFiSnapshot:
    raw = json.loads(FIXTURE.read_text())
    resources = {tuple(key.split("/", 1)): tuple(value) for key, value in raw["resources"].items()}
    issues = tuple(UniFiCoverageIssue(**value) for value in raw["coverage_issues"])
    return UniFiSnapshot(raw["controller_key"], tuple(raw["sites"]), resources, issues)


def repository(tmp_path: Path) -> tuple[Repository, int]:
    root = tmp_path / "data"
    root.mkdir()
    repo = Repository.open(root / "discovery.db", data_root=root)
    deployment = repo.upsert_deployment("fixture", "Fixture", NOW.isoformat())
    return repo, deployment


def test_migration_is_numbered_and_contains_historical_unifi_domains() -> None:
    migration = available_migrations()[-1]
    assert (migration.version, migration.name) == (4, "unifi_inventory")
    assert {"unifi_sites", "unifi_entities", "unifi_relationships"} <= {
        row.split("(", 1)[0].split()[-1]
        for row in migration.sql.splitlines()
        if row.startswith("CREATE TABLE")
    }


def test_normalization_maps_every_domain_and_scopes_cross_site_ids() -> None:
    inventory = normalize_snapshot(snapshot(), observed_at=NOW)
    kinds = {entity.kind for entity in inventory.entities}
    assert {
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
    } <= kinds
    assert len([item for item in inventory.entities if item.controller_id == "ap-1"]) == 1
    reused = [
        item
        for item in inventory.entities
        if item.kind == "client" and item.controller_id == "client-reused"
    ]
    assert len(reused) == 2
    assert reused[0].scoped_id != reused[1].scoped_id
    stale = next(item for item in reused if item.site_key == "site-a")
    active = next(item for item in reused if item.site_key == "site-b")
    assert (stale.active, stale.state, active.active) == (False, "disconnected", True)
    assert len(inventory.devices) == 5
    assert inventory.relationships[0].kind == "uplink"
    serialized = json.dumps([entity.attributes for entity in inventory.entities])
    assert "password" not in serialized.casefold()


def test_normalizer_handles_invalid_optional_data_and_requires_aware_time() -> None:
    malformed = UniFiSnapshot(
        "fixture:443",
        ({"_id": "site"},),
        {
            ("site", "devices"): (
                {
                    "_id": "bad",
                    "type": "usw",
                    "mac": "invalid",
                    "ip": "999.1.1.1",
                    "last_seen": -1,
                    "port_table": ["bad", {"port_idx": 1}, {"port_idx": 1}],
                },
                {"type": "ugw", "name": "anonymous", "last_seen": 10**100},
            ),
            ("site", "clients"): ("malformed",),
        },
    )
    result = normalize_snapshot(malformed, observed_at=NOW)
    assert len(result.devices) == 2
    assert all(item.last_seen_at is None for item in result.entities)
    with pytest.raises(ValueError, match="timezone"):
        normalize_snapshot(malformed, observed_at=datetime(2026, 1, 1))


def test_persistence_defensively_skips_unknown_entities_and_orphan_relationships(
    tmp_path: Path,
) -> None:
    repo, deployment = repository(tmp_path)
    inventory = NormalizedUniFiInventory(
        "fixture:443",
        NOW,
        (("site", "Site"),),
        (UniFiEntity("site", "future", "id", None, None, True, None, {}),),
        (UniFiRelationship("site", "missing", "remote", "uplink"),),
        (),
        (),
    )
    assert persist_inventory(repo, deployment, inventory) == 1
    assert repo.connection.execute("SELECT COUNT(*) FROM unifi_entities").fetchone()[0] == 0
    assert repo.connection.execute("SELECT COUNT(*) FROM unifi_relationships").fetchone()[0] == 0
    repo.close()


def test_persistence_correlates_ids_without_duplicates_and_retains_coverage(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    inventory = normalize_snapshot(snapshot(), observed_at=NOW)
    assert persist_inventory(repo, deployment, inventory) == len(inventory.entities)
    assert persist_inventory(repo, deployment, inventory) == len(inventory.entities)
    connection = repo.connection
    assert connection.execute("SELECT COUNT(*) FROM unifi_sites").fetchone()[0] == 2
    assert connection.execute("SELECT COUNT(*) FROM unifi_entities").fetchone()[0] == len(
        inventory.entities
    )
    assert connection.execute("SELECT COUNT(*) FROM unifi_relationships").fetchone()[0] == len(
        inventory.relationships
    )
    assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 5
    linked = connection.execute(
        "SELECT COUNT(*) FROM unifi_entities WHERE canonical_device_id IS NOT NULL"
    ).fetchone()[0]
    assert linked == 5
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM observations WHERE subject_type = 'unifi_coverage'"
        ).fetchone()[0]
        == 2
    )
    assert repo.integrity_check().ok
    repo.close()


class FakeClient:
    def __init__(self, _endpoint: UniFiEndpoint) -> None:
        self.calls: list[tuple[str, str]] = []

    async def login(self, _credentials: UniFiCredentials) -> None:
        return None

    async def get_pages(self, resource: str, *, site: str = "default") -> tuple[object, ...]:
        self.calls.append((site, resource))
        if resource == "sites":
            return ({"_id": "site"},)
        if resource == "alarms":
            raise CollectorAuthenticationError("forbidden secret-token")
        if resource == "events":
            raise UniFiError("unsupported secret-token")
        if resource == "devices":
            return ({"_id": "switch", "type": "usw", "mac": "02:00:00:00:00:01"},)
        return ()


def test_inventory_collector_isolates_permission_and_omitted_endpoints() -> None:
    captured: list[NormalizedUniFiInventory] = []

    def sink(inventory: NormalizedUniFiInventory) -> int:
        captured.append(inventory)
        return len(inventory.entities)

    collector = UniFiInventoryCollector(
        UniFiEndpoint("https://controller.invalid"),
        lambda _reference: UniFiCredentials("fixture", "synthetic-password"),
        sink,
        NOW,
        FakeClient,
    )
    context = CollectorContext(
        "192.0.2.1", CredentialReference("fixture", "UNIFI_PROFILE"), asyncio.Event()
    )
    result = asyncio.run(collector.collect(context))
    assert result.item_count == 1
    assert {issue.category for issue in result.issues} == {
        "permission_denied",
        "endpoint_omitted",
    }
    assert len(captured[0].coverage_issues) == 2
    assert "secret-token" not in json.dumps([issue.detail for issue in result.issues])
    assert set(FakeClient(UniFiEndpoint("https://controller.invalid")).calls) == set()


def test_inventory_collector_requires_reference_and_honors_cancellation() -> None:
    collector = UniFiInventoryCollector(
        UniFiEndpoint("https://controller.invalid"),
        lambda _reference: UniFiCredentials("fixture", "synthetic-password"),
        lambda _inventory: 0,
        NOW,
        FakeClient,
    )
    with pytest.raises(UniFiError, match="credential reference"):
        asyncio.run(collector.collect(CollectorContext("192.0.2.1", None, asyncio.Event())))
    stopped = asyncio.Event()
    stopped.set()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            collector.collect(
                CollectorContext(
                    "192.0.2.1", CredentialReference("fixture", "UNIFI_PROFILE"), stopped
                )
            )
        )


def test_resource_contract_is_complete_and_staleness_is_configurable() -> None:
    assert UNIFI_RESOURCES == (
        "devices",
        "clients",
        "networks",
        "wlans",
        "profiles",
        "alarms",
        "events",
    )
    inventory = normalize_snapshot(snapshot(), observed_at=NOW, stale_after=timedelta(days=10000))
    client = next(
        entity
        for entity in inventory.entities
        if entity.site_key == "site-a" and entity.kind == "client"
    )
    assert client.last_seen_at is not None
