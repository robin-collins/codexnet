"""Synthetic passive ARP and decoded kernel-neighbour tests."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import struct
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from field_discovery.correlation import (
    DeviceObservation,
    IdentifierKind,
    IdentityEvidence,
    correlate,
)
from field_discovery.neighbor import (
    MAX_ARP_PAYLOAD_BYTES,
    ArpParser,
    NeighborEvidence,
    NeighborTracker,
    parse_arp_evidence,
    parse_kernel_neighbor,
)
from field_discovery.passive import (
    PassiveEventPipeline,
    PassiveFrame,
    PassiveObservation,
    PassiveParseError,
)

NOW = datetime(2026, 7, 15, 2, 3, 4, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures/neighbor/kernel-neighbors.json"


def arp_packet(
    *,
    operation: int = 1,
    sender_mac: str = "001122334455",
    sender_ip: str = "192.168.50.10",
    target_mac: str = "000000000000",
    target_ip: str = "192.168.50.1",
    padding: bytes = b"",
) -> bytes:
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
        + bytes.fromhex(sender_mac)
        + ipaddress.IPv4Address(sender_ip).packed
        + bytes.fromhex(target_mac)
        + ipaddress.IPv4Address(target_ip).packed
        + padding
    )


def arp_frame(**kwargs: Any) -> PassiveFrame:
    return PassiveFrame("arp", arp_packet(**kwargs), NOW, "eth-test")


def evidence(
    address: str,
    mac: str | None,
    *,
    observed_at: datetime = NOW,
    state: str = "reachable",
    interface: str = "eth0",
    source: str = "synthetic",
) -> NeighborEvidence:
    return NeighborEvidence(address, mac, interface, state, source, observed_at)


def test_arp_request_and_reply_normalize_sender_only_without_payload() -> None:
    request = parse_arp_evidence(arp_frame())
    reply = parse_arp_evidence(
        arp_frame(
            operation=2,
            sender_mac="AABBCCDDEEFF",
            sender_ip="192.168.50.1",
            target_mac="001122334455",
            target_ip="192.168.50.10",
            padding=b"synthetic-padding",
        )
    )
    assert request == evidence(
        "192.168.50.10",
        "00:11:22:33:44:55",
        state="reachable",
        interface="eth-test",
        source="passive.arp",
    ).__class__(
        "192.168.50.10",
        "00:11:22:33:44:55",
        "eth-test",
        "reachable",
        "passive.arp",
        NOW,
        "request",
    )
    assert reply.operation == "reply"
    assert reply.address == "192.168.50.1"
    assert reply.mac_address == "aa:bb:cc:dd:ee:ff"
    assert not hasattr(reply, "payload")


@pytest.mark.parametrize(
    ("payload", "protocol", "message"),
    [
        (b"short", "arp", "shorter"),
        (arp_packet() + bytes(MAX_ARP_PAYLOAD_BYTES), "arp", "size limit"),
        (struct.pack("!HHBBH", 2, 0x0800, 6, 4, 1) + bytes(20), "arp", "type"),
        (struct.pack("!HHBBH", 1, 0x0806, 6, 4, 1) + bytes(20), "arp", "type"),
        (struct.pack("!HHBBH", 1, 0x0800, 5, 4, 1) + bytes(20), "arp", "lengths"),
        (struct.pack("!HHBBH", 1, 0x0800, 6, 16, 1) + bytes(44), "arp", "lengths"),
        (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 3) + bytes(20), "arp", "operation"),
        (arp_packet()[:20], "arp", "truncated"),
        (arp_packet(sender_ip="0.0.0.0"), "arp", "unspecified"),
        (arp_packet(), "other", "different protocol"),
    ],
)
def test_malformed_arp_is_rejected_per_frame(payload: bytes, protocol: str, message: str) -> None:
    with pytest.raises(PassiveParseError, match=message):
        parse_arp_evidence(PassiveFrame(protocol, payload, NOW, "eth0"))


def test_kernel_fixture_normalizes_complete_incomplete_and_failed_records() -> None:
    records = json.loads(FIXTURE.read_text())
    output = [
        item
        for record in records
        if (item := parse_kernel_neighbor(record, observed_at=NOW, selected_interface="eth0"))
        is not None
    ]
    assert [(item.address, item.mac_address, item.state) for item in output] == [
        ("192.168.50.10", "00:11:22:33:44:55", "reachable"),
        ("192.168.50.11", None, "incomplete"),
        ("192.168.50.13", None, "failed"),
    ]
    assert all(item.source == "kernel.neighbor" for item in output)


@pytest.mark.parametrize(
    ("record", "message"),
    [
        ({}, "dev and dst"),
        ({"dev": 2, "dst": "10.0.0.1"}, "dev and dst"),
        ({"dev": "eth0", "dst": "bad"}, "IPv4"),
        ({"dev": "eth0", "dst": "10.0.0.1", "state": []}, "state"),
        ({"dev": "eth0", "dst": "10.0.0.1", "state": [2]}, "state"),
        ({"dev": "eth0", "dst": "10.0.0.1", "state": 2}, "state"),
        ({"dev": "eth0", "dst": "10.0.0.1", "state": "UNKNOWN"}, "unsupported"),
        ({"dev": "eth0", "dst": "10.0.0.1", "lladdr": 2}, "lladdr"),
        ({"dev": "eth0", "dst": "10.0.0.1", "lladdr": "bad"}, "MAC"),
    ],
)
def test_malformed_kernel_records_are_isolated(record: dict[str, Any], message: str) -> None:
    with pytest.raises(PassiveParseError, match=message):
        parse_kernel_neighbor(record, observed_at=NOW)


def test_neighbor_model_validates_source_interface_state_mac_and_time() -> None:
    assert evidence("10.0.0.1", "00-11-22-33-44-55").mac_address == "00:11:22:33:44:55"
    bad_values = [
        ("bad", None, "eth0", "reachable", "source", NOW),
        ("10.0.0.1", "00112233445z", "eth0", "reachable", "source", NOW),
        ("10.0.0.1", None, "", "reachable", "source", NOW),
        ("10.0.0.1", None, "eth0", "reachable", "", NOW),
        ("10.0.0.1", None, "eth0", "unknown", "source", NOW),
        ("10.0.0.1", None, "eth0", "reachable", "source", datetime(2026, 1, 1)),
    ]
    for arguments in bad_values:
        with pytest.raises((PassiveParseError, ValueError)):
            NeighborEvidence(*arguments)


def test_duplicate_updates_last_seen_only_after_window_and_ages() -> None:
    tracker = NeighborTracker(max_age=timedelta(seconds=60), dedupe_window=timedelta(seconds=10))
    first = tracker.observe(evidence("10.0.0.10", "001122334455"))
    duplicate = tracker.observe(
        evidence("10.0.0.10", "001122334455", observed_at=NOW + timedelta(seconds=5))
    )
    later = tracker.observe(
        evidence(
            "10.0.0.10", "001122334455", observed_at=NOW + timedelta(seconds=15), state="stale"
        )
    )
    assert first[0].fields["first_seen"] == NOW.isoformat()
    assert duplicate == ()
    assert later[0].fields["first_seen"] == NOW.isoformat()
    assert later[0].fields["last_seen"] == (NOW + timedelta(seconds=15)).isoformat()
    assert later[0].fields["state"] == "stale"
    assert tracker.expire(NOW + timedelta(seconds=70)) == ()
    expired = tracker.expire(NOW + timedelta(seconds=76))
    assert expired[0].kind == "neighbor_expired"
    assert expired[0].fields["last_seen"] == (NOW + timedelta(seconds=15)).isoformat()
    assert tracker.tracked_count == 0


def test_ip_reuse_and_mac_movement_are_conflicts_not_merges() -> None:
    reuse = NeighborTracker()
    reuse.observe(evidence("10.0.0.20", "001122334401"))
    reused = reuse.observe(evidence("10.0.0.20", "001122334402", observed_at=NOW + timedelta(1)))
    assert [item.kind for item in reused] == ["neighbor_observation", "neighbor_ip_reuse"]
    assert reused[1].fields["previous_macs"] == ["00:11:22:33:44:01"]

    movement = NeighborTracker()
    movement.observe(evidence("10.0.0.20", "001122334401"))
    moved = movement.observe(evidence("10.0.0.21", "001122334401", observed_at=NOW + timedelta(1)))
    assert [item.kind for item in moved] == ["neighbor_observation", "neighbor_mac_movement"]
    assert moved[1].fields["previous_addresses"] == ["10.0.0.20"]

    correlated = correlate(
        (
            DeviceObservation(
                "old",
                "arp",
                NOW,
                (
                    IdentityEvidence(IdentifierKind.MAC, "001122334401", "arp", NOW),
                    IdentityEvidence(IdentifierKind.IPV4, "10.0.0.20", "arp", NOW),
                ),
            ),
            DeviceObservation(
                "new",
                "arp",
                NOW + timedelta(1),
                (
                    IdentityEvidence(IdentifierKind.MAC, "001122334402", "arp", NOW + timedelta(1)),
                    IdentityEvidence(IdentifierKind.IPV4, "10.0.0.20", "arp", NOW + timedelta(1)),
                ),
            ),
        )
    )
    assert len(correlated.devices) == 2
    assert correlated.conflicts[0].conflict_kind == "reused_ipv4"


def test_incomplete_neighbor_and_capacity_eviction_are_bounded() -> None:
    tracker = NeighborTracker(max_entries=1, dedupe_window=timedelta(0))
    incomplete = tracker.observe(evidence("10.0.0.30", None, state="incomplete"))
    assert incomplete[0].fields["mac_address"] is None
    assert incomplete[0].fields["state"] == "incomplete"
    tracker.observe(evidence("10.0.0.31", "001122334431"))
    assert tracker.tracked_count == 1
    assert tracker.expire(NOW + timedelta(hours=1))[0].fields["address"] == "10.0.0.31"

    for kwargs in (
        {"max_age": timedelta(0)},
        {"dedupe_window": timedelta(seconds=-1)},
        {"max_entries": 0},
    ):
        with pytest.raises(ValueError, match="bounds"):
            NeighborTracker(**kwargs)


def test_pipeline_integration_deduplicates_without_active_network_behavior() -> None:
    async def scenario() -> None:
        output: list[PassiveObservation] = []

        async def sink(item: PassiveObservation) -> None:
            output.append(item)

        parser = ArpParser(NeighborTracker(dedupe_window=timedelta(seconds=30)))
        pipeline = PassiveEventPipeline(
            parsers={"arp": (parser,)}, sink=sink, queue_size=2, max_frame_bytes=64
        )
        raw = arp_packet()
        await pipeline.start()
        assert await pipeline.submit("arp", raw, observed_at=NOW, interface="eth-test")
        assert await pipeline.submit(
            "arp", raw, observed_at=NOW + timedelta(seconds=1), interface="eth-test"
        )
        metrics = await pipeline.stop()
        assert len(output) == 1
        assert not hasattr(output[0], "payload")
        assert raw not in repr(output).encode()
        assert metrics.emitted_observations == 1
        assert metrics.parser_failures == 0

        default_parser = ArpParser()
        assert default_parser.tracker.tracked_count == 0

    asyncio.run(scenario())


def test_timezone_conversion_and_default_kernel_state() -> None:
    local = datetime(2026, 7, 15, 12, 33, 4, tzinfo=timezone(timedelta(hours=10, minutes=30)))
    item = parse_kernel_neighbor({"dst": "10.0.0.1", "dev": "eth0"}, observed_at=local)
    assert item is not None
    assert item.state == "none"
    assert item.observed_at == NOW
    with pytest.raises(ValueError, match="timezone"):
        NeighborTracker().expire(datetime(2026, 1, 1))
