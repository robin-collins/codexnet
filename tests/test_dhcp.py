"""Synthetic-only DHCP passive observation and pipeline tests."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from field_discovery.dhcp import (
    DHCP_MAGIC_COOKIE,
    MAX_DHCP_FRAME_BYTES,
    DhcpParser,
    parse_dhcp,
)
from field_discovery.passive import (
    PassiveEventPipeline,
    PassiveFrame,
    PassiveObservation,
    PassiveParseError,
)
from field_discovery.redaction import REDACTED, Redactor

NOW = datetime(2026, 7, 15, 1, 2, 3, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures/dhcp/events.json"


def _ip(value: str | None) -> bytes:
    return ipaddress.IPv4Address(value or "0.0.0.0").packed


def _option(code: int, value: bytes) -> bytes:
    return bytes((code, len(value))) + value


def packet(event: dict[str, Any], *, end: bool = True) -> bytes:
    """Build a bounded synthetic BOOTP/DHCP payload from fixture metadata."""
    payload = bytearray(240)
    payload[0] = event.get("op", 1)
    payload[1] = event.get("hardware_type", 1)
    payload[2] = event.get("hardware_length", 6)
    payload[4:8] = struct.pack("!I", event.get("xid", 1))
    payload[12:16] = _ip(event.get("client_address"))
    payload[16:20] = _ip(event.get("assigned"))
    payload[20:24] = _ip(event.get("next_server"))
    payload[24:28] = _ip(event.get("relay"))
    hardware = bytes.fromhex(event.get("client_mac", "001122334455"))
    payload[28 : 28 + len(hardware)] = hardware
    payload[236:240] = DHCP_MAGIC_COOKIE
    payload.extend(_option(53, bytes((event["message_type"],))))
    scalar_options = (
        (50, "requested", _ip),
        (54, "server", _ip),
        (51, "lease", lambda value: struct.pack("!I", value)),
        (58, "renewal", lambda value: struct.pack("!I", value)),
        (59, "rebinding", lambda value: struct.pack("!I", value)),
        (12, "hostname", lambda value: value.encode()),
        (60, "vendor", lambda value: value.encode()),
        (15, "domain", lambda value: value.encode()),
        (61, "client_id", bytes.fromhex),
    )
    for code, key, encode in scalar_options:
        if key in event:
            payload.extend(_option(code, encode(event[key])))
    for code, key in ((3, "routers"), (6, "dns")):
        if key in event:
            payload.extend(_option(code, b"".join(_ip(value) for value in event[key])))
    if end:
        payload.append(255)
    return bytes(payload)


def frame(event: dict[str, Any], *, payload: bytes | None = None) -> PassiveFrame:
    return PassiveFrame("dhcp", payload or packet(event), NOW, "eth-test")


@pytest.fixture(scope="module")
def events() -> dict[str, dict[str, Any]]:
    document = json.loads(FIXTURE.read_text())
    return {item["name"]: item for item in document}


def test_dora_sequence_normalizes_visible_metadata_and_never_retains_payload(
    events: dict[str, dict[str, Any]],
) -> None:
    results = [
        parse_dhcp(frame(events[name]))[0] for name in ("discover", "offer-a", "request", "ack")
    ]
    assert [item.fields["message_type"] for item in results] == [
        "discover",
        "offer",
        "request",
        "ack",
    ]
    discover, offer, request, ack = results
    assert discover.fields["client_mac"] == "00:11:22:33:44:55"
    assert discover.fields["requested_address"] == "192.168.50.100"
    assert discover.fields["hostname"] == "workstation-1"
    assert offer.fields == {
        "message_type": "offer",
        "transaction_id": "12345678",
        "client_mac": "00:11:22:33:44:55",
        "client_identifier": None,
        "client_address": None,
        "requested_address": None,
        "assigned_address": "192.168.50.100",
        "server_identifier": "192.168.50.1",
        "relay_address": None,
        "lease_seconds": 3600,
        "renewal_seconds": 1800,
        "rebinding_seconds": 3150,
        "hostname": None,
        "vendor_class": "SyntheticClient",
        "routers": ["192.168.50.1"],
        "dns_servers": ["192.168.50.1", "192.168.50.2"],
        "domain_name": "example.invalid",
        "is_renewal": False,
        "interface": "eth-test",
    }
    assert offer.expires_at == NOW + timedelta(seconds=3600)
    assert request.fields["server_identifier"] == "192.168.50.1"
    assert ack.fields["assigned_address"] == "192.168.50.100"
    assert all(not hasattr(item, "payload") for item in results)
    assert repr(results).find("63825363") == -1


def test_multiple_servers_remain_independent(events: dict[str, dict[str, Any]]) -> None:
    first = parse_dhcp(frame(events["offer-a"]))[0]
    second = parse_dhcp(frame(events["offer-b"]))[0]
    assert first.fields["transaction_id"] == second.fields["transaction_id"]
    assert first.fields["server_identifier"] == "192.168.50.1"
    assert second.fields["server_identifier"] == "192.168.50.2"
    assert second.fields["assigned_address"] == "192.168.50.101"


def test_renewal_uses_ciaddr_and_marks_request_and_ack(events: dict[str, dict[str, Any]]) -> None:
    request = parse_dhcp(frame(events["renew-request"]))[0]
    ack = parse_dhcp(frame(events["renew-ack"]))[0]
    assert request.fields["client_address"] == "192.168.50.100"
    assert request.fields["assigned_address"] == "192.168.50.100"
    assert request.fields["is_renewal"] is True
    assert ack.fields["assigned_address"] == "192.168.50.100"
    assert ack.fields["is_renewal"] is True
    assert ack.expires_at == NOW + timedelta(seconds=7200)


def test_server_falls_back_to_siaddr_and_non_ethernet_uses_client_id() -> None:
    event = {
        "message_type": 2,
        "op": 2,
        "hardware_type": 99,
        "hardware_length": 4,
        "client_mac": "01020304",
        "client_id": "ff001122",
        "assigned": "10.0.0.20",
        "next_server": "10.0.0.1",
        "relay": "10.0.0.254",
    }
    result = parse_dhcp(frame(event))[0]
    assert result.fields["client_mac"] is None
    assert result.fields["client_identifier"] == "ff001122"
    assert result.fields["server_identifier"] == "10.0.0.1"
    assert result.fields["relay_address"] == "10.0.0.254"
    assert result.expires_at is None


def test_address_reuse_and_bounded_lease_tracking_are_explicit() -> None:
    parser = DhcpParser(max_tracked_leases=1)
    first = {"message_type": 5, "op": 2, "client_mac": "001122334401", "assigned": "10.0.0.20"}
    renewal = {"message_type": 5, "op": 2, "client_mac": "001122334401", "assigned": "10.0.0.20"}
    reused = {"message_type": 5, "op": 2, "client_mac": "001122334402", "assigned": "10.0.0.20"}
    other = {"message_type": 5, "op": 2, "client_mac": "001122334403", "assigned": "10.0.0.21"}

    assert [item.kind for item in parser(frame(first))] == ["dhcp_message"]
    assert [item.kind for item in parser(frame(renewal))] == ["dhcp_message"]
    output = tuple(parser(frame(reused)))
    assert [item.kind for item in output] == ["dhcp_message", "dhcp_address_reuse"]
    assert output[1].fields == {
        "address": "10.0.0.20",
        "previous_client": "00:11:22:33:44:01",
        "current_client": "00:11:22:33:44:02",
        "interface": "eth-test",
    }
    tuple(parser(frame(other)))
    assert parser.tracked_lease_count == 1
    assert [item.kind for item in parser(frame(first))] == ["dhcp_message"]


def test_non_ack_and_ack_without_identity_do_not_track() -> None:
    parser = DhcpParser()
    discover = {"message_type": 1, "op": 1, "client_mac": "001122334455"}
    assert [item.kind for item in parser(frame(discover))] == ["dhcp_message"]
    no_identity = {
        "message_type": 5,
        "op": 2,
        "hardware_type": 99,
        "hardware_length": 4,
        "client_mac": "01020304",
        "assigned": "10.0.0.20",
    }
    assert [item.kind for item in parser(frame(no_identity))] == ["dhcp_message"]
    assert parser.tracked_lease_count == 0
    with pytest.raises(ValueError, match="capacity"):
        DhcpParser(max_tracked_leases=0)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda data: data[:239], "shorter"),
        (lambda data: data + bytes(MAX_DHCP_FRAME_BYTES), "size limit"),
        (lambda data: data[:236] + b"bad!" + data[240:], "cookie"),
        (lambda data: bytes((3,)) + data[1:], "operation"),
        (lambda data: data[:2] + bytes((0,)) + data[3:], "operation"),
        (lambda data: data[:-1], "end marker"),
        (lambda data: data[:-1] + bytes((54,)), "length is truncated"),
        (lambda data: data[:-1] + bytes((54, 4, 1, 2)), "value is truncated"),
        (lambda data: data + b"", "protocol"),
    ],
)
def test_malformed_frames_are_isolated(
    mutate: Any, message: str, events: dict[str, dict[str, Any]]
) -> None:
    payload = mutate(packet(events["discover"]))
    protocol = "other" if message == "protocol" else "dhcp"
    with pytest.raises(PassiveParseError, match=message):
        parse_dhcp(PassiveFrame(protocol, payload, NOW))


@pytest.mark.parametrize(
    ("code", "value", "message"),
    [
        (53, b"", "option 53"),
        (53, b"\x09", "unsupported"),
        (54, b"\x01", "option 54"),
        (50, b"\x01", "option 50"),
        (51, b"\x01", "option 51"),
        (58, b"\x01", "option 58"),
        (59, b"\x01", "option 59"),
        (3, b"", "option 3"),
        (6, b"\x01", "option 6"),
        (12, b"", "option 12"),
        (15, b"\x00", "option 15"),
    ],
)
def test_malformed_options_are_rejected(
    code: int, value: bytes, message: str, events: dict[str, dict[str, Any]]
) -> None:
    base = packet({"message_type": 1, "op": 1})
    payload = (
        base[:240] + _option(code, value) + base[243:]
        if code == 53
        else base[:-1] + _option(code, value) + bytes((255,))
    )
    with pytest.raises(PassiveParseError, match=message):
        parse_dhcp(PassiveFrame("dhcp", payload, NOW))


def test_duplicate_option_and_operation_message_mismatch_are_rejected(
    events: dict[str, dict[str, Any]],
) -> None:
    base = packet(events["discover"])
    duplicate = base[:-1] + _option(53, b"\x01") + bytes((255,))
    with pytest.raises(PassiveParseError, match="duplicate"):
        parse_dhcp(PassiveFrame("dhcp", duplicate, NOW))
    mismatch = dict(events["discover"], op=2)
    with pytest.raises(PassiveParseError, match="conflicts"):
        parse_dhcp(frame(mismatch))
    server_mismatch = dict(events["offer-a"], op=1)
    with pytest.raises(PassiveParseError, match="conflicts"):
        parse_dhcp(frame(server_mismatch))


def test_pad_unknown_options_and_default_redactor_are_safe(
    events: dict[str, dict[str, Any]],
) -> None:
    base = packet(events["discover"])
    payload = base[:240] + b"\x00" + _option(200, b"ignored") + base[240:]
    result = parse_dhcp(PassiveFrame("dhcp", payload, NOW))[0]
    assert result.fields["message_type"] == "discover"


def test_pipeline_bounds_deduplicates_redacts_and_retains_no_payload() -> None:
    async def scenario() -> None:
        output: list[PassiveObservation] = []

        async def sink(item: PassiveObservation) -> None:
            output.append(item)

        parser = DhcpParser(redactor=Redactor(("supersecret",)))
        pipeline = PassiveEventPipeline(
            parsers={"dhcp": (parser,)},
            sink=sink,
            queue_size=2,
            worker_count=1,
            max_frame_bytes=600,
        )
        event = {
            "message_type": 1,
            "op": 1,
            "client_mac": "001122334455",
            "hostname": "supersecret",
            "vendor": "password=visible-value",
        }
        raw = packet(event)
        await pipeline.start()
        assert await pipeline.submit("dhcp", raw, observed_at=NOW, interface="eth-test")
        assert await pipeline.submit("dhcp", raw, observed_at=NOW, interface="eth-test")
        metrics = await pipeline.stop()
        assert len(output) == 1
        assert output[0].fields["hostname"] == REDACTED
        assert output[0].fields["vendor_class"] == f"password={REDACTED}"
        assert not hasattr(output[0], "payload")
        assert raw not in repr(output).encode()
        assert metrics.duplicate_observations == 1
        assert metrics.parser_failures == 0

    asyncio.run(scenario())
