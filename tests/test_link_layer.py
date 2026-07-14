"""Sanitized LLDP/CDP replay tests; no live capture or transmission."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from field_discovery.link_layer import link_layer_parsers, parse_cdp, parse_lldp
from field_discovery.passive import (
    PassiveEventPipeline,
    PassiveFrame,
    PassiveObservation,
    PassiveParseError,
)

NOW = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures" / "passive" / "link-layer.json"


def _fixtures() -> dict[str, dict[str, str]]:
    return cast(dict[str, dict[str, str]], json.loads(FIXTURE.read_text(encoding="utf-8")))


def _frame(name: str) -> PassiveFrame:
    fixture = _fixtures()[name]
    return PassiveFrame(fixture["protocol"], bytes.fromhex(fixture["payload_hex"]), NOW, "eth-test")


def _single(
    parser: Callable[[PassiveFrame], Iterable[PassiveObservation]], frame: PassiveFrame
) -> PassiveObservation:
    return next(iter(parser(frame)))


@pytest.mark.parametrize(
    ("fixture", "name", "port", "address", "vlan", "ttl"),
    [
        ("generic_lldp", "generic-switch", "port-1", "192.0.2.20", 10, 120),
        ("aruba_lldp", "aruba-ap-01", "1/1/1", "192.0.2.21", 20, 90),
        ("hp_lldp", "hp-switch-01", "A1", "192.0.2.22", 30, 60),
    ],
)
def test_sanitized_generic_aruba_and_hp_lldp_replay(
    fixture: str, name: str, port: str, address: str, vlan: int, ttl: int
) -> None:
    result = _single(parse_lldp, _frame(fixture))
    assert result.kind == "link_layer_neighbor"
    assert result.source == "passive:lldp"
    assert result.observed_at == NOW
    assert result.expires_at == NOW + timedelta(seconds=ttl)
    assert result.fields["protocol"] == "lldp"
    assert result.fields["local_interface"] == "eth-test"
    assert result.fields["system_name"] == name
    assert result.fields["port_id"] == port
    assert result.fields["management_address"] == address
    assert result.fields["vlan_id"] == vlan
    assert result.fields["ttl_seconds"] == ttl
    assert result.fields["chassis_id"].startswith("02:00:00:")  # type: ignore[union-attr]
    assert result.fields["capabilities_supported"]


def test_sanitized_cisco_cdp_replay_and_unknown_tlv() -> None:
    result = _single(parse_cdp, _frame("cisco_cdp"))
    assert result.source == "passive:cdp"
    assert result.expires_at == NOW + timedelta(seconds=180)
    assert result.fields == {
        "protocol": "cdp",
        "protocol_version": 2,
        "ttl_seconds": 180,
        "local_interface": "eth-test",
        "chassis_id_subtype": "device_name",
        "chassis_id": "cisco-edge-01",
        "system_name": "cisco-edge-01",
        "port_id_subtype": "interface_name",
        "port_id": "GigabitEthernet1/0/24",
        "capabilities_enabled": ["router", "switch", "igmp"],
        "system_description": "Cisco IOS synthetic",
        "platform": "Cisco C9300",
        "vlan_id": 120,
        "management_address": "192.0.2.10",
        "management_addresses": ["192.0.2.10"],
    }


def test_link_layer_parsers_integrate_with_pipeline_and_expire() -> None:
    async def scenario() -> None:
        output: list[PassiveObservation] = []

        async def sink(item: PassiveObservation) -> None:
            output.append(item)

        registrations = link_layer_parsers()
        pipeline = PassiveEventPipeline(parsers=registrations, sink=sink, dedupe_window_seconds=0)
        await pipeline.start()
        for fixture in ("generic_lldp", "cisco_cdp"):
            frame = _frame(fixture)
            assert await pipeline.submit(
                frame.protocol,
                frame.payload,
                observed_at=frame.observed_at,
                interface=frame.interface,
            )
        metrics = await pipeline.stop()
        assert metrics.emitted_observations == 2
        assert metrics.parser_failures == 0
        assert [item.expires_at for item in output] == [
            NOW + timedelta(seconds=120),
            NOW + timedelta(seconds=180),
        ]
        assert all(not hasattr(item, "payload") for item in output)

    asyncio.run(scenario())


def _lldp_tlv(tlv_type: int, value: bytes) -> bytes:
    return ((tlv_type << 9) | len(value)).to_bytes(2, "big") + value


def _cdp_tlv(tlv_type: int, value: bytes) -> bytes:
    return tlv_type.to_bytes(2, "big") + (len(value) + 4).to_bytes(2, "big") + value


def _minimal_lldp(*extra: bytes, ttl: int = 10) -> bytes:
    return b"".join(
        (
            _lldp_tlv(1, b"\x07node"),
            _lldp_tlv(2, b"\x05port"),
            _lldp_tlv(3, ttl.to_bytes(2, "big")),
            *extra,
            _lldp_tlv(0, b""),
        )
    )


def _minimal_cdp(*extra: bytes, version: int = 2) -> bytes:
    return b"".join(
        (
            bytes((version, 10, 0, 0)),
            _cdp_tlv(1, b"node"),
            _cdp_tlv(3, b"port"),
            *extra,
        )
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x02",
        _lldp_tlv(1, b"\x07node") + b"\x04",
        _lldp_tlv(1, b"\x07node") + b"\x04\x10x",
        _minimal_lldp()[:-2],
        _minimal_lldp() + b"x",
        _lldp_tlv(0, b"x"),
        _lldp_tlv(1, b"\x07node") + _lldp_tlv(1, b"\x07again") + _minimal_lldp(),
        _lldp_tlv(1, b"\x07node") + _lldp_tlv(2, b"\x05port") + _lldp_tlv(0, b""),
        _minimal_lldp(_lldp_tlv(3, b"x")),
        _minimal_lldp(_lldp_tlv(7, b"x")),
        _minimal_lldp(_lldp_tlv(8, b"x")),
        _minimal_lldp(_lldp_tlv(127, b"x")),
        _minimal_lldp(_lldp_tlv(127, b"\x00\x80\xc2\x01x")),
    ],
)
def test_truncated_and_invalid_lldp_frames_are_rejected(payload: bytes) -> None:
    with pytest.raises(PassiveParseError):
        tuple(parse_lldp(PassiveFrame("lldp", payload, NOW)))


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x02\x0a\x00",
        _minimal_cdp(version=3),
        b"\x02\x0a\x00\x00\x00",
        b"\x02\x0a\x00\x00\x00\x01\x00\x03",
        b"\x02\x0a\x00\x00\x00\x01\x00\x08x",
        bytes((2, 10, 0, 0)) + _cdp_tlv(1, b"node"),
        _minimal_cdp(_cdp_tlv(4, b"x")),
        _minimal_cdp(_cdp_tlv(10, b"x")),
        _minimal_cdp(_cdp_tlv(2, b"x")),
    ],
)
def test_truncated_and_invalid_cdp_frames_are_rejected(payload: bytes) -> None:
    with pytest.raises(PassiveParseError):
        tuple(parse_cdp(PassiveFrame("cdp", payload, NOW)))


def test_identity_variants_management_addresses_and_zero_ttl() -> None:
    ipv4_network_id = _lldp_tlv(1, b"\x05\x01\xc0\x00\x02\x63")
    ipv6_port_id = _lldp_tlv(2, b"\x04\x02" + bytes.fromhex("20010db8000000000000000000000001"))
    payload = ipv4_network_id + ipv6_port_id + _lldp_tlv(3, b"\x00\x00") + _lldp_tlv(0, b"")
    result = _single(parse_lldp, PassiveFrame("lldp", payload, NOW))
    assert result.fields["chassis_id"] == "192.0.2.99"
    assert result.fields["port_id"] == "2001:db8::1"
    assert result.expires_at == NOW

    addresses = (
        (2).to_bytes(4, "big")
        + b"\x01\x01\xcc\x00\x04\xc0\x00\x02\x0b"
        + b"\x01\x01\x8e\x00\x10"
        + bytes.fromhex("20010db8000000000000000000000002")
    )
    cdp = _minimal_cdp(_cdp_tlv(2, addresses))
    result = _single(parse_cdp, PassiveFrame("cdp", cdp, NOW))
    assert result.fields["management_addresses"] == ["192.0.2.11", "2001:db8::2"]


def test_wrong_parser_protocol_and_text_validation() -> None:
    with pytest.raises(PassiveParseError, match="different protocol"):
        tuple(parse_lldp(PassiveFrame("cdp", _minimal_lldp(), NOW)))
    with pytest.raises(PassiveParseError, match="different protocol"):
        tuple(parse_cdp(PassiveFrame("lldp", _minimal_cdp(), NOW)))
    with pytest.raises(PassiveParseError, match="UTF-8"):
        tuple(parse_lldp(PassiveFrame("lldp", _minimal_lldp(_lldp_tlv(5, b"\xff")), NOW)))
    with pytest.raises(PassiveParseError, match="system name"):
        tuple(parse_lldp(PassiveFrame("lldp", _minimal_lldp(_lldp_tlv(5, b"")), NOW)))


def test_parser_failure_does_not_stop_later_pipeline_frames() -> None:
    async def scenario() -> None:
        output: list[PassiveObservation] = []

        async def sink(item: PassiveObservation) -> None:
            output.append(item)

        pipeline = PassiveEventPipeline(parsers={"lldp": (parse_lldp,)}, sink=sink)
        await pipeline.start()
        assert await pipeline.submit("lldp", b"truncated", observed_at=NOW)
        valid = _frame("generic_lldp")
        assert await pipeline.submit("lldp", valid.payload, observed_at=NOW)
        metrics = await pipeline.stop()
        assert metrics.parser_failures == 1
        assert metrics.emitted_observations == 1
        assert output[0].fields["system_name"] == "generic-switch"

    asyncio.run(scenario())


def test_optional_lldp_fields_and_non_vlan_organizational_tlv() -> None:
    payload = _minimal_lldp(
        _lldp_tlv(4, b"uplink"),
        _lldp_tlv(127, b"\x00\x01\x02\x03"),
    )
    result = _single(parse_lldp, PassiveFrame("lldp", payload, NOW))
    assert result.fields["port_description"] == "uplink"
    assert "vlan_id" not in result.fields


@pytest.mark.parametrize(
    "payload",
    [
        _lldp_tlv(1, b"\x07node")
        + _lldp_tlv(2, b"\x05port")
        + _lldp_tlv(3, b"x")
        + _lldp_tlv(0, b""),
        _lldp_tlv(1, b"\x07")
        + _lldp_tlv(2, b"\x05port")
        + _lldp_tlv(3, b"\x00\x01")
        + _lldp_tlv(0, b""),
        _lldp_tlv(1, b"\x04xx")
        + _lldp_tlv(2, b"\x05port")
        + _lldp_tlv(3, b"\x00\x01")
        + _lldp_tlv(0, b""),
        _lldp_tlv(1, b"\x05\x01")
        + _lldp_tlv(2, b"\x05port")
        + _lldp_tlv(3, b"\x00\x01")
        + _lldp_tlv(0, b""),
        _lldp_tlv(1, b"\x05\x03xxxx")
        + _lldp_tlv(2, b"\x05port")
        + _lldp_tlv(3, b"\x00\x01")
        + _lldp_tlv(0, b""),
        _minimal_lldp(_lldp_tlv(8, b"\x14" + b"\x00" * 6)),
        b"".join(_lldp_tlv(9, b"") for _ in range(129)) + _lldp_tlv(0, b""),
    ],
)
def test_additional_lldp_bounds(payload: bytes) -> None:
    with pytest.raises(PassiveParseError):
        tuple(parse_lldp(PassiveFrame("lldp", payload, NOW)))


@pytest.mark.parametrize(
    "addresses",
    [
        (65).to_bytes(4, "big"),
        (1).to_bytes(4, "big"),
        (1).to_bytes(4, "big") + b"\x00\x05",
        (1).to_bytes(4, "big") + b"\x00\x00",
        (1).to_bytes(4, "big") + b"\x00\x00\x00\x05x",
        (0).to_bytes(4, "big") + b"x",
    ],
)
def test_additional_cdp_address_bounds(addresses: bytes) -> None:
    with pytest.raises(PassiveParseError):
        tuple(parse_cdp(PassiveFrame("cdp", _minimal_cdp(_cdp_tlv(2, addresses)), NOW)))


def test_empty_and_ignored_cdp_address_sets_and_tlv_limit() -> None:
    empty = (0).to_bytes(4, "big")
    ignored = (1).to_bytes(4, "big") + b"\x00\x00\x00\x01x"
    result = _single(
        parse_cdp,
        PassiveFrame(
            "cdp",
            _minimal_cdp(_cdp_tlv(2, empty), _cdp_tlv(0x16, empty), _cdp_tlv(2, ignored)),
            NOW,
        ),
    )
    assert "management_address" not in result.fields

    excessive = bytes((2, 10, 0, 0)) + b"".join(_cdp_tlv(0x7777, b"") for _ in range(129))
    with pytest.raises(PassiveParseError, match="too many"):
        tuple(parse_cdp(PassiveFrame("cdp", excessive, NOW)))
