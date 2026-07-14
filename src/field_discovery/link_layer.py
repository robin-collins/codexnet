"""Bounded LLDP and CDP parsers for passive synthetic/capture input.

The functions in this module only decode bytes already supplied to them. They
open no sockets, send no discovery requests, and retain no input payload.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator
from datetime import timedelta

from field_discovery.passive import (
    JsonValue,
    PassiveFrame,
    PassiveObservation,
    PassiveParseError,
    PassiveParser,
)

_MAX_LLDP_BYTES = 4_096
_MAX_CDP_BYTES = 8_192
_MAX_TLVS = 128
_IEEE_8021_OUI = b"\x00\x80\xc2"

_LLDP_CAPABILITIES = (
    (0x0001, "other"),
    (0x0002, "repeater"),
    (0x0004, "bridge"),
    (0x0008, "wlan_access_point"),
    (0x0010, "router"),
    (0x0020, "telephone"),
    (0x0040, "docsis"),
    (0x0080, "station"),
    (0x0100, "customer_vlan"),
    (0x0200, "service_vlan"),
    (0x0400, "two_port_mac_relay"),
)

_CDP_CAPABILITIES = (
    (0x0001, "router"),
    (0x0002, "transparent_bridge"),
    (0x0004, "source_route_bridge"),
    (0x0008, "switch"),
    (0x0010, "host"),
    (0x0020, "igmp"),
    (0x0040, "repeater"),
    (0x0080, "telephone"),
    (0x0100, "remotely_managed"),
    (0x0200, "two_port_mac_relay"),
)


def parse_lldp(frame: PassiveFrame) -> Iterable[PassiveObservation]:
    """Parse an LLDPDU TLV stream into one normalized neighbour observation."""
    if frame.protocol != "lldp":
        raise PassiveParseError("LLDP parser received a different protocol")
    fields: dict[str, JsonValue] = {"protocol": "lldp"}
    if frame.interface is not None:
        fields["local_interface"] = frame.interface
    required: set[int] = set()
    ended = False
    for tlv_type, value in _lldp_tlvs(frame.payload):
        if tlv_type == 0:
            ended = True
            continue
        if tlv_type in {1, 2, 3}:
            if tlv_type in required:
                raise PassiveParseError("duplicate mandatory LLDP TLV")
            required.add(tlv_type)
        if tlv_type == 1:
            subtype, identifier = _identifier(value, "chassis")
            fields["chassis_id_subtype"] = subtype
            fields["chassis_id"] = identifier
        elif tlv_type == 2:
            subtype, identifier = _identifier(value, "port")
            fields["port_id_subtype"] = subtype
            fields["port_id"] = identifier
        elif tlv_type == 3:
            if len(value) != 2:
                raise PassiveParseError("invalid LLDP TTL")
            fields["ttl_seconds"] = int.from_bytes(value, "big")
        elif tlv_type == 4:
            fields["port_description"] = _text(value, 512, "LLDP port description")
        elif tlv_type == 5:
            fields["system_name"] = _text(value, 255, "LLDP system name")
        elif tlv_type == 6:
            fields["system_description"] = _text(value, 1_024, "LLDP system description")
        elif tlv_type == 7:
            supported, enabled = _lldp_capabilities(value)
            fields["capabilities_supported"] = supported
            fields["capabilities_enabled"] = enabled
        elif tlv_type == 8:
            fields["management_address"] = _lldp_management_address(value)
        elif tlv_type == 127:
            vlan = _lldp_organizational(value)
            if vlan is not None:
                fields["vlan_id"] = vlan
        # Unknown TLVs are safely bounded by _lldp_tlvs and intentionally ignored.
    if not ended:
        raise PassiveParseError("LLDP end TLV is missing")
    if required != {1, 2, 3}:
        raise PassiveParseError("LLDP mandatory TLVs are missing")
    ttl = fields["ttl_seconds"]
    assert isinstance(ttl, int)
    yield PassiveObservation(
        "link_layer_neighbor",
        fields,
        "passive:lldp",
        observed_at=frame.observed_at,
        expires_at=frame.observed_at + timedelta(seconds=ttl),
    )


def parse_cdp(frame: PassiveFrame) -> Iterable[PassiveObservation]:
    """Parse a Cisco CDP PDU into one normalized neighbour observation."""
    if frame.protocol != "cdp":
        raise PassiveParseError("CDP parser received a different protocol")
    payload = frame.payload
    if not 4 <= len(payload) <= _MAX_CDP_BYTES:
        raise PassiveParseError("CDP frame length is invalid")
    version, ttl = payload[0], payload[1]
    if version not in {1, 2}:
        raise PassiveParseError("unsupported CDP version")
    fields: dict[str, JsonValue] = {
        "protocol": "cdp",
        "protocol_version": version,
        "ttl_seconds": ttl,
    }
    if frame.interface is not None:
        fields["local_interface"] = frame.interface
    for tlv_type, value in _cdp_tlvs(payload[4:]):
        if tlv_type == 0x0001:
            fields["chassis_id_subtype"] = "device_name"
            fields["chassis_id"] = _text(value, 255, "CDP device ID")
            fields["system_name"] = fields["chassis_id"]
        elif tlv_type == 0x0002:
            addresses = _cdp_addresses(value)
            if addresses:
                fields["management_address"] = addresses[0]
                fields["management_addresses"] = addresses
        elif tlv_type == 0x0003:
            fields["port_id_subtype"] = "interface_name"
            fields["port_id"] = _text(value, 255, "CDP port ID")
        elif tlv_type == 0x0004:
            if len(value) != 4:
                raise PassiveParseError("invalid CDP capabilities")
            fields["capabilities_enabled"] = _capability_names(
                int.from_bytes(value, "big"), _CDP_CAPABILITIES
            )
        elif tlv_type == 0x0005:
            fields["system_description"] = _text(value, 1_024, "CDP software version")
        elif tlv_type == 0x0006:
            fields["platform"] = _text(value, 255, "CDP platform")
        elif tlv_type == 0x000A:
            if len(value) != 2:
                raise PassiveParseError("invalid CDP native VLAN")
            fields["vlan_id"] = int.from_bytes(value, "big")
        elif tlv_type == 0x0016:
            addresses = _cdp_addresses(value)
            if addresses:
                fields["management_address"] = addresses[0]
                fields["management_addresses"] = addresses
        # Unknown TLVs are length checked and ignored.
    if "chassis_id" not in fields or "port_id" not in fields:
        raise PassiveParseError("CDP device or port identity is missing")
    yield PassiveObservation(
        "link_layer_neighbor",
        fields,
        "passive:cdp",
        observed_at=frame.observed_at,
        expires_at=frame.observed_at + timedelta(seconds=ttl),
    )


def link_layer_parsers() -> dict[str, tuple[PassiveParser, ...]]:
    """Return passive-pipeline registrations without activating capture."""
    return {"lldp": (parse_lldp,), "cdp": (parse_cdp,)}


def _lldp_tlvs(payload: bytes) -> Iterator[tuple[int, bytes]]:
    if not 2 <= len(payload) <= _MAX_LLDP_BYTES:
        raise PassiveParseError("LLDP frame length is invalid")
    offset = 0
    count = 0
    while offset < len(payload):
        if len(payload) - offset < 2:
            raise PassiveParseError("truncated LLDP TLV header")
        header = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2
        tlv_type, length = header >> 9, header & 0x01FF
        if length > len(payload) - offset:
            raise PassiveParseError("truncated LLDP TLV value")
        count += 1
        if count > _MAX_TLVS:
            raise PassiveParseError("too many LLDP TLVs")
        value = payload[offset : offset + length]
        offset += length
        if tlv_type == 0:
            if length != 0:
                raise PassiveParseError("invalid LLDP end TLV")
            if any(payload[offset:]):
                raise PassiveParseError("non-padding bytes follow LLDP end TLV")
            yield tlv_type, value
            return
        yield tlv_type, value


def _cdp_tlvs(payload: bytes) -> Iterator[tuple[int, bytes]]:
    offset = 0
    count = 0
    while offset < len(payload):
        if len(payload) - offset < 4:
            raise PassiveParseError("truncated CDP TLV header")
        tlv_type = int.from_bytes(payload[offset : offset + 2], "big")
        length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        if length < 4 or length > len(payload) - offset:
            raise PassiveParseError("invalid or truncated CDP TLV")
        count += 1
        if count > _MAX_TLVS:
            raise PassiveParseError("too many CDP TLVs")
        yield tlv_type, payload[offset + 4 : offset + length]
        offset += length


def _identifier(value: bytes, identity: str) -> tuple[str, str]:
    if len(value) < 2:
        raise PassiveParseError(f"invalid LLDP {identity} ID")
    subtype, body = value[0], value[1:]
    chassis_names = {
        1: "chassis_component",
        2: "interface_alias",
        3: "port_component",
        4: "mac_address",
        5: "network_address",
        6: "interface_name",
        7: "locally_assigned",
    }
    port_names = {
        1: "interface_alias",
        2: "port_component",
        3: "mac_address",
        4: "network_address",
        5: "interface_name",
        6: "agent_circuit_id",
        7: "locally_assigned",
    }
    mac_subtype = 4 if identity == "chassis" else 3
    network_subtype = 5 if identity == "chassis" else 4
    if subtype == mac_subtype:
        if len(body) != 6:
            raise PassiveParseError(f"invalid LLDP {identity} MAC")
        identifier = ":".join(f"{octet:02x}" for octet in body)
    elif subtype == network_subtype:
        identifier = _network_address(body, f"LLDP {identity}")
    else:
        identifier = _text(body, 255, f"LLDP {identity} ID")
    names = chassis_names if identity == "chassis" else port_names
    return names.get(subtype, f"unknown_{subtype}"), identifier


def _lldp_capabilities(value: bytes) -> tuple[list[JsonValue], list[JsonValue]]:
    if len(value) != 4:
        raise PassiveParseError("invalid LLDP capabilities")
    supported = int.from_bytes(value[:2], "big")
    enabled = int.from_bytes(value[2:], "big")
    return (
        _capability_names(supported, _LLDP_CAPABILITIES),
        _capability_names(enabled, _LLDP_CAPABILITIES),
    )


def _capability_names(value: int, definitions: tuple[tuple[int, str], ...]) -> list[JsonValue]:
    return [name for bit, name in definitions if value & bit]


def _lldp_management_address(value: bytes) -> str:
    if len(value) < 7:
        raise PassiveParseError("invalid LLDP management address")
    address_length = value[0]
    if address_length < 2 or 1 + address_length + 5 > len(value):
        raise PassiveParseError("truncated LLDP management address")
    return _network_address(value[1 : 1 + address_length], "LLDP management")


def _lldp_organizational(value: bytes) -> int | None:
    if len(value) < 4:
        raise PassiveParseError("truncated LLDP organizational TLV")
    if value[:3] == _IEEE_8021_OUI and value[3] == 1:
        if len(value) != 6:
            raise PassiveParseError("invalid LLDP port VLAN TLV")
        return int.from_bytes(value[4:], "big")
    return None


def _cdp_addresses(value: bytes) -> list[JsonValue]:
    if len(value) < 4:
        raise PassiveParseError("truncated CDP addresses")
    count = int.from_bytes(value[:4], "big")
    if count > 64:
        raise PassiveParseError("too many CDP addresses")
    offset = 4
    result: list[JsonValue] = []
    for _ in range(count):
        if len(value) - offset < 2:
            raise PassiveParseError("truncated CDP address protocol")
        protocol_length = value[offset + 1]
        offset += 2
        if protocol_length > len(value) - offset:
            raise PassiveParseError("truncated CDP address protocol value")
        protocol = value[offset : offset + protocol_length]
        offset += protocol_length
        if len(value) - offset < 2:
            raise PassiveParseError("truncated CDP address length")
        address_length = int.from_bytes(value[offset : offset + 2], "big")
        offset += 2
        if address_length > len(value) - offset:
            raise PassiveParseError("truncated CDP address value")
        address = value[offset : offset + address_length]
        offset += address_length
        # NLPID 0xcc denotes IPv4; common 4/16-byte values are also safe to normalize.
        if protocol == b"\xcc" or address_length in {4, 16}:
            result.append(str(ipaddress.ip_address(address)))
    if offset != len(value):
        raise PassiveParseError("trailing bytes in CDP addresses")
    return result


def _network_address(value: bytes, label: str) -> str:
    if len(value) < 2:
        raise PassiveParseError(f"invalid {label} network address")
    family, packed = value[0], value[1:]
    expected = 4 if family == 1 else 16 if family == 2 else 0
    if expected == 0 or len(packed) != expected:
        raise PassiveParseError(f"unsupported {label} address family")
    try:
        return str(ipaddress.ip_address(packed))
    except ValueError as exc:  # pragma: no cover - packed lengths already constrain ipaddress
        raise PassiveParseError(f"invalid {label} address") from exc


def _text(value: bytes, maximum: int, label: str) -> str:
    if not value or len(value) > maximum or b"\x00" in value:
        raise PassiveParseError(f"invalid {label}")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PassiveParseError(f"invalid UTF-8 in {label}") from exc
