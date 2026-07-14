"""Bounded, passive-only DHCPv4 observation parsing.

The parser consumes transient frames supplied by the passive pipeline and emits
only normalized metadata.  It has no socket, capture, transmission, or raw
artifact interface and therefore cannot act as a DHCP client or server.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import OrderedDict
from collections.abc import Iterable
from datetime import timedelta

from field_discovery.passive import JsonValue, PassiveFrame, PassiveObservation, PassiveParseError
from field_discovery.redaction import Redactor

BOOTP_HEADER_BYTES = 236
DHCP_FIXED_BYTES = 240
DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"
MAX_DHCP_FRAME_BYTES = 4_096
MAX_TRACKED_LEASES = 4_096

_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}
_CLIENT_MESSAGES = frozenset({"discover", "request", "decline", "release", "inform"})
_SERVER_MESSAGES = frozenset({"offer", "ack", "nak"})


def _ipv4(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(raw))


def _nonzero_ipv4(raw: bytes) -> str | None:
    value = _ipv4(raw)
    return None if value == "0.0.0.0" else value


def _options(payload: bytes) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    offset = DHCP_FIXED_BYTES
    ended = False
    while offset < len(payload):
        code = payload[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            ended = True
            break
        if offset >= len(payload):
            raise PassiveParseError("DHCP option length is truncated")
        length = payload[offset]
        offset += 1
        end = offset + length
        if end > len(payload):
            raise PassiveParseError("DHCP option value is truncated")
        if code in result:
            raise PassiveParseError(f"duplicate DHCP option {code}")
        result[code] = payload[offset:end]
        offset = end
    if not ended:
        raise PassiveParseError("DHCP options have no end marker")
    return result


def _fixed(options: dict[int, bytes], code: int, length: int) -> bytes | None:
    value = options.get(code)
    if value is not None and len(value) != length:
        raise PassiveParseError(f"DHCP option {code} must be {length} bytes")
    return value


def _seconds(options: dict[int, bytes], code: int) -> int | None:
    value = _fixed(options, code, 4)
    return None if value is None else struct.unpack("!I", value)[0]


def _address_list(options: dict[int, bytes], code: int) -> list[JsonValue]:
    value = options.get(code)
    if value is None:
        return []
    if not value or len(value) % 4:
        raise PassiveParseError(f"DHCP option {code} must contain IPv4 addresses")
    return [_ipv4(value[offset : offset + 4]) for offset in range(0, len(value), 4)]


def _text(options: dict[int, bytes], code: int, redactor: Redactor) -> str | None:
    value = options.get(code)
    if value is None:
        return None
    if not value:
        raise PassiveParseError(f"DHCP option {code} must not be empty")
    decoded = value.decode("utf-8", errors="replace").strip().strip("\x00")
    if not decoded:
        raise PassiveParseError(f"DHCP option {code} has no usable text")
    return redactor.text(decoded)


def parse_dhcp(
    frame: PassiveFrame, *, redactor: Redactor | None = None
) -> tuple[PassiveObservation, ...]:
    """Parse one captured DHCPv4 BOOTP payload into bounded structured metadata."""
    payload = frame.payload
    if frame.protocol.casefold() != "dhcp":
        raise PassiveParseError("DHCP parser received a different protocol")
    if len(payload) < DHCP_FIXED_BYTES:
        raise PassiveParseError("DHCP frame is shorter than the fixed header")
    if len(payload) > MAX_DHCP_FRAME_BYTES:
        raise PassiveParseError("DHCP frame exceeds the parser size limit")
    if payload[BOOTP_HEADER_BYTES:DHCP_FIXED_BYTES] != DHCP_MAGIC_COOKIE:
        raise PassiveParseError("DHCP magic cookie is missing")
    operation = payload[0]
    hardware_type = payload[1]
    hardware_length = payload[2]
    if operation not in {1, 2} or not 1 <= hardware_length <= 16:
        raise PassiveParseError("BOOTP operation or hardware length is invalid")

    options = _options(payload)
    message_value = _fixed(options, 53, 1)
    if message_value is None or message_value[0] not in _MESSAGE_TYPES:
        raise PassiveParseError("DHCP message type is missing or unsupported")
    message_type = _MESSAGE_TYPES[message_value[0]]
    if (message_type in _CLIENT_MESSAGES and operation != 1) or (
        message_type in _SERVER_MESSAGES and operation != 2
    ):
        raise PassiveParseError("DHCP message type conflicts with BOOTP operation")

    actual_redactor = redactor or Redactor()
    transaction_id = payload[4:8].hex()
    client_address = _nonzero_ipv4(payload[12:16])
    offered_address = _nonzero_ipv4(payload[16:20])
    next_server = _nonzero_ipv4(payload[20:24])
    relay_address = _nonzero_ipv4(payload[24:28])
    raw_client_hardware = payload[28 : 28 + hardware_length]
    client_mac = (
        ":".join(f"{octet:02x}" for octet in raw_client_hardware)
        if hardware_type == 1 and hardware_length == 6
        else None
    )
    client_identifier = options.get(61)
    server_identifier_value = _fixed(options, 54, 4)
    requested_address_value = _fixed(options, 50, 4)
    lease_seconds = _seconds(options, 51)
    renewal_seconds = _seconds(options, 58)
    rebinding_seconds = _seconds(options, 59)
    server_identifier = (
        _ipv4(server_identifier_value) if server_identifier_value is not None else next_server
    )
    assigned_address = (
        offered_address or client_address if message_type in {"offer", "ack"} else client_address
    )
    requested_address = (
        _ipv4(requested_address_value) if requested_address_value is not None else None
    )
    fields: dict[str, JsonValue] = {
        "message_type": message_type,
        "transaction_id": transaction_id,
        "client_mac": client_mac,
        "client_identifier": client_identifier.hex() if client_identifier else None,
        "client_address": client_address,
        "requested_address": requested_address,
        "assigned_address": assigned_address,
        "server_identifier": server_identifier,
        "relay_address": relay_address,
        "lease_seconds": lease_seconds,
        "renewal_seconds": renewal_seconds,
        "rebinding_seconds": rebinding_seconds,
        "hostname": _text(options, 12, actual_redactor),
        "vendor_class": _text(options, 60, actual_redactor),
        "routers": _address_list(options, 3),
        "dns_servers": _address_list(options, 6),
        "domain_name": _text(options, 15, actual_redactor),
        "is_renewal": message_type in {"request", "ack"} and client_address is not None,
        "interface": frame.interface,
    }
    expires_at = (
        frame.observed_at + timedelta(seconds=lease_seconds)
        if lease_seconds is not None and message_type in {"offer", "ack"}
        else None
    )
    return (
        PassiveObservation(
            "dhcp_message",
            fields,
            "passive.dhcp",
            observed_at=frame.observed_at,
            expires_at=expires_at,
        ),
    )


class DhcpParser:
    """Stateful bounded wrapper that discloses observed address reuse."""

    def __init__(
        self,
        *,
        redactor: Redactor | None = None,
        max_tracked_leases: int = MAX_TRACKED_LEASES,
    ) -> None:
        if max_tracked_leases < 1:
            raise ValueError("DHCP lease tracking capacity must be positive")
        self._redactor = redactor or Redactor()
        self._max_tracked_leases = max_tracked_leases
        self._leases: OrderedDict[str, str] = OrderedDict()

    @property
    def tracked_lease_count(self) -> int:
        """Return the bounded count without exposing client identities."""
        return len(self._leases)

    def __call__(self, frame: PassiveFrame) -> Iterable[PassiveObservation]:
        """Parse metadata and optionally emit an explicit address-reuse conflict."""
        parsed = parse_dhcp(frame, redactor=self._redactor)
        message = parsed[0]
        fields = message.fields
        assigned = fields.get("assigned_address")
        client = fields.get("client_mac") or fields.get("client_identifier")
        yield message
        if fields.get("message_type") != "ack" or not isinstance(assigned, str) or not client:
            return
        client_text = str(client)
        previous = self._leases.get(assigned)
        if previous is not None and previous != client_text:
            yield PassiveObservation(
                "dhcp_address_reuse",
                {
                    "address": assigned,
                    "previous_client": previous,
                    "current_client": client_text,
                    "interface": fields.get("interface"),
                },
                "passive.dhcp",
                observed_at=message.observed_at,
            )
        self._leases[assigned] = client_text
        self._leases.move_to_end(assigned)
        if len(self._leases) > self._max_tracked_leases:
            self._leases.popitem(last=False)
