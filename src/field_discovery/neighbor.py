"""Passive-only ARP and Linux neighbour evidence normalization."""

from __future__ import annotations

import ipaddress
import struct
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from field_discovery.passive import JsonValue, PassiveFrame, PassiveObservation, PassiveParseError

MAX_ARP_PAYLOAD_BYTES = 256
DEFAULT_NEIGHBOR_MAX_AGE = timedelta(minutes=30)
DEFAULT_DEDUPE_WINDOW = timedelta(seconds=30)
DEFAULT_TRACKED_NEIGHBORS = 4_096
_VALID_STATES = frozenset(
    {"permanent", "noarp", "reachable", "stale", "none", "incomplete", "delay", "probe", "failed"}
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("neighbor timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise PassiveParseError("neighbor IPv4 address is invalid") from exc


def _mac(value: str) -> str:
    plain = value.strip().replace(":", "").replace("-", "")
    if len(plain) != 12:
        raise PassiveParseError("neighbor MAC address is invalid")
    try:
        raw = bytes.fromhex(plain)
    except ValueError as exc:
        raise PassiveParseError("neighbor MAC address is invalid") from exc
    return ":".join(f"{octet:02x}" for octet in raw)


@dataclass(frozen=True)
class NeighborEvidence:
    """One normalized, non-merging IP/MAC relationship claim."""

    address: str
    mac_address: str | None
    interface: str
    state: str
    source: str
    observed_at: datetime
    operation: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", _ipv4(self.address))
        if self.mac_address is not None:
            object.__setattr__(self, "mac_address", _mac(self.mac_address))
        interface = self.interface.strip()
        source = self.source.strip()
        state = self.state.strip().casefold()
        if not interface or not source:
            raise PassiveParseError("neighbor interface and source must not be empty")
        if state not in _VALID_STATES:
            raise PassiveParseError("neighbor state is unsupported")
        object.__setattr__(self, "interface", interface)
        object.__setattr__(self, "source", source)
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "observed_at", _utc(self.observed_at))


def parse_arp_evidence(frame: PassiveFrame) -> NeighborEvidence:
    """Parse the sender mapping from one bounded Ethernet/IPv4 ARP payload."""
    if frame.protocol.casefold() != "arp":
        raise PassiveParseError("ARP parser received a different protocol")
    payload = frame.payload
    if len(payload) < 8:
        raise PassiveParseError("ARP payload is shorter than its header")
    if len(payload) > MAX_ARP_PAYLOAD_BYTES:
        raise PassiveParseError("ARP payload exceeds the parser size limit")
    hardware_type, protocol_type, hardware_length, protocol_length, operation = struct.unpack(
        "!HHBBH", payload[:8]
    )
    if hardware_type != 1 or protocol_type != 0x0800:
        raise PassiveParseError("ARP hardware or protocol type is unsupported")
    if hardware_length != 6 or protocol_length != 4:
        raise PassiveParseError("ARP address lengths are unsupported")
    if operation not in {1, 2}:
        raise PassiveParseError("ARP operation is unsupported")
    required = 8 + (2 * hardware_length) + (2 * protocol_length)
    if len(payload) < required:
        raise PassiveParseError("ARP address fields are truncated")
    sender_mac = ":".join(f"{octet:02x}" for octet in payload[8:14])
    sender_ip = str(ipaddress.IPv4Address(payload[14:18]))
    if sender_ip == "0.0.0.0":
        raise PassiveParseError("ARP sender IPv4 address is unspecified")
    return NeighborEvidence(
        sender_ip,
        sender_mac,
        frame.interface or "unknown",
        "reachable",
        "passive.arp",
        frame.observed_at,
        "request" if operation == 1 else "reply",
    )


def parse_kernel_neighbor(
    record: Mapping[str, Any], *, observed_at: datetime, selected_interface: str | None = None
) -> NeighborEvidence | None:
    """Normalize one already-decoded ``ip -j neighbour`` record without running commands."""
    interface_value = record.get("dev")
    address_value = record.get("dst")
    if not isinstance(interface_value, str) or not isinstance(address_value, str):
        raise PassiveParseError("kernel neighbor requires dev and dst strings")
    if selected_interface is not None and interface_value != selected_interface:
        return None
    state_value = record.get("state", "none")
    if isinstance(state_value, list):
        if not state_value or not all(isinstance(item, str) for item in state_value):
            raise PassiveParseError("kernel neighbor state is invalid")
        state = state_value[0]
    elif isinstance(state_value, str):
        state = state_value
    else:
        raise PassiveParseError("kernel neighbor state is invalid")
    mac_value = record.get("lladdr")
    if mac_value is not None and not isinstance(mac_value, str):
        raise PassiveParseError("kernel neighbor lladdr must be text")
    return NeighborEvidence(
        address_value,
        mac_value,
        interface_value,
        state,
        "kernel.neighbor",
        observed_at,
    )


@dataclass
class _TrackedNeighbor:
    evidence: NeighborEvidence
    first_seen: datetime
    last_seen: datetime
    last_emitted: datetime
    expires_at: datetime


class NeighborTracker:
    """Bounded deduplication, movement/reuse disclosure, and deterministic aging."""

    def __init__(
        self,
        *,
        max_age: timedelta = DEFAULT_NEIGHBOR_MAX_AGE,
        dedupe_window: timedelta = DEFAULT_DEDUPE_WINDOW,
        max_entries: int = DEFAULT_TRACKED_NEIGHBORS,
    ) -> None:
        if max_age <= timedelta(0) or dedupe_window < timedelta(0) or max_entries < 1:
            raise ValueError("neighbor age, dedupe, and capacity bounds are invalid")
        self._max_age = max_age
        self._dedupe_window = dedupe_window
        self._max_entries = max_entries
        self._entries: OrderedDict[tuple[str, str | None, str], _TrackedNeighbor] = OrderedDict()

    @property
    def tracked_count(self) -> int:
        """Expose only the bounded state count."""
        return len(self._entries)

    def observe(self, evidence: NeighborEvidence) -> tuple[PassiveObservation, ...]:
        """Record evidence, returning facts/conflicts but never merging identities."""
        now = evidence.observed_at
        key = (evidence.address, evidence.mac_address, evidence.interface)
        existing = self._entries.get(key)
        if existing is not None:
            existing.last_seen = now
            existing.expires_at = now + self._max_age
            existing.evidence = evidence
            self._entries.move_to_end(key)
            if now - existing.last_emitted < self._dedupe_window:
                return ()
            existing.last_emitted = now
            return (self._observation(existing),)

        output: list[PassiveObservation] = []
        if evidence.mac_address is not None:
            prior_macs = sorted(
                {
                    item.evidence.mac_address
                    for item in self._entries.values()
                    if item.evidence.address == evidence.address
                    and item.evidence.interface == evidence.interface
                    and item.evidence.mac_address is not None
                    and item.evidence.mac_address != evidence.mac_address
                }
            )
            if prior_macs:
                output.append(
                    self._conflict(
                        "neighbor_ip_reuse",
                        evidence,
                        {
                            "previous_macs": cast(list[JsonValue], prior_macs),
                            "current_mac": evidence.mac_address,
                        },
                    )
                )
            prior_addresses = sorted(
                {
                    item.evidence.address
                    for item in self._entries.values()
                    if item.evidence.mac_address == evidence.mac_address
                    and item.evidence.interface == evidence.interface
                    and item.evidence.address != evidence.address
                }
            )
            if prior_addresses:
                output.append(
                    self._conflict(
                        "neighbor_mac_movement",
                        evidence,
                        {
                            "previous_addresses": cast(list[JsonValue], prior_addresses),
                            "current_address": evidence.address,
                        },
                    )
                )
        tracked = _TrackedNeighbor(evidence, now, now, now, now + self._max_age)
        self._entries[key] = tracked
        self._entries.move_to_end(key)
        if len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
        return (self._observation(tracked), *output)

    def expire(self, now: datetime) -> tuple[PassiveObservation, ...]:
        """Remove and disclose entries whose bounded validity interval ended."""
        current = _utc(now)
        expired: list[PassiveObservation] = []
        for key, tracked in tuple(self._entries.items()):
            if tracked.expires_at > current:
                continue
            del self._entries[key]
            expired.append(
                PassiveObservation(
                    "neighbor_expired",
                    {
                        "address": tracked.evidence.address,
                        "mac_address": tracked.evidence.mac_address,
                        "interface": tracked.evidence.interface,
                        "last_seen": tracked.last_seen.isoformat(),
                    },
                    tracked.evidence.source,
                    observed_at=current,
                )
            )
        return tuple(expired)

    @staticmethod
    def _observation(tracked: _TrackedNeighbor) -> PassiveObservation:
        evidence = tracked.evidence
        fields: dict[str, JsonValue] = {
            "address": evidence.address,
            "mac_address": evidence.mac_address,
            "interface": evidence.interface,
            "state": evidence.state,
            "operation": evidence.operation,
            "first_seen": tracked.first_seen.isoformat(),
            "last_seen": tracked.last_seen.isoformat(),
        }
        return PassiveObservation(
            "neighbor_observation",
            fields,
            evidence.source,
            observed_at=evidence.observed_at,
            expires_at=tracked.expires_at,
        )

    @staticmethod
    def _conflict(
        kind: str, evidence: NeighborEvidence, details: dict[str, JsonValue]
    ) -> PassiveObservation:
        return PassiveObservation(
            kind,
            {
                "address": evidence.address,
                "mac_address": evidence.mac_address,
                "interface": evidence.interface,
                **details,
            },
            evidence.source,
            observed_at=evidence.observed_at,
        )


class ArpParser:
    """Passive pipeline parser backed by a caller-owned bounded tracker."""

    def __init__(self, tracker: NeighborTracker | None = None) -> None:
        self.tracker = tracker or NeighborTracker()

    def __call__(self, frame: PassiveFrame) -> tuple[PassiveObservation, ...]:
        return self.tracker.observe(parse_arp_evidence(frame))
