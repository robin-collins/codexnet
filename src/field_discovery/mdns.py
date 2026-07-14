"""Bounded, read-only mDNS and DNS-SD response observation.

This module parses DNS message bytes already supplied by a capture adapter.  It
does not open sockets, join multicast groups, transmit queries, or retain packet
payloads.  The stateful parser only retains bounded structured cache entries so
that TTL expiry and goodbye records can be represented explicitly.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Final, cast

from field_discovery.passive import JsonValue, PassiveFrame, PassiveObservation, PassiveParseError
from field_discovery.redaction import Redactor

_DNS_HEADER: Final = struct.Struct("!HHHHHH")
_RR_HEADER: Final = struct.Struct("!HHIH")
_MAX_POINTER_JUMPS: Final = 16


@dataclass(frozen=True)
class _Record:
    name: str
    record_type: int
    ttl: int
    value: object


@dataclass(frozen=True)
class _CacheEntry:
    observation: PassiveObservation
    expires_at: datetime


class MDNSParser:
    """Parse bounded mDNS responses and maintain a bounded structured TTL cache."""

    def __init__(
        self,
        *,
        max_message_bytes: int = 9_000,
        max_questions: int = 128,
        max_records: int = 512,
        max_txt_bytes: int = 1_300,
        max_cache_entries: int = 4_096,
        max_ttl_seconds: int = 604_800,
        redactor: Redactor | None = None,
    ) -> None:
        bounds = (
            max_message_bytes,
            max_questions,
            max_records,
            max_txt_bytes,
            max_cache_entries,
            max_ttl_seconds,
        )
        if any(value < 1 for value in bounds):
            raise ValueError("mDNS parser bounds must be positive")
        self._max_message_bytes = max_message_bytes
        self._max_questions = max_questions
        self._max_records = max_records
        self._max_txt_bytes = max_txt_bytes
        self._max_cache_entries = max_cache_entries
        self._max_ttl_seconds = max_ttl_seconds
        self._redactor = redactor or Redactor()
        self._cache: OrderedDict[tuple[str, str], _CacheEntry] = OrderedDict()

    @property
    def cache_size(self) -> int:
        """Number of structured records retained for lifecycle tracking."""
        return len(self._cache)

    def __call__(self, frame: PassiveFrame) -> Iterable[PassiveObservation]:
        if frame.protocol.casefold() not in {"mdns", "dns-sd"}:
            raise PassiveParseError("mDNS parser received an unexpected protocol")
        observed_at = frame.observed_at.astimezone(UTC)
        expired = list(self.expire(observed_at))
        records = self._parse_message(frame.payload)
        output = expired
        for record in records:
            observation = self._observation(record, observed_at)
            identity = self._identity(observation)
            if record.ttl == 0:
                self._cache.pop(identity, None)
                output.append(observation)
                continue
            assert observation.expires_at is not None
            self._cache[identity] = _CacheEntry(observation, observation.expires_at)
            self._cache.move_to_end(identity)
            while len(self._cache) > self._max_cache_entries:
                self._cache.popitem(last=False)
            output.append(observation)
        return output

    def expire(self, now: datetime) -> tuple[PassiveObservation, ...]:
        """Remove due cache entries and return explicit expiry observations."""
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("mDNS cache expiry time must be timezone-aware")
        timestamp = now.astimezone(UTC)
        expired: list[PassiveObservation] = []
        for identity, entry in tuple(self._cache.items()):
            if entry.expires_at > timestamp:
                continue
            self._cache.pop(identity)
            fields = dict(entry.observation.fields)
            fields["action"] = "expired"
            expired.append(
                replace(
                    entry.observation, fields=fields, observed_at=timestamp, expires_at=timestamp
                )
            )
        return tuple(expired)

    def _parse_message(self, payload: bytes) -> tuple[_Record, ...]:
        if len(payload) > self._max_message_bytes:
            raise PassiveParseError("mDNS message exceeds configured size limit")
        if len(payload) < _DNS_HEADER.size:
            raise PassiveParseError("truncated mDNS header")
        _identifier, flags, questions, answers, authorities, additionals = _DNS_HEADER.unpack_from(
            payload
        )
        if not flags & 0x8000:
            return ()
        record_count = answers + authorities + additionals
        if questions > self._max_questions or record_count > self._max_records:
            raise PassiveParseError("mDNS section count exceeds configured limit")
        offset = _DNS_HEADER.size
        for _ in range(questions):
            _name, offset = _read_name(payload, offset)
            if offset + 4 > len(payload):
                raise PassiveParseError("truncated mDNS question")
            offset += 4
        records: list[_Record] = []
        for _ in range(record_count):
            name, offset = _read_name(payload, offset)
            if offset + _RR_HEADER.size > len(payload):
                raise PassiveParseError("truncated mDNS resource-record header")
            record_type, record_class, ttl, length = _RR_HEADER.unpack_from(payload, offset)
            offset += _RR_HEADER.size
            end = offset + length
            if end > len(payload):
                raise PassiveParseError("truncated mDNS resource-record data")
            # Ignore non-IN records while still validating their bounded extent.
            if record_class & 0x7FFF == 1:
                value = self._parse_rdata(payload, offset, end, record_type)
                if value is not None:
                    records.append(_Record(name, record_type, ttl, value))
            offset = end
        if offset != len(payload):
            raise PassiveParseError("mDNS message has trailing data")
        return tuple(records)

    def _parse_rdata(self, payload: bytes, start: int, end: int, record_type: int) -> object | None:
        if record_type == 1:  # A
            if end - start != 4:
                raise PassiveParseError("invalid mDNS IPv4 address length")
            return str(ipaddress.IPv4Address(payload[start:end]))
        if record_type == 12:  # PTR
            name, consumed = _read_name(payload, start)
            if consumed != end:
                raise PassiveParseError("invalid DNS-SD PTR data")
            return name
        if record_type == 33:  # SRV
            if end - start < 7:
                raise PassiveParseError("truncated DNS-SD SRV data")
            priority, weight, port = struct.unpack_from("!HHH", payload, start)
            target, consumed = _read_name(payload, start + 6)
            if consumed != end:
                raise PassiveParseError("invalid DNS-SD SRV data")
            return priority, weight, port, target
        if record_type == 16:  # TXT
            if end - start > self._max_txt_bytes:
                raise PassiveParseError("DNS-SD TXT data exceeds configured limit")
            return self._parse_txt(payload[start:end])
        return None

    def _parse_txt(self, data: bytes) -> Mapping[str, str | list[str]]:
        values: dict[str, str | list[str]] = {}
        offset = 0
        while offset < len(data):
            length = data[offset]
            offset += 1
            if offset + length > len(data):
                raise PassiveParseError("truncated DNS-SD TXT item")
            try:
                item = data[offset : offset + length].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PassiveParseError("invalid UTF-8 in DNS-SD TXT item") from exc
            offset += length
            key, separator, value = item.partition("=")
            if not key or len(key) > 255 or any(ord(char) < 0x20 for char in key):
                raise PassiveParseError("invalid DNS-SD TXT key")
            redacted = self._redactor.value({key: value if separator else ""})[key]
            existing = values.get(key)
            if existing is None:
                values[key] = redacted
            elif isinstance(existing, list):
                existing.append(redacted)
            else:
                values[key] = [existing, redacted]
        return values

    def _observation(self, record: _Record, observed_at: datetime) -> PassiveObservation:
        ttl = min(record.ttl, self._max_ttl_seconds)
        action = "goodbye" if record.ttl == 0 else "announce"
        expires_at = observed_at if record.ttl == 0 else observed_at + timedelta(seconds=ttl)
        fields: dict[str, JsonValue]
        kind: str
        if record.record_type == 12:
            kind = "mdns_service"
            fields = {
                "service_type": record.name,
                "instance": cast(str, record.value),
                "action": action,
            }
        elif record.record_type == 33:
            priority, weight, port, hostname = cast(tuple[int, int, int, str], record.value)
            kind = "mdns_instance"
            fields = {
                "instance": record.name,
                "hostname": hostname,
                "port": port,
                "priority": priority,
                "weight": weight,
                "action": action,
            }
        elif record.record_type == 1:
            kind = "mdns_address"
            fields = {
                "hostname": record.name,
                "address": cast(str, record.value),
                "action": action,
            }
        elif record.record_type == 16:
            kind = "mdns_txt"
            fields = {
                "instance": record.name,
                "txt": cast(dict[str, JsonValue], record.value),
                "action": action,
            }
        else:
            raise AssertionError(
                "unsupported record reached observation boundary"
            )  # pragma: no cover
        return PassiveObservation(
            kind=kind,
            fields=fields,
            source="mdns",
            observed_at=observed_at,
            expires_at=expires_at,
        )

    @staticmethod
    def _identity(observation: PassiveObservation) -> tuple[str, str]:
        fields = {key: value for key, value in observation.fields.items() if key != "action"}
        return observation.kind, repr(sorted(fields.items()))


def _read_name(message: bytes, offset: int) -> tuple[str, int]:
    """Read a bounded DNS name, detecting pointer loops and invalid labels."""
    if offset >= len(message):
        raise PassiveParseError("truncated mDNS name")
    labels: list[str] = []
    cursor = offset
    consumed: int | None = None
    visited: set[int] = set()
    wire_length = 1
    jumps = 0
    while True:
        if cursor >= len(message):
            raise PassiveParseError("truncated mDNS name")
        length = message[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                raise PassiveParseError("truncated mDNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message) or pointer in visited or jumps >= _MAX_POINTER_JUMPS:
                raise PassiveParseError("invalid or looping mDNS compression pointer")
            visited.add(pointer)
            jumps += 1
            if consumed is None:
                consumed = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise PassiveParseError("invalid mDNS label encoding")
        cursor += 1
        if length == 0:
            if consumed is None:
                consumed = cursor
            break
        if cursor + length > len(message):
            raise PassiveParseError("invalid or truncated mDNS label")
        wire_length += length + 1
        if wire_length > 255:
            raise PassiveParseError("mDNS name exceeds DNS wire limit")
        try:
            label = message[cursor : cursor + length].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PassiveParseError("invalid UTF-8 in mDNS name") from exc
        if any(ord(char) < 0x20 for char in label):
            raise PassiveParseError("invalid mDNS label")
        labels.append(label)
        cursor += length
    return ".".join(labels).casefold(), consumed
