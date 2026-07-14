"""Synthetic binary replay tests for bounded mDNS/DNS-SD observation."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import struct
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from field_discovery.mdns import MDNSParser, _read_name
from field_discovery.passive import (
    PassiveEventPipeline,
    PassiveFrame,
    PassiveObservation,
    PassiveParseError,
)
from field_discovery.redaction import REDACTED

NOW = datetime(2026, 2, 3, 4, 5, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures" / "mdns" / "announcement.json"


def _name(value: str) -> bytes:
    return (
        b"".join(bytes((len(label.encode()),)) + label.encode() for label in value.split("."))
        + b"\0"
    )


def _rr(name: str, record_type: int, ttl: int, data: bytes) -> bytes:
    return _name(name) + struct.pack("!HHIH", record_type, 0x8001, ttl, len(data)) + data


def _message(*records: bytes, flags: int = 0x8400, questions: int = 0) -> bytes:
    return struct.pack("!HHHHHH", 0, flags, questions, len(records), 0, 0) + b"".join(records)


def _fixture_message(*, ttl: int = 120) -> bytes:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    txt = b"".join(bytes((len(item.encode()),)) + item.encode() for item in fixture["txt"])
    return _message(
        _rr(fixture["service_type"], 12, ttl, _name(fixture["instance"])),
        _rr(
            fixture["instance"],
            33,
            ttl,
            struct.pack("!HHH", 0, 0, fixture["port"]) + _name(fixture["hostname"]),
        ),
        _rr(fixture["hostname"], 1, ttl, ipaddress.IPv4Address(fixture["address"]).packed),
        _rr(fixture["instance"], 16, ttl, txt),
    )


def _frame(payload: bytes, when: datetime = NOW, protocol: str = "mdns") -> PassiveFrame:
    return PassiveFrame(protocol, payload, when, "fixture0")


def test_fixture_normalizes_service_instance_hostname_ipv4_and_redacted_txt() -> None:
    parser = MDNSParser()
    observations = tuple(parser(_frame(_fixture_message())))
    assert [item.kind for item in observations] == [
        "mdns_service",
        "mdns_instance",
        "mdns_address",
        "mdns_txt",
    ]
    assert observations[0].fields == {
        "service_type": "_http._tcp.local",
        "instance": "synthetic-printer._http._tcp.local",
        "action": "announce",
    }
    assert observations[1].fields["hostname"] == "synthetic-printer.local"
    assert observations[1].fields["port"] == 631
    assert observations[2].fields["address"] == "192.0.2.44"
    assert observations[3].fields["txt"] == {
        "note": "synthetic fixture",
        "password": REDACTED,
        "token": REDACTED,
    }
    assert all(item.expires_at == NOW + timedelta(seconds=120) for item in observations)
    assert parser.cache_size == 4
    serialized = json.dumps([dict(item.fields) for item in observations])
    assert "fixture-only-secret" not in serialized
    assert "fixture-only-token" not in serialized


def test_pipeline_deduplicates_repeat_announcements_without_retaining_payload() -> None:
    async def scenario() -> None:
        output: list[PassiveObservation] = []

        async def sink(item: PassiveObservation) -> None:
            output.append(item)

        parser = MDNSParser()
        pipeline = PassiveEventPipeline(
            parsers={"mdns": (parser,)}, sink=sink, dedupe_window_seconds=30
        )
        await pipeline.start()
        payload = _fixture_message()
        assert await pipeline.submit("mdns", payload, observed_at=NOW)
        assert await pipeline.submit("mdns", payload, observed_at=NOW + timedelta(seconds=1))
        metrics = await pipeline.stop()
        assert len(output) == 4
        assert metrics.emitted_observations == 4
        assert metrics.duplicate_observations == 4
        assert not any(hasattr(item, "payload") for item in output)

    asyncio.run(scenario())


def test_goodbye_removes_matching_cache_entry_and_is_not_deduplicated() -> None:
    parser = MDNSParser()
    initial = tuple(parser(_frame(_fixture_message())))
    goodbye = tuple(parser(_frame(_fixture_message(ttl=0), NOW + timedelta(seconds=5))))
    assert len(initial) == len(goodbye) == 4
    assert all(item.fields["action"] == "goodbye" for item in goodbye)
    assert all(item.expires_at == NOW + timedelta(seconds=5) for item in goodbye)
    assert parser.cache_size == 0


def test_cache_expiry_emits_lifecycle_events_and_refresh_extends_ttl() -> None:
    parser = MDNSParser(max_cache_entries=2)
    address = _message(_rr("host.local", 1, 2, ipaddress.IPv4Address("192.0.2.9").packed))
    assert len(tuple(parser(_frame(address)))) == 1
    assert not parser.expire(NOW + timedelta(seconds=1))
    # A duplicate refresh updates structured expiry even when a pipeline would dedupe persistence.
    assert len(tuple(parser(_frame(address, NOW + timedelta(seconds=1))))) == 1
    assert not parser.expire(NOW + timedelta(seconds=2))
    expired = parser.expire(NOW + timedelta(seconds=3))
    assert len(expired) == 1
    assert expired[0].fields["action"] == "expired"
    assert expired[0].observed_at == expired[0].expires_at == NOW + timedelta(seconds=3)
    assert parser.cache_size == 0


def test_due_cache_entries_are_expired_before_new_message_observations() -> None:
    parser = MDNSParser()
    address = _message(_rr("old.local", 1, 1, b"\xc0\x00\x02\x09"))
    tuple(parser(_frame(address)))
    output = tuple(
        parser(
            _frame(
                _message(_rr("new.local", 1, 10, b"\xc0\x00\x02\x0a")),
                NOW + timedelta(seconds=2),
            )
        )
    )
    assert [item.fields["action"] for item in output] == ["expired", "announce"]


def test_cache_and_ttl_are_bounded() -> None:
    parser = MDNSParser(max_cache_entries=2, max_ttl_seconds=10)
    records = tuple(
        parser(
            _frame(
                _message(
                    _rr("one.local", 1, 4_000_000_000, b"\xc0\x00\x02\x01"),
                    _rr("two.local", 1, 20, b"\xc0\x00\x02\x02"),
                    _rr("three.local", 1, 20, b"\xc0\x00\x02\x03"),
                )
            )
        )
    )
    assert len(records) == 3
    assert records[0].expires_at == NOW + timedelta(seconds=10)
    assert parser.cache_size == 2


@pytest.mark.parametrize(
    "payload, message",
    [
        (b"short", "header"),
        (_message(_rr("bad.local", 1, 10, b"abc")), "address length"),
        (
            struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 10, 4)
            + b"\xc0\x00\x02\x01",
            "looping",
        ),
        (
            struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\x40" + (b"a" * 64) + b"\0",
            "label encoding",
        ),
        (_message(_rr("x.local", 16, 10, b"\x05abc")), "TXT item"),
    ],
)
def test_malformed_and_compression_loop_messages_fail_closed(payload: bytes, message: str) -> None:
    with pytest.raises(PassiveParseError, match=message):
        tuple(MDNSParser()(_frame(payload)))


def test_oversized_message_txt_and_section_counts_are_rejected() -> None:
    with pytest.raises(PassiveParseError, match="message exceeds"):
        tuple(MDNSParser(max_message_bytes=12)(_frame(b"x" * 13)))
    txt = bytes((8,)) + b"key=data"
    with pytest.raises(PassiveParseError, match="TXT data exceeds"):
        tuple(MDNSParser(max_txt_bytes=4)(_frame(_message(_rr("x.local", 16, 10, txt)))))
    header = struct.pack("!HHHHHH", 0, 0x8400, 129, 0, 0, 0)
    with pytest.raises(PassiveParseError, match="section count"):
        tuple(MDNSParser()(_frame(header)))
    record_header = struct.pack("!HHHHHH", 0, 0x8400, 0, 513, 0, 0)
    with pytest.raises(PassiveParseError, match="section count"):
        tuple(MDNSParser()(_frame(record_header)))


def test_questions_compression_and_all_section_counts_parse_safely() -> None:
    question_name = _name("_http._tcp.local")
    question = question_name + struct.pack("!HH", 12, 1)
    # The PTR owner points to the question name; RDATA is an uncompressed instance.
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 10, len(_name("one._http._tcp.local")))
    rr += _name("one._http._tcp.local")
    payload = struct.pack("!HHHHHH", 0, 0x8400, 1, 0, 1, 0) + question + rr
    output = tuple(MDNSParser()(_frame(payload)))
    assert output[0].fields["service_type"] == "_http._tcp.local"
    truncated_question = struct.pack("!HHHHHH", 0, 0x8400, 1, 0, 0, 0) + b"\0\0"
    with pytest.raises(PassiveParseError, match="question"):
        tuple(MDNSParser()(_frame(truncated_question)))


@pytest.mark.parametrize(
    "record, message",
    [
        (b"\0" + b"\0" * 3, "record header"),
        (b"\0" + struct.pack("!HHIH", 1, 1, 10, 4) + b"\xc0", "record data"),
        (
            _rr("service.local", 12, 10, _name("instance.local") + b"x"),
            "PTR data",
        ),
        (_rr("instance.local", 33, 10, b"\0" * 6), "SRV data"),
        (
            _rr("instance.local", 33, 10, b"\0" * 6 + _name("host.local") + b"x"),
            "SRV data",
        ),
    ],
)
def test_resource_record_boundaries_fail_closed(record: bytes, message: str) -> None:
    with pytest.raises(PassiveParseError, match=message):
        tuple(MDNSParser()(_frame(_message(record))))
    with pytest.raises(PassiveParseError, match="trailing data"):
        tuple(MDNSParser()(_frame(struct.pack("!HHHHHH", 0, 0x8400, 0, 0, 0, 0) + b"x")))


@pytest.mark.parametrize(
    "txt, message",
    [
        (bytes((2,)) + b"\xff\xff", "UTF-8"),
        (bytes((2,)) + b"=x", "TXT key"),
        (bytes((3,)) + b"a\x01x", "TXT key"),
    ],
)
def test_invalid_txt_content_fails_closed(txt: bytes, message: str) -> None:
    with pytest.raises(PassiveParseError, match=message):
        tuple(MDNSParser()(_frame(_message(_rr("instance.local", 16, 10, txt)))))


def test_txt_flags_duplicate_keys_and_structural_value_redaction() -> None:
    items = ("flag", "note=token=hidden-value", "note=safe", "note=again")
    txt = b"".join(bytes((len(item),)) + item.encode() for item in items)
    observation = next(iter(MDNSParser()(_frame(_message(_rr("instance.local", 16, 10, txt))))))
    assert observation.fields["txt"] == {
        "flag": "",
        "note": [f"token={REDACTED}", "safe", "again"],
    }


@pytest.mark.parametrize(
    "message, offset, error",
    [
        (b"", 0, "truncated mDNS name"),
        (b"\x01", 0, "truncated mDNS label"),
        (b"\x01a", 0, "truncated mDNS name"),
        (b"\xc0", 0, "compression pointer"),
        (b"\xc0\xff", 0, "looping"),
        (b"\x80\0", 0, "label encoding"),
        (b"\x01\xff\0", 0, "UTF-8"),
        (b"\x01\x01\0", 0, "invalid mDNS label"),
    ],
)
def test_name_reader_adversarial_boundaries(message: bytes, offset: int, error: str) -> None:
    with pytest.raises(PassiveParseError, match=error):
        _read_name(message, offset)


def test_name_reader_rejects_overlong_name_and_pointer_chain() -> None:
    overlong = b"".join(b"\x3f" + (b"a" * 63) for _ in range(4)) + b"\x01a\0"
    with pytest.raises(PassiveParseError, match="wire limit"):
        _read_name(overlong, 0)
    # Seventeen two-byte forward pointers followed by a root label exceeds the jump bound.
    chain = bytearray()
    for index in range(17):
        target = (index + 1) * 2
        chain.extend((0xC0 | (target >> 8), target & 0xFF))
    chain.append(0)
    with pytest.raises(PassiveParseError, match="looping"):
        _read_name(bytes(chain), 0)


def test_queries_unknown_records_classes_and_protocol_contract_are_safe() -> None:
    parser = MDNSParser()
    assert not tuple(parser(_frame(struct.pack("!HHHHHH", 0, 0, 0, 0, 0, 0))))
    unknown = _name("x.local") + struct.pack("!HHIH", 28, 1, 10, 16) + (b"\0" * 16)
    non_in = _name("x.local") + struct.pack("!HHIH", 1, 3, 10, 4) + b"\xc0\x00\x02\x01"
    assert not tuple(parser(_frame(_message(unknown, non_in))))
    with pytest.raises(PassiveParseError, match="unexpected protocol"):
        tuple(parser(_frame(_fixture_message(), protocol="lldp")))


def test_constructor_and_expiry_reject_invalid_contracts() -> None:
    for keyword in (
        "max_message_bytes",
        "max_questions",
        "max_records",
        "max_txt_bytes",
        "max_cache_entries",
        "max_ttl_seconds",
    ):
        with pytest.raises(ValueError, match="bounds"):
            MDNSParser(**{keyword: 0})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="timezone-aware"):
        MDNSParser().expire(datetime(2026, 1, 1))
    local = datetime(2026, 2, 3, 14, 35, tzinfo=timezone(timedelta(hours=10, minutes=30)))
    observations = tuple(MDNSParser()(_frame(_fixture_message(), local, protocol="dns-sd")))
    assert observations[0].observed_at == NOW
