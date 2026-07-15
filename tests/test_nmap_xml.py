"""Nmap XML parsing tests use only sanitized synthetic artifacts."""

from __future__ import annotations

import io
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast

import pytest

from field_discovery.nmap_xml import NmapXmlError, ParserLimits, _bounded, parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


def test_success_fixture_extracts_complete_tcp_udp_inventory() -> None:
    scan = parse_nmap_xml(FIXTURES / "success.xml")

    assert scan.scanner == "nmap"
    assert scan.version == "7.95"
    assert scan.xml_output_version == "1.05"
    assert scan.args and "192.0.2.0/24" in scan.args
    assert scan.started_at == datetime(2026, 7, 15, 9, 0, tzinfo=UTC)
    assert scan.finished_at == datetime(2026, 7, 15, 9, 0, 4, tzinfo=UTC)
    assert scan.elapsed_seconds == 4.25
    assert scan.summary == "Synthetic scan complete"
    assert scan.exit_status == "success"
    assert [
        (item.scan_type, item.protocol, item.num_services, item.services) for item in scan.scan_info
    ] == [
        ("syn", "tcp", 2, "22,443"),
        ("udp", "udp", 1, "161"),
    ]
    assert [(script.phase, script.script_id) for script in scan.scripts] == [
        ("pre", "broadcast-fixture"),
        ("post", "post-fixture"),
    ]

    host = scan.hosts[0]
    assert host.started_at and host.ended_at
    assert (host.state, host.state_reason) == ("up", "arp-response")
    assert [(item.address, item.address_type, item.vendor) for item in host.addresses] == [
        ("192.0.2.10", "ipv4", None),
        ("02:00:00:00:00:10", "mac", "Example Networks"),
    ]
    assert [(item.name, item.hostname_type) for item in host.hostnames] == [
        ("switch-01.example.test", "PTR")
    ]
    assert [(port.protocol, port.port, port.state) for port in host.ports] == [
        ("tcp", 22, "open"),
        ("udp", 161, "open"),
    ]
    ssh = host.ports[0]
    assert (ssh.reason, ssh.reason_ttl) == ("syn-ack", 64)
    assert ssh.service is not None
    assert (
        ssh.service.name,
        ssh.service.product,
        ssh.service.version,
        ssh.service.extra_info,
        ssh.service.method,
        ssh.service.confidence,
        ssh.service.tunnel,
        ssh.service.cpes,
    ) == (
        "ssh",
        "SyntheticSSH",
        "1.2",
        "fixture",
        "probed",
        10,
        None,
        ("cpe:/a:example:ssh:1.2",),
    )
    assert [(item.phase, item.script_id, item.output) for item in ssh.scripts] == [
        ("port", "ssh-hostkey", "synthetic fingerprint")
    ]
    assert host.ports[1].reason_ttl is None
    assert host.scripts[0].phase == "host"
    match = host.os_matches[0]
    assert (match.name, match.accuracy, match.line) == ("Synthetic Network OS", 98, 123)
    os_class = match.classes[0]
    assert (
        os_class.device_type,
        os_class.vendor,
        os_class.os_family,
        os_class.os_generation,
        os_class.accuracy,
        os_class.cpes,
    ) == (
        "switch",
        "Example Networks",
        "SyntheticOS",
        "1",
        98,
        ("cpe:/o:example:syntheticos:1",),
    )


@pytest.mark.parametrize(
    ("fixture", "expected_state", "expected_exit"),
    [
        ("partial.xml", "up", None),
        ("ipv4-only.xml", "down", None),
        ("missing-fields.xml", None, "error"),
    ],
)
def test_partial_ipv4_only_and_missing_field_fixtures(
    fixture: str, expected_state: str | None, expected_exit: str | None
) -> None:
    scan = parse_nmap_xml(FIXTURES / fixture)
    assert scan.hosts[0].state == expected_state
    assert scan.exit_status == expected_exit
    if fixture == "missing-fields.xml":
        port = scan.hosts[0].ports[0]
        assert (port.state, port.reason, port.service) == (None, None, None)
    else:
        assert scan.hosts[0].addresses[0].address_type == "ipv4"


def test_large_stream_is_consumed_incrementally() -> None:
    hosts = b"".join(
        f'<host><address addr="192.0.2.{index % 254 + 1}" addrtype="ipv4"/></host>'.encode()
        for index in range(2_000)
    )
    stream = io.BytesIO(b'<nmaprun scanner="nmap">' + hosts + b"</nmaprun>")
    scan = parse_nmap_xml(stream, limits=ParserLimits(chunk_size=127))
    assert len(scan.hosts) == 2_000
    assert stream.tell() > 127


def test_malformed_input_exposes_no_partial_result() -> None:
    result = None
    with pytest.raises(NmapXmlError, match="malformed"):
        result = parse_nmap_xml(FIXTURES / "malformed.xml")
    assert result is None


@pytest.mark.parametrize(
    "payload",
    [
        b'<!DOCTYPE nmaprun SYSTEM "https://example.invalid/evil.dtd"><nmaprun/>',
        b'<!DOCTYPE nmaprun [<!ENTITY fixture "expanded">]><nmaprun>&fixture;</nmaprun>',
    ],
)
def test_dtd_and_entities_are_rejected_without_resolution(payload: bytes) -> None:
    with pytest.raises(NmapXmlError, match="prohibited"):
        parse_nmap_xml(io.BytesIO(payload), limits=ParserLimits(chunk_size=5))


def test_canonical_nmap_doctype_is_accepted_across_chunks() -> None:
    payload = (
        b'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap">'
        b'<runstats><finished time="1700000000" exit="success"/></runstats></nmaprun>'
    )

    scan = parse_nmap_xml(io.BytesIO(payload), limits=ParserLimits(chunk_size=5))

    assert scan.scanner == "nmap"


def test_incomplete_doctype_is_rejected() -> None:
    with pytest.raises(NmapXmlError, match="incomplete DTD"):
        parse_nmap_xml(io.BytesIO(b"<!DOCTYPE"), limits=ParserLimits(chunk_size=3))


@pytest.mark.parametrize(
    "payload",
    [
        b"<!DOCTYPE other><nmaprun/>",
        b'<!ENTITY fixture "expanded"><nmaprun/>',
    ],
)
def test_noncanonical_declarations_are_rejected_in_one_chunk(payload: bytes) -> None:
    with pytest.raises(NmapXmlError, match="prohibited"):
        parse_nmap_xml(io.BytesIO(payload))


@pytest.mark.parametrize(
    ("payload", "limits", "message"),
    [
        (b"", ParserLimits(), "empty"),
        (b"<other/>", ParserLimits(), "root"),
        (b"<nmaprun><a><b/></a></nmaprun>", ParserLimits(max_depth=2), "nesting"),
        (b"<nmaprun/>padding", ParserLimits(max_bytes=8), "byte limit"),
        (b"<nmaprun><host/><host/></nmaprun>", ParserLimits(max_hosts=1), "host limit"),
        (
            b'<nmaprun><host><ports><port protocol="tcp" portid="1"/>'
            b'<port protocol="tcp" portid="2"/></ports></host></nmaprun>',
            ParserLimits(max_ports_per_host=1),
            "port limit",
        ),
        (
            b'<nmaprun><host><hostscript><script id="a"/>'
            b'<script id="b"/></hostscript></host></nmaprun>',
            ParserLimits(max_scripts_per_host=1),
            "script limit",
        ),
        (
            b'<nmaprun scanner="toolong"/>',
            ParserLimits(max_text=3),
            "text limit",
        ),
        (b'<nmaprun scanner="bad\x00value"/>', ParserLimits(), "encoding"),
    ],
)
def test_resource_and_document_limits(payload: bytes, limits: ParserLimits, message: str) -> None:
    with pytest.raises(NmapXmlError, match=message):
        parse_nmap_xml(io.BytesIO(payload), limits=limits)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b'<nmaprun start="nope"/>', "integer"),
        (b'<nmaprun start="999999999999999999999999999"/>', "timestamp range"),
        (b'<nmaprun><runstats><finished elapsed="nope"/></runstats></nmaprun>', "number"),
        (b'<nmaprun><host><address addr="192.0.2.1"/></host></nmaprun>', "address"),
        (b"<nmaprun><host><hostnames><hostname/></hostnames></host></nmaprun>", "hostname"),
        (b"<nmaprun><host><os><osmatch/></os></host></nmaprun>", "OS match"),
        (b'<nmaprun><host><ports><port portid="22"/></ports></host></nmaprun>', "protocol"),
        (
            b'<nmaprun><host><ports><port protocol="tcp" portid="70000"/></ports></host></nmaprun>',
            "valid protocol",
        ),
        (
            b'<nmaprun><host><ports><port protocol="tcp" portid="x"/></ports></host></nmaprun>',
            "integer",
        ),
        (b"<nmaprun><host><hostscript><script/></hostscript></host></nmaprun>", "script"),
    ],
)
def test_invalid_nmap_fields_fail_closed(payload: bytes, message: str) -> None:
    with pytest.raises(NmapXmlError, match=message):
        parse_nmap_xml(io.BytesIO(payload))


def test_binary_input_and_positive_limits_are_required() -> None:
    with pytest.raises(NmapXmlError, match="binary"):
        parse_nmap_xml(cast(BinaryIO, io.StringIO("<nmaprun/>")))
    with pytest.raises(ValueError, match="positive"):
        ParserLimits(max_bytes=0)
    with pytest.raises(NmapXmlError, match="NUL"):
        _bounded("unsafe\x00text", "fixture field", ParserLimits())
