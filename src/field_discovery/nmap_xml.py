"""Hardened, streaming parser for nmap XML artifacts.

The public parser returns only after the complete document has been validated.  It
does not yield hosts while parsing, so callers can keep database imports atomic.
DTD and entity declarations are rejected before they reach ElementTree; the
stdlib parser does not perform network resolution.
"""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, cast


class NmapXmlError(ValueError):
    """An nmap XML artifact is unsafe, malformed, or outside parser limits."""


@dataclass(frozen=True)
class ParserLimits:
    """Resource limits applied before a scan can become an import candidate."""

    max_bytes: int = 256 * 1024 * 1024
    max_depth: int = 64
    max_hosts: int = 100_000
    max_ports_per_host: int = 65_536
    max_scripts_per_host: int = 4_096
    max_text: int = 1_048_576
    chunk_size: int = 64 * 1024

    def __post_init__(self) -> None:
        if (
            min(
                self.max_bytes,
                self.max_depth,
                self.max_hosts,
                self.max_ports_per_host,
                self.max_scripts_per_host,
                self.max_text,
                self.chunk_size,
            )
            <= 0
        ):
            raise ValueError("all nmap parser limits must be positive")


@dataclass(frozen=True)
class NmapAddress:
    address: str
    address_type: str
    vendor: str | None = None


@dataclass(frozen=True)
class NmapHostname:
    name: str
    hostname_type: str | None = None


@dataclass(frozen=True)
class NmapScript:
    script_id: str
    output: str
    phase: str


@dataclass(frozen=True)
class NmapService:
    name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    method: str | None
    confidence: int | None
    tunnel: str | None
    cpes: tuple[str, ...]


@dataclass(frozen=True)
class NmapPort:
    protocol: str
    port: int
    state: str | None
    reason: str | None
    reason_ttl: int | None
    service: NmapService | None
    scripts: tuple[NmapScript, ...]


@dataclass(frozen=True)
class NmapOsClass:
    device_type: str | None
    vendor: str | None
    os_family: str | None
    os_generation: str | None
    accuracy: int | None
    cpes: tuple[str, ...]


@dataclass(frozen=True)
class NmapOsMatch:
    name: str
    accuracy: int | None
    line: int | None
    classes: tuple[NmapOsClass, ...]


@dataclass(frozen=True)
class NmapHost:
    started_at: datetime | None
    ended_at: datetime | None
    state: str | None
    state_reason: str | None
    addresses: tuple[NmapAddress, ...]
    hostnames: tuple[NmapHostname, ...]
    os_matches: tuple[NmapOsMatch, ...]
    ports: tuple[NmapPort, ...]
    scripts: tuple[NmapScript, ...]


@dataclass(frozen=True)
class NmapScanInfo:
    scan_type: str | None
    protocol: str | None
    num_services: int | None
    services: str | None


@dataclass(frozen=True)
class NmapScan:
    scanner: str | None
    args: str | None
    version: str | None
    xml_output_version: str | None
    started_at: datetime | None
    finished_at: datetime | None
    elapsed_seconds: float | None
    summary: str | None
    exit_status: str | None
    scan_info: tuple[NmapScanInfo, ...]
    scripts: tuple[NmapScript, ...]
    hosts: tuple[NmapHost, ...]


def _bounded(value: str | None, field: str, limits: ParserLimits) -> str | None:
    if value is None:
        return None
    if len(value) > limits.max_text:
        raise NmapXmlError(f"{field} exceeds the configured text limit")
    if "\x00" in value:
        raise NmapXmlError(f"{field} contains a NUL byte")
    return value


def _integer(value: str | None, field: str) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise NmapXmlError(f"{field} must be an integer") from exc


def _floating(value: str | None, field: str) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError as exc:
        raise NmapXmlError(f"{field} must be a number") from exc


def _timestamp(value: str | None, field: str) -> datetime | None:
    epoch = _integer(value, field)
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise NmapXmlError(f"{field} is outside the supported timestamp range") from exc


def _script(element: ET.Element, phase: str, limits: ParserLimits) -> NmapScript:
    script_id = _bounded(element.get("id"), "NSE script id", limits)
    if not script_id:
        raise NmapXmlError("NSE script is missing its id")
    output = _bounded(element.get("output", ""), "NSE script output", limits)
    assert output is not None
    return NmapScript(script_id, output, phase)


def _service(element: ET.Element, limits: ParserLimits) -> NmapService:
    return NmapService(
        _bounded(element.get("name"), "service name", limits),
        _bounded(element.get("product"), "service product", limits),
        _bounded(element.get("version"), "service version", limits),
        _bounded(element.get("extrainfo"), "service extra info", limits),
        _bounded(element.get("method"), "service method", limits),
        _integer(element.get("conf"), "service confidence"),
        _bounded(element.get("tunnel"), "service tunnel", limits),
        tuple(
            value
            for child in element.findall("cpe")
            if (value := _bounded(child.text, "service CPE", limits)) is not None
        ),
    )


def _host(element: ET.Element, limits: ParserLimits) -> NmapHost:
    status = element.find("status")
    addresses = tuple(
        NmapAddress(
            _bounded(item.get("addr"), "host address", limits) or "",
            _bounded(item.get("addrtype"), "host address type", limits) or "",
            _bounded(item.get("vendor"), "host address vendor", limits),
        )
        for item in element.findall("address")
    )
    if any(not item.address or not item.address_type for item in addresses):
        raise NmapXmlError("host address is missing addr or addrtype")
    hostnames = tuple(
        NmapHostname(
            _bounded(item.get("name"), "hostname", limits) or "",
            _bounded(item.get("type"), "hostname type", limits),
        )
        for item in element.findall("hostnames/hostname")
    )
    if any(not item.name for item in hostnames):
        raise NmapXmlError("hostname entry is missing its name")

    os_matches: list[NmapOsMatch] = []
    for match in element.findall("os/osmatch"):
        name = _bounded(match.get("name"), "OS match name", limits)
        if not name:
            raise NmapXmlError("OS match is missing its name")
        classes = tuple(
            NmapOsClass(
                _bounded(item.get("type"), "OS class type", limits),
                _bounded(item.get("vendor"), "OS class vendor", limits),
                _bounded(item.get("osfamily"), "OS family", limits),
                _bounded(item.get("osgen"), "OS generation", limits),
                _integer(item.get("accuracy"), "OS class accuracy"),
                tuple(
                    value
                    for child in item.findall("cpe")
                    if (value := _bounded(child.text, "OS CPE", limits)) is not None
                ),
            )
            for item in match.findall("osclass")
        )
        os_matches.append(
            NmapOsMatch(
                name,
                _integer(match.get("accuracy"), "OS match accuracy"),
                _integer(match.get("line"), "OS match line"),
                classes,
            )
        )

    ports: list[NmapPort] = []
    script_count = 0
    for item in element.findall("ports/port"):
        if len(ports) >= limits.max_ports_per_host:
            raise NmapXmlError("host exceeds the configured port limit")
        protocol = _bounded(item.get("protocol"), "port protocol", limits)
        port_number = _integer(item.get("portid"), "port number")
        if not protocol or port_number is None or not 0 <= port_number <= 65535:
            raise NmapXmlError("port requires a valid protocol and port number")
        state = item.find("state")
        service_element = item.find("service")
        scripts = tuple(_script(script, "port", limits) for script in item.findall("script"))
        script_count += len(scripts)
        ports.append(
            NmapPort(
                protocol,
                port_number,
                _bounded(state.get("state"), "port state", limits) if state is not None else None,
                _bounded(state.get("reason"), "port state reason", limits)
                if state is not None
                else None,
                _integer(state.get("reason_ttl"), "port reason TTL") if state is not None else None,
                _service(service_element, limits) if service_element is not None else None,
                scripts,
            )
        )
    host_scripts = tuple(
        _script(script, "host", limits) for script in element.findall("hostscript/script")
    )
    script_count += len(host_scripts)
    if script_count > limits.max_scripts_per_host:
        raise NmapXmlError("host exceeds the configured NSE script limit")
    return NmapHost(
        _timestamp(element.get("starttime"), "host start time"),
        _timestamp(element.get("endtime"), "host end time"),
        _bounded(status.get("state"), "host state", limits) if status is not None else None,
        _bounded(status.get("reason"), "host state reason", limits) if status is not None else None,
        addresses,
        hostnames,
        tuple(os_matches),
        tuple(ports),
        host_scripts,
    )


def _parse_stream(stream: BinaryIO, limits: ParserLimits) -> NmapScan:
    parser = ET.XMLPullParser(events=("start", "end"))
    total = 0
    depth = 0
    root_attributes: dict[str, str] | None = None
    hosts: list[NmapHost] = []
    scan_info: list[NmapScanInfo] = []
    scan_scripts: list[NmapScript] = []
    finished: ET.Element | None = None
    declaration_tail = b""

    try:
        while chunk := stream.read(limits.chunk_size):
            if not isinstance(chunk, bytes):
                raise NmapXmlError("nmap XML input must be opened in binary mode")
            total += len(chunk)
            if total > limits.max_bytes:
                raise NmapXmlError("nmap XML exceeds the configured byte limit")
            declaration_window = (declaration_tail + chunk).upper()
            if total == len(chunk) and (
                chunk.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in chunk
            ):
                raise NmapXmlError("nmap XML must use an ASCII-compatible encoding")
            if b"<!DOCTYPE" in declaration_window or b"<!ENTITY" in declaration_window:
                raise NmapXmlError("DTD and entity declarations are prohibited")
            declaration_tail = declaration_window[-16:]
            parser.feed(chunk)
            for event, element in parser.read_events():
                if event == "start":
                    depth += 1
                    if depth > limits.max_depth:
                        raise NmapXmlError("nmap XML exceeds the configured nesting limit")
                    if root_attributes is None:
                        if element.tag != "nmaprun":
                            raise NmapXmlError("document root must be nmaprun")
                        root_attributes = dict(element.attrib)
                    continue

                if element.tag == "scaninfo":
                    scan_info.append(
                        NmapScanInfo(
                            _bounded(element.get("type"), "scan type", limits),
                            _bounded(element.get("protocol"), "scan protocol", limits),
                            _integer(element.get("numservices"), "scan service count"),
                            _bounded(element.get("services"), "scan services", limits),
                        )
                    )
                elif element.tag == "host":
                    if len(hosts) >= limits.max_hosts:
                        raise NmapXmlError("scan exceeds the configured host limit")
                    hosts.append(_host(element, limits))
                    element.clear()
                elif element.tag == "finished":
                    finished = element
                elif element.tag in {"prescript", "postscript"}:
                    phase = "pre" if element.tag == "prescript" else "post"
                    scan_scripts.extend(
                        _script(script, phase, limits) for script in element.findall("script")
                    )
                    element.clear()
                depth -= 1
        if total == 0:
            raise NmapXmlError("nmap XML document is empty")
        parser.close()
    except ET.ParseError as exc:
        raise NmapXmlError(f"malformed nmap XML: {exc}") from exc

    assert root_attributes is not None
    return NmapScan(
        _bounded(root_attributes.get("scanner"), "scanner", limits),
        _bounded(root_attributes.get("args"), "scan arguments", limits),
        _bounded(root_attributes.get("version"), "nmap version", limits),
        _bounded(root_attributes.get("xmloutputversion"), "XML output version", limits),
        _timestamp(root_attributes.get("start"), "scan start time"),
        _timestamp(finished.get("time"), "scan finish time") if finished is not None else None,
        _floating(finished.get("elapsed"), "scan elapsed time") if finished is not None else None,
        _bounded(finished.get("summary"), "scan summary", limits) if finished is not None else None,
        _bounded(finished.get("exit"), "scan exit status", limits)
        if finished is not None
        else None,
        tuple(scan_info),
        tuple(scan_scripts),
        tuple(hosts),
    )


def parse_nmap_xml(
    source: str | os.PathLike[str] | BinaryIO, *, limits: ParserLimits | None = None
) -> NmapScan:
    """Parse one complete nmap XML file or binary stream without network access."""
    effective_limits = limits or ParserLimits()
    if hasattr(source, "read"):
        return _parse_stream(cast(BinaryIO, source), effective_limits)
    with Path(source).open("rb") as stream:
        return _parse_stream(stream, effective_limits)
