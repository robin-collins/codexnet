"""Deterministic inventory report model, DOCX generation, and validation."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from posixpath import normpath
from typing import Any, cast
from urllib.parse import unquote
from xml.etree import ElementTree as ET

from field_discovery.artifacts import safe_filename
from field_discovery.infrastructure_reporting import build_infrastructure_model
from field_discovery.platform_reporting import build_platform_report_model
from field_discovery.redaction import Redactor
from field_discovery.repository import Repository

_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_CP = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
_DC = "http://purl.org/dc/elements/1.1/"
_DCTERMS = "http://purl.org/dc/terms/"
_XSI = "http://www.w3.org/2001/XMLSchema-instance"
_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_CONTENT = "http://schemas.openxmlformats.org/package/2006/content-types"
_WP = "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
_A = "http://schemas.openxmlformats.org/drawingml/2006/main"
_PIC = "http://schemas.openxmlformats.org/drawingml/2006/picture"
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_MAX_DOCX_ENTRIES = 64
_MAX_DOCX_UNCOMPRESSED = 32 * 1024 * 1024
_MAX_DOCX_ENTRY = 8 * 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_SAFE_DOCUMENT_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_MAX_RELATIONSHIP_TARGET = 2_048
_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_EMBEDDED_URI_SCHEME = re.compile(r"(?:^|[=&])\s*[A-Za-z][A-Za-z0-9+.-]*:")
_REPORT_FILENAME = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,180}-Network-Discovery-(?P<date>[0-9]{8})\.docx$"
)
_REQUIRED_REPORT_SECTIONS = frozenset(
    {
        "Table of contents",
        "Executive summary",
        "Embedded diagrams",
        "Switch port maps",
        "VLAN inventory",
        "Switch neighbors",
        "Printer inventory",
        "UPS inventory",
        "Environment readings",
        "Firmware versions",
        "Infrastructure data quality",
        "UniFi topology and inventory",
        "Active Directory structure and trusts",
        "Collection coverage",
        "Device inventory",
        "Service inventory",
        "Conflicts and data quality",
        "Limitations",
    }
)
_PROHIBITED_REPORT_CONTENT = re.compile(
    r"(?i)\b(?:mimikatz|secretsdump|kerberoast(?:ing)?|as[- ]?rep roast(?:ing)?|"
    r"password crack(?:ing)?|credential dump(?:ing)?|bloodhound|attack[- ]path collection|"
    r"brute[- ]force)\b"
)
_REQUIRED_CORE_PROPERTIES = (
    (_DC, "title"),
    (_DC, "subject"),
    (_DC, "creator"),
    (_CP, "lastModifiedBy"),
    (_CP, "revision"),
    (_CP, "keywords"),
    (_DCTERMS, "created"),
    (_DCTERMS, "modified"),
)

ET.register_namespace("w", _W)
ET.register_namespace("r", _R)
ET.register_namespace("cp", _CP)
ET.register_namespace("dc", _DC)
ET.register_namespace("dcterms", _DCTERMS)
ET.register_namespace("xsi", _XSI)
ET.register_namespace("wp", _WP)
ET.register_namespace("a", _A)
ET.register_namespace("pic", _PIC)


class ReportError(RuntimeError):
    """Report data or output failed a safety or validity requirement."""


@dataclass(frozen=True)
class ReportOutputs:
    """Published report paths and deterministic content digests."""

    docx_path: Path
    json_path: Path
    docx_sha256: str
    json_sha256: str


@dataclass(frozen=True)
class DocxValidation:
    """Semantic and structural DOCX validation result."""

    entries: tuple[str, ...]
    paragraph_count: int
    table_count: int
    external_relationships: tuple[str, ...]


def _iso(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportError("repository contains an invalid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReportError("repository timestamp must include a timezone")
    return parsed.astimezone(UTC)


def _age_days(observed_at: str, generated_at: datetime) -> float:
    seconds = max(0.0, (generated_at - _iso(observed_at)).total_seconds())
    return round(seconds / 86_400, 3)


def _json_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReportError("repository contains invalid observation JSON") from exc


def build_report_model(
    repository: Repository,
    deployment_id: int,
    *,
    generated_at: datetime,
    confidentiality: str = "Confidential",
    document_version: str = "1.0",
    customer_name: str = "Not supplied",
    site_name: str = "Not supplied",
    author: str = "Not supplied",
    company_name: str = "CodexNet",
) -> dict[str, Any]:
    """Build a source/age/confidence-aware deterministic report dictionary."""
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ReportError("report generation timestamp must include a timezone")
    generated = generated_at.astimezone(UTC)
    if not _SAFE_DOCUMENT_VERSION.fullmatch(document_version):
        raise ReportError("document version is invalid")
    metadata_values = {
        "confidentiality": confidentiality,
        "customer_name": customer_name,
        "site_name": site_name,
        "author": author,
        "company_name": company_name,
    }
    if any(not isinstance(value, str) or not value.strip() for value in metadata_values.values()):
        raise ReportError("report metadata values must be non-empty strings")
    deployment = repository.connection.execute(
        "SELECT * FROM deployments WHERE id = ?", (deployment_id,)
    ).fetchone()
    if deployment is None:
        raise ReportError("deployment does not exist")

    run_rows = repository.connection.execute(
        "SELECT r.collector, r.status, r.started_at, r.finished_at, r.item_count, "
        "COUNT(e.id) AS error_count FROM collector_runs r "
        "LEFT JOIN collector_errors e ON e.collector_run_id = r.id "
        "WHERE r.deployment_id = ? GROUP BY r.id ORDER BY r.started_at, r.id",
        (deployment_id,),
    ).fetchall()
    coverage = [
        {
            "collector": str(row["collector"]),
            "status": str(row["status"]),
            "started_at": str(row["started_at"]),
            "finished_at": row["finished_at"],
            "item_count": int(row["item_count"]),
            "error_count": int(row["error_count"]),
        }
        for row in run_rows
    ]

    devices: list[dict[str, Any]] = []
    device_rows = repository.connection.execute(
        "SELECT * FROM devices WHERE deployment_id = ? ORDER BY canonical_key", (deployment_id,)
    ).fetchall()
    for device in device_rows:
        device_id = int(device["id"])
        aliases = [
            {
                "kind": str(row["alias_kind"]),
                "value": str(row["alias_value"]),
                "confidence": float(row["confidence"]),
                "source": str(row["source"]),
                "observed_at": str(row["observed_at"]),
                "age_days": _age_days(str(row["observed_at"]), generated),
            }
            for row in repository.connection.execute(
                "SELECT alias_kind, alias_value, confidence, source, observed_at "
                "FROM device_aliases WHERE device_id = ? "
                "ORDER BY alias_kind, alias_value, observed_at, source",
                (device_id,),
            )
        ]
        facts = [
            {
                "type": str(row["fact_type"]),
                "value": _json_value(str(row["fact_value_json"])),
                "confidence": float(row["confidence"]),
                "inferred": bool(row["inferred"]),
                "source": str(row["source"]),
                "observed_at": str(row["observed_at"]),
                "age_days": _age_days(str(row["observed_at"]), generated),
            }
            for row in repository.connection.execute(
                "SELECT fact_type, fact_value_json, confidence, inferred, source, observed_at "
                "FROM observations WHERE deployment_id = ? AND subject_type = 'device' "
                "AND subject_id = ? ORDER BY fact_type, observed_at, source, id",
                (deployment_id, device_id),
            )
        ]
        services = [
            {
                "transport": str(row["transport"]),
                "port": int(row["port"]),
                "name": row["service_name"],
                "product": row["product"],
                "version": row["version"],
                "state": row["state"],
                "source": str(row["source"]),
                "observed_at": str(row["observed_at"]),
                "age_days": _age_days(str(row["observed_at"]), generated),
            }
            for row in repository.connection.execute(
                "SELECT transport, port, service_name, product, version, state, source, "
                "observed_at FROM services WHERE device_id = ? "
                "ORDER BY transport, port, observed_at, source",
                (device_id,),
            )
        ]
        devices.append(
            {
                "canonical_key": str(device["canonical_key"]),
                "created_at": str(device["created_at"]),
                "retired_at": device["retired_at"],
                "aliases": aliases,
                "facts": facts,
                "services": services,
            }
        )

    conflicts = _conflicts(repository, deployment_id)
    infrastructure = build_infrastructure_model(repository, deployment_id, generated_at=generated)
    platforms = build_platform_report_model(repository, deployment_id, generated_at=generated)
    limitations: list[str] = [
        "Inventory contains observations visible to configured collectors only.",
        "Absence of an observed service or device does not prove absence from the network.",
        "OS and service identification may be inferred and must be read with confidence and age.",
    ]
    if not devices:
        limitations.append("No devices were available for this deployment.")
    if not any(device["services"] for device in devices):
        limitations.append("No services were available for this deployment.")
    incomplete_collectors = sorted(
        {row["collector"] for row in coverage if row["status"] != "succeeded"}
    )
    if incomplete_collectors:
        limitations.append(
            "Collectors with incomplete or failed runs: " + ", ".join(incomplete_collectors) + "."
        )
    model: dict[str, Any] = {
        "schema_version": 2,
        "document": {
            "title": "Network Discovery Report",
            "document_version": document_version,
            "confidentiality": confidentiality,
            "generated_at": generated.isoformat(),
            "customer_name": customer_name,
            "site_name": site_name,
            "author": author,
            "company_name": company_name,
        },
        "deployment": {
            "site_key": str(deployment["site_key"]),
            "display_name": str(deployment["display_name"]),
            "assessment_started_at": str(deployment["started_at"]),
            "assessment_ended_at": deployment["ended_at"],
        },
        "coverage": coverage,
        "summary": {
            "device_count": len(devices),
            "service_count": sum(len(device["services"]) for device in devices),
            "conflict_count": len(conflicts),
            "collector_run_count": len(coverage),
            "infrastructure_conflict_count": len(cast(list[object], infrastructure["conflicts"])),
        },
        "devices": devices,
        "conflicts": conflicts,
        "infrastructure": infrastructure,
        "platforms": platforms,
        "limitations": limitations,
    }
    return cast(dict[str, Any], repository.redactor.value(model))


def _conflicts(repository: Repository, deployment_id: int) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    alias_rows = repository.connection.execute(
        "SELECT a.alias_kind, a.alias_value, GROUP_CONCAT(DISTINCT d.canonical_key) AS devices, "
        "COUNT(DISTINCT d.id) AS device_count FROM device_aliases a "
        "JOIN devices d ON d.id = a.device_id WHERE d.deployment_id = ? "
        "AND a.alias_kind IN ('ipv4', 'hostname') GROUP BY a.alias_kind, a.alias_value "
        "HAVING COUNT(DISTINCT d.id) > 1 ORDER BY a.alias_kind, a.alias_value",
        (deployment_id,),
    ).fetchall()
    for row in alias_rows:
        conflicts.append(
            {
                "kind": f"reused_{row['alias_kind']}",
                "value": str(row["alias_value"]),
                "devices": sorted(str(row["devices"]).split(",")),
                "explanation": "Reusable identity was retained on multiple devices, not merged.",
            }
        )
    decision_rows = repository.connection.execute(
        "SELECT decision, reason_json, confidence, source, observed_at "
        "FROM correlation_decisions WHERE deployment_id = ? AND decision = 'conflict' "
        "ORDER BY observed_at, id",
        (deployment_id,),
    ).fetchall()
    for row in decision_rows:
        conflicts.append(
            {
                "kind": "correlation_conflict",
                "value": _json_value(str(row["reason_json"])),
                "confidence": float(row["confidence"]),
                "source": str(row["source"]),
                "observed_at": str(row["observed_at"]),
            }
        )
    return conflicts


def deterministic_json(model: dict[str, Any]) -> bytes:
    """Encode report JSON canonically for snapshots and digest tracking."""
    return json.dumps(model, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _element(tag: str, text: str | None = None, **attributes: str) -> ET.Element:
    node = ET.Element(
        f"{{{_W}}}{tag}", {f"{{{_W}}}{key}": value for key, value in attributes.items()}
    )
    if text is not None:
        node.text = text
    return node


def _paragraph(text: object, style: str | None = None) -> ET.Element:
    paragraph = _element("p")
    if style:
        properties = _element("pPr")
        properties.append(_element("pStyle", val=style))
        paragraph.append(properties)
    run = _element("r")
    value = _element("t", str(text))
    value.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    run.append(value)
    paragraph.append(run)
    return paragraph


def _field_paragraph(instruction: str, placeholder: str) -> ET.Element:
    paragraph = _element("p")
    field = _element("fldSimple", instr=instruction)
    run = _element("r")
    value = _element("t", placeholder)
    run.append(value)
    field.append(run)
    paragraph.append(field)
    return paragraph


def _page_break() -> ET.Element:
    paragraph = _element("p")
    run = _element("r")
    run.append(_element("br", type="page"))
    paragraph.append(run)
    return paragraph


def _table(headers: tuple[str, ...], rows: list[tuple[object, ...]]) -> ET.Element:
    table = _element("tbl")
    properties = _element("tblPr")
    properties.append(_element("tblStyle", val="TableGrid"))
    table.append(properties)
    for row_index, values in enumerate([headers, *rows]):
        row = _element("tr")
        row_properties = _element("trPr")
        row_properties.append(_element("cantSplit"))
        if row_index == 0:
            row_properties.append(_element("tblHeader", val="1"))
        row.append(row_properties)
        for value in values:
            cell = _element("tc")
            cell.append(_paragraph(value if value not in {None, ""} else "—"))
            row.append(cell)
        table.append(row)
    return table


def _section_properties(*, landscape: bool = False) -> ET.Element:
    section = _element("sectPr")
    header = _element("headerReference", type="default")
    header.set(f"{{{_R}}}id", "rId4")
    section.append(header)
    footer = _element("footerReference", type="default")
    footer.set(f"{{{_R}}}id", "rId5")
    section.append(footer)
    if landscape:
        section.append(_element("pgSz", w="15840", h="12240", orient="landscape"))
    else:
        section.append(_element("pgSz", w="12240", h="15840"))
    section.append(_element("pgMar", top="1080", right="720", bottom="1080", left="720"))
    return section


def _section_break(*, landscape: bool) -> ET.Element:
    paragraph = _element("p")
    properties = _element("pPr")
    properties.append(_section_properties(landscape=landscape))
    paragraph.append(properties)
    return paragraph


def _image_paragraph(relationship_id: str, name: str, identifier: int) -> ET.Element:
    width, height = 8_900_000, 5_200_000
    paragraph = _element("p")
    run = _element("r")
    drawing = _element("drawing")
    inline = ET.Element(
        f"{{{_WP}}}inline", {"distT": "0", "distB": "0", "distL": "0", "distR": "0"}
    )
    ET.SubElement(inline, f"{{{_WP}}}extent", {"cx": str(width), "cy": str(height)})
    ET.SubElement(inline, f"{{{_WP}}}docPr", {"id": str(identifier), "name": name})
    graphic = ET.SubElement(inline, f"{{{_A}}}graphic")
    graphic_data = ET.SubElement(
        graphic,
        f"{{{_A}}}graphicData",
        {"uri": "http://schemas.openxmlformats.org/drawingml/2006/picture"},
    )
    picture = ET.SubElement(graphic_data, f"{{{_PIC}}}pic")
    non_visual = ET.SubElement(picture, f"{{{_PIC}}}nvPicPr")
    ET.SubElement(non_visual, f"{{{_PIC}}}cNvPr", {"id": "0", "name": name})
    ET.SubElement(non_visual, f"{{{_PIC}}}cNvPicPr")
    fill = ET.SubElement(picture, f"{{{_PIC}}}blipFill")
    ET.SubElement(fill, f"{{{_A}}}blip", {f"{{{_R}}}embed": relationship_id})
    stretch = ET.SubElement(fill, f"{{{_A}}}stretch")
    ET.SubElement(stretch, f"{{{_A}}}fillRect")
    shape = ET.SubElement(picture, f"{{{_PIC}}}spPr")
    transform = ET.SubElement(shape, f"{{{_A}}}xfrm")
    ET.SubElement(transform, f"{{{_A}}}off", {"x": "0", "y": "0"})
    ET.SubElement(transform, f"{{{_A}}}ext", {"cx": str(width), "cy": str(height)})
    geometry = ET.SubElement(shape, f"{{{_A}}}prstGeom", {"prst": "rect"})
    ET.SubElement(geometry, f"{{{_A}}}avLst")
    drawing.append(inline)
    run.append(drawing)
    paragraph.append(run)
    return paragraph


def _svg(title: str, nodes: list[str], edges: list[str]) -> bytes:
    visible_nodes = nodes[:24]
    visible_edges = edges[:18]
    lines = [*visible_nodes, *visible_edges]
    if len(nodes) > len(visible_nodes) or len(edges) > len(visible_edges):
        lines.append(
            f"Additional entries omitted: {len(nodes) - len(visible_nodes)} nodes, "
            f"{len(edges) - len(visible_edges)} relationships"
        )
    if not lines:
        lines = ["No supported evidence was available for this diagram."]
    height = max(360, 150 + len(lines) * 42)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="{height}" '
        'viewBox="0 0 1200 {0}">'.format(height),
        '<rect width="1200" height="100%" fill="#ffffff"/>',
        f'<text x="40" y="55" font-family="Arial, sans-serif" font-size="30" '
        f'font-weight="bold" fill="#17365d">{html.escape(title)}</text>',
    ]
    for index, line in enumerate(lines):
        y = 100 + index * 42
        fill = "#d9eaf7" if index < len(visible_nodes) else "#eaf2df"
        parts.append(
            f'<rect x="40" y="{y - 27}" width="1120" height="34" rx="6" '
            f'fill="{fill}" stroke="#5b7188"/>'
        )
        parts.append(
            f'<text x="55" y="{y - 4}" font-family="Arial, sans-serif" font-size="17" '
            f'fill="#1f1f1f">{html.escape(line)}</text>'
        )
    parts.append("</svg>")
    return "".join(parts).encode("utf-8")


def _diagram_assets(model: dict[str, Any]) -> tuple[tuple[str, str, bytes], ...]:
    infrastructure = model["infrastructure"]
    platforms = model["platforms"]
    device_nodes = [f"Device: {item['canonical_key']}" for item in model["devices"]]
    neighbor_edges = [
        f"{item['device_key'] or item['target']} — {item['key']} (source-labelled evidence)"
        for item in infrastructure["neighbors"]
    ]
    vlan_nodes = [
        f"VLAN {item['key']} on {item['device_key'] or item['target']}"
        for item in infrastructure["vlans"]
    ]
    address_nodes = [
        f"{device['canonical_key']}: {alias['value']}"
        for device in model["devices"]
        for alias in device["aliases"]
        if alias["kind"] == "ipv4"
    ]
    port_nodes = [
        f"{item['device_key'] or item['target']} port {item['key']}"
        for item in infrastructure["switch_ports"]
    ]

    def platform_lines(key: str) -> tuple[list[str], list[str]]:
        diagram = platforms[key]["diagram"]
        labels = {node["id"]: node["label"] for node in diagram["nodes"]}
        nodes = [
            f"{node['kind']}: {node['label']} · {node['source']} · age {node['age_days']}d"
            for node in diagram["nodes"]
        ]
        edges = [
            f"{labels.get(edge['from'], edge['from'])} → {edge['kind']} → "
            f"{labels.get(edge['to'], edge['to'])} · {edge['source']}"
            for edge in diagram["edges"]
        ]
        return nodes, edges

    unifi_nodes, unifi_edges = platform_lines("unifi")
    ad_nodes, ad_edges = platform_lines("active_directory")
    return (
        (
            "network-topology.svg",
            "Network topology",
            _svg("Network topology", device_nodes, neighbor_edges),
        ),
        (
            "vlan-subnet.svg",
            "VLAN and subnet relationships",
            _svg("VLAN and subnet relationships", vlan_nodes, address_nodes),
        ),
        ("switch-port-map.svg", "Switch port map", _svg("Switch port map", port_nodes, [])),
        ("unifi-topology.svg", "UniFi topology", _svg("UniFi topology", unifi_nodes, unifi_edges)),
        (
            "active-directory.svg",
            "Active Directory domains, sites, subnets, controllers and trusts",
            _svg("Active Directory structure", ad_nodes, ad_edges),
        ),
    )


def _document_xml(model: dict[str, Any]) -> bytes:
    document = ET.Element(f"{{{_W}}}document")
    body = _element("body")
    document.append(body)
    metadata = model["document"]
    deployment = model["deployment"]
    body.append(_paragraph(metadata["title"], "Title"))
    body.append(_paragraph(f"{metadata['customer_name']} — {metadata['site_name']}", "Subtitle"))
    body.append(
        _table(
            ("Document metadata", "Value"),
            [
                ("Customer", metadata["customer_name"]),
                ("Site", metadata["site_name"]),
                ("Assessment start", deployment["assessment_started_at"]),
                ("Assessment end", deployment["assessment_ended_at"] or "In progress"),
                ("Author", metadata["author"]),
                ("Company", metadata["company_name"]),
                ("Document version", metadata["document_version"]),
                ("Confidentiality", metadata["confidentiality"]),
                ("Generated", metadata["generated_at"]),
            ],
        )
    )
    body.append(_page_break())
    body.append(_paragraph("Table of contents", "Heading1"))
    body.append(
        _field_paragraph(
            'TOC \\o "1-3" \\h \\z \\u',
            "Update this field in Word or LibreOffice to refresh the table of contents.",
        )
    )
    body.append(_page_break())
    body.append(_paragraph("Executive summary", "Heading1"))
    summary = model["summary"]
    body.append(
        _paragraph(
            f"Observed {summary['device_count']} devices and {summary['service_count']} services. "
            f"The report discloses {summary['conflict_count']} conflicts."
        )
    )
    body.append(_paragraph("Embedded diagrams", "Heading1"))
    for image_index, (_filename, title, _payload) in enumerate(_diagram_assets(model), start=1):
        body.append(_paragraph(title, "Heading2"))
        body.append(_image_paragraph(f"rId{image_index + 5}", title, image_index))
    body.append(_section_break(landscape=False))
    infrastructure = model["infrastructure"]
    section_titles = (
        ("switch_ports", "Switch port maps"),
        ("vlans", "VLAN inventory"),
        ("neighbors", "Switch neighbors"),
        ("printers", "Printer inventory"),
        ("ups", "UPS inventory"),
        ("environment", "Environment readings"),
        ("firmware", "Firmware versions"),
    )
    for section_key, title in section_titles:
        body.append(_paragraph(title, "Heading1"))
        rows: list[tuple[object, ...]] = []
        for item in infrastructure[section_key]:
            for field_name, field in item["fields"].items():
                evidence = field["evidence"]
                sources = ", ".join(sorted({entry["source"] for entry in evidence}))
                ages = ", ".join(str(entry["age_days"]) for entry in evidence)
                stale = "Yes" if any(entry["stale"] for entry in evidence) else "No"
                rows.append(
                    (
                        item["device_key"] or item["target"],
                        item["key"],
                        field_name,
                        json.dumps(field["value"], sort_keys=True, ensure_ascii=False),
                        sources,
                        ages,
                        stale,
                        "Yes" if field["conflict"] else "No",
                    )
                )
        body.append(
            _table(
                (
                    "Device",
                    "Port/Index",
                    "Field",
                    "Value",
                    "Source",
                    "Age (days)",
                    "Stale",
                    "Conflict",
                ),
                rows,
            )
        )
    body.append(_paragraph("Infrastructure data quality", "Heading1"))
    for issue in infrastructure["data_quality"]:
        body.append(_paragraph(json.dumps(issue, sort_keys=True, ensure_ascii=False)))
    for limitation in infrastructure["limitations"]:
        body.append(_paragraph(f"• {limitation}"))
    body.append(_section_break(landscape=True))
    platforms = model["platforms"]
    for platform_key, title in (
        ("unifi", "UniFi topology and inventory"),
        ("active_directory", "Active Directory structure and trusts"),
    ):
        platform = platforms[platform_key]
        body.append(_paragraph(title, "Heading1"))
        diagram = platform["diagram"]
        body.append(_paragraph("Diagram nodes", "Heading2"))
        body.append(
            _table(
                ("Type", "Label", "Opaque ID", "Source", "Observed", "Age (days)"),
                [
                    (
                        item["kind"],
                        item["label"],
                        item["id"],
                        item["source"],
                        item["observed_at"],
                        item["age_days"],
                    )
                    for item in diagram["nodes"]
                ],
            )
        )
        body.append(_paragraph("Diagram relationships", "Heading2"))
        body.append(
            _table(
                ("From", "Relationship", "To", "Source", "Observed"),
                [
                    (
                        item["from"],
                        item["kind"],
                        item["to"],
                        item["source"],
                        item["observed_at"],
                    )
                    for item in diagram["edges"]
                ],
            )
        )
        body.append(_paragraph("Coverage and permissions", "Heading2"))
        if platform["coverage_notes"]:
            for note in platform["coverage_notes"]:
                body.append(_paragraph(json.dumps(note, sort_keys=True, ensure_ascii=False)))
        else:
            body.append(_paragraph("No collector permission or partial-coverage notes recorded."))
        if platform_key == "unifi":
            body.append(_paragraph("UniFi sites", "Heading2"))
            body.append(
                _table(
                    ("Controller", "Site", "Name", "Source", "Observed", "Entities"),
                    [
                        (
                            site["controller"],
                            site["site"],
                            site["name"],
                            site["source"],
                            site["observed_at"],
                            len(site["entities"]),
                        )
                        for site in platform["sites"]
                    ],
                )
            )
        else:
            body.append(_paragraph("AD domains and forests", "Heading2"))
            body.append(
                _table(
                    ("Domain", "Forest", "Functional level", "Source", "Observed", "Entities"),
                    [
                        (
                            domain["domain"],
                            domain["forest"],
                            domain["functional_level"],
                            domain["source"],
                            domain["observed_at"],
                            len(domain["entities"]),
                        )
                        for domain in platform["domains"]
                    ],
                )
            )
    body.append(_section_break(landscape=False))
    body.append(_paragraph("Collection coverage", "Heading1"))
    body.append(
        _table(
            ("Collector", "Status", "Started", "Finished", "Items", "Errors"),
            [
                (
                    row["collector"],
                    row["status"],
                    row["started_at"],
                    row["finished_at"],
                    row["item_count"],
                    row["error_count"],
                )
                for row in model["coverage"]
            ],
        )
    )
    body.append(_paragraph("Device inventory", "Heading1"))
    for device in model["devices"]:
        body.append(_paragraph(device["canonical_key"], "Heading2"))
        body.append(
            _table(
                ("Identity", "Value", "Source", "Observed", "Age (days)", "Confidence"),
                [
                    (
                        item["kind"],
                        item["value"],
                        item["source"],
                        item["observed_at"],
                        item["age_days"],
                        item["confidence"],
                    )
                    for item in device["aliases"]
                ],
            )
        )
        body.append(
            _table(
                ("Fact", "Value", "Source", "Observed", "Age (days)", "Confidence", "Basis"),
                [
                    (
                        item["type"],
                        json.dumps(item["value"], sort_keys=True, ensure_ascii=False),
                        item["source"],
                        item["observed_at"],
                        item["age_days"],
                        item["confidence"],
                        "Inference" if item["inferred"] else "Observed",
                    )
                    for item in device["facts"]
                ],
            )
        )
    body.append(_paragraph("Service inventory", "Heading1"))
    service_rows: list[tuple[object, ...]] = []
    for device in model["devices"]:
        service_rows.extend(
            (
                device["canonical_key"],
                item["transport"],
                item["port"],
                item["name"],
                item["product"],
                item["version"],
                item["state"],
                item["source"],
                item["age_days"],
            )
            for item in device["services"]
        )
    body.append(
        _table(
            (
                "Device",
                "Transport",
                "Port",
                "Service",
                "Product",
                "Version",
                "State",
                "Source",
                "Age",
            ),
            service_rows,
        )
    )
    body.append(_section_break(landscape=True))
    body.append(_paragraph("Conflicts and data quality", "Heading1"))
    if model["conflicts"]:
        for conflict in model["conflicts"]:
            body.append(_paragraph(json.dumps(conflict, sort_keys=True, ensure_ascii=False)))
    else:
        body.append(_paragraph("No explicit correlation conflicts were recorded."))
    body.append(_paragraph("Limitations", "Heading1"))
    for limitation in model["limitations"]:
        body.append(_paragraph(f"• {limitation}"))
    body.append(_section_properties(landscape=False))
    return cast(bytes, ET.tostring(document, encoding="utf-8", xml_declaration=True))


def _core_xml(model: dict[str, Any]) -> bytes:
    root = ET.Element(f"{{{_CP}}}coreProperties")
    metadata = model["document"]
    values = (
        (
            _DC,
            "title",
            f"{metadata['customer_name']} — {metadata['site_name']} — {metadata['title']}",
        ),
        (_DC, "subject", "Authorised network discovery inventory"),
        (_DC, "creator", metadata["author"]),
        (_CP, "lastModifiedBy", metadata["company_name"]),
        (_CP, "revision", metadata["document_version"]),
    )
    for namespace, tag, value in values:
        ET.SubElement(root, f"{{{namespace}}}{tag}").text = str(value)
    for tag in ("created", "modified"):
        node = ET.SubElement(root, f"{{{_DCTERMS}}}{tag}")
        node.set(f"{{{_XSI}}}type", "dcterms:W3CDTF")
        node.text = str(metadata["generated_at"])
    ET.SubElement(root, f"{{{_CP}}}keywords").text = str(metadata["confidentiality"])
    return cast(bytes, ET.tostring(root, encoding="utf-8", xml_declaration=True))


def _serialize(element: ET.Element) -> bytes:
    return cast(bytes, ET.tostring(element, encoding="utf-8", xml_declaration=True))


def _template_styles(template_path: Path | None) -> ET.Element:
    if template_path is None:
        return _element("styles")
    try:
        info = template_path.lstat()
        if (
            template_path.suffix.casefold() != ".docx"
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
        ):
            raise ReportError("report template must be a regular non-symlink DOCX")
        archive = zipfile.ZipFile(template_path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ReportError("report template is not a readable DOCX") from exc
    try:
        infos = archive.infolist()
        if (
            len(infos) > _MAX_DOCX_ENTRIES
            or len({item.filename for item in infos}) != len(infos)
            or sum(item.file_size for item in infos) > _MAX_DOCX_UNCOMPRESSED
        ):
            raise ReportError("report template exceeds safety bounds")
        for item in infos:
            if item.file_size > _MAX_DOCX_ENTRY:
                raise ReportError("report template entry exceeds safety bounds")
            if item.filename.endswith(".rels"):
                relationships = ET.fromstring(archive.read(item))
                if any(
                    relation.get("TargetMode", "").casefold() == "external"
                    for relation in relationships
                ):
                    raise ReportError("report template contains external relationships")
        payload = archive.read("word/styles.xml")
    except KeyError as exc:
        raise ReportError("report template has no Word styles part") from exc
    except ET.ParseError as exc:
        raise ReportError("report template contains malformed relationships") from exc
    finally:
        archive.close()
    if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        raise ReportError("report template styles failed security scan")
    try:
        styles = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ReportError("report template styles are malformed") from exc
    if styles.tag != f"{{{_W}}}styles":
        raise ReportError("report template styles root is invalid")
    return styles


def _styles_xml(template_path: Path | None) -> bytes:
    styles_root = _template_styles(template_path)
    existing = {
        style.get(f"{{{_W}}}styleId"): style for style in styles_root.findall(f"{{{_W}}}style")
    }
    style_specs = (
        ("paragraph", "Normal", "Normal", True, False, None),
        ("paragraph", "Title", "Title", False, True, None),
        ("paragraph", "Subtitle", "Subtitle", False, False, None),
        ("paragraph", "Heading1", "heading 1", False, True, 0),
        ("paragraph", "Heading2", "heading 2", False, True, 1),
        ("table", "TableGrid", "Table Grid", False, False, None),
    )
    for style_type, style_id, name, default, quick, level in style_specs:
        style = existing.get(style_id)
        if style is None:
            attributes = {"type": style_type, "styleId": style_id}
            if default:
                attributes["default"] = "1"
            style = _element("style", **attributes)
            style.append(_element("name", val=name))
            if style_id not in {"Normal", "TableGrid"}:
                style.append(_element("basedOn", val="Normal"))
            styles_root.append(style)
        if level is not None:
            existing_properties = style.find(f"{{{_W}}}pPr")
            if existing_properties is not None:
                style.remove(existing_properties)
            properties = _element("pPr")
            numbering = _element("numPr")
            numbering.append(_element("ilvl", val=str(level)))
            numbering.append(_element("numId", val="1"))
            properties.append(numbering)
            style.append(properties)
        if quick and style.find(f"{{{_W}}}qFormat") is None:
            style.append(_element("qFormat"))
    return _serialize(styles_root)


def _numbering_xml() -> bytes:
    root = _element("numbering")
    abstract = _element("abstractNum", abstractNumId="1")
    for level, text in ((0, "%1."), (1, "%1.%2."), (2, "%1.%2.%3.")):
        item = _element("lvl", ilvl=str(level))
        item.append(_element("start", val="1"))
        item.append(_element("numFmt", val="decimal"))
        item.append(_element("lvlText", val=text))
        item.append(_element("suff", val="space"))
        abstract.append(item)
    root.append(abstract)
    number = _element("num", numId="1")
    number.append(_element("abstractNumId", val="1"))
    root.append(number)
    return _serialize(root)


def _header_xml(model: dict[str, Any]) -> bytes:
    root = _element("hdr")
    metadata = model["document"]
    root.append(
        _paragraph(
            f"{metadata['company_name']} | {metadata['customer_name']} | {metadata['site_name']}"
        )
    )
    return _serialize(root)


def _footer_xml(model: dict[str, Any]) -> bytes:
    root = _element("ftr")
    paragraph = _paragraph(f"{model['document']['confidentiality']} | Page ")
    page = _element("fldSimple", instr="PAGE")
    page.append(_element("r"))
    paragraph.append(page)
    between = _element("r")
    between.append(_element("t", " of "))
    paragraph.append(between)
    pages = _element("fldSimple", instr="NUMPAGES")
    pages.append(_element("r"))
    paragraph.append(pages)
    root.append(paragraph)
    return _serialize(root)


def _settings_xml() -> bytes:
    root = _element("settings")
    root.append(_element("updateFields", val="true"))
    root.append(_element("evenAndOddHeaders", val="false"))
    return _serialize(root)


def _package_parts(model: dict[str, Any], *, template_path: Path | None = None) -> dict[str, bytes]:
    types = ET.Element(f"{{{_CONTENT}}}Types")
    defaults = (
        ("rels", "application/vnd.openxmlformats-package.relationships+xml"),
        ("xml", "application/xml"),
        ("svg", "image/svg+xml"),
    )
    for extension, content_type in defaults:
        ET.SubElement(
            types,
            f"{{{_CONTENT}}}Default",
            {"Extension": extension, "ContentType": content_type},
        )
    overrides = (
        (
            "/word/document.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
        ),
        (
            "/word/styles.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
        ),
        (
            "/word/numbering.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml",
        ),
        (
            "/word/settings.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
        ),
        (
            "/word/header1.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml",
        ),
        (
            "/word/footer1.xml",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml",
        ),
        ("/docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml"),
        (
            "/docProps/app.xml",
            "application/vnd.openxmlformats-officedocument.extended-properties+xml",
        ),
    )
    for part_name, content_type in overrides:
        ET.SubElement(
            types,
            f"{{{_CONTENT}}}Override",
            {"PartName": part_name, "ContentType": content_type},
        )

    relationships = ET.Element(f"{{{_REL}}}Relationships")
    root_relationships = (
        (
            "rId1",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
            "word/document.xml",
        ),
        (
            "rId2",
            "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
            "docProps/core.xml",
        ),
        (
            "rId3",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties",
            "docProps/app.xml",
        ),
    )
    for identifier, relationship_type, target in root_relationships:
        ET.SubElement(
            relationships,
            f"{{{_REL}}}Relationship",
            {"Id": identifier, "Type": relationship_type, "Target": target},
        )
    document_relationships = ET.Element(f"{{{_REL}}}Relationships")
    ET.SubElement(
        document_relationships,
        f"{{{_REL}}}Relationship",
        {
            "Id": "rId1",
            "Type": ("http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"),
            "Target": "styles.xml",
        },
    )
    for identifier, relationship_type, target in (
        (
            "rId2",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering",
            "numbering.xml",
        ),
        (
            "rId3",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings",
            "settings.xml",
        ),
        (
            "rId4",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/header",
            "header1.xml",
        ),
        (
            "rId5",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer",
            "footer1.xml",
        ),
    ):
        ET.SubElement(
            document_relationships,
            f"{{{_REL}}}Relationship",
            {"Id": identifier, "Type": relationship_type, "Target": target},
        )
    diagrams = _diagram_assets(model)
    for index, (filename, _title, _payload) in enumerate(diagrams, start=6):
        ET.SubElement(
            document_relationships,
            f"{{{_REL}}}Relationship",
            {
                "Id": f"rId{index}",
                "Type": "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                "Target": f"media/{filename}",
            },
        )

    app_namespace = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
    app_root = ET.Element(f"{{{app_namespace}}}Properties")
    ET.SubElement(app_root, f"{{{app_namespace}}}Application").text = "CodexNet"
    ET.SubElement(app_root, f"{{{app_namespace}}}AppVersion").text = "1.0"

    parts = {
        "[Content_Types].xml": _serialize(types),
        "_rels/.rels": _serialize(relationships),
        "docProps/app.xml": _serialize(app_root),
        "docProps/core.xml": _core_xml(model),
        "word/_rels/document.xml.rels": _serialize(document_relationships),
        "word/document.xml": _document_xml(model),
        "word/styles.xml": _styles_xml(template_path),
        "word/numbering.xml": _numbering_xml(),
        "word/settings.xml": _settings_xml(),
        "word/header1.xml": _header_xml(model),
        "word/footer1.xml": _footer_xml(model),
    }
    for filename, _title, payload in diagrams:
        parts[f"word/media/{filename}"] = payload
    return parts


def deterministic_docx(model: dict[str, Any], *, template_path: Path | None = None) -> bytes:
    """Create a deterministic, self-contained WordprocessingML package."""
    import io

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, payload in sorted(_package_parts(model, template_path=template_path).items()):
            info = zipfile.ZipInfo(name, date_time=_FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            info.create_system = 3
            archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return output.getvalue()


def _safe_output_root(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReportError("report output root must be a real directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ReportError("report output root must not allow group or other access")


def _publish(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ReportError("report output must be a new regular file") from exc
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def generate_reports(
    repository: Repository,
    deployment_id: int,
    output_root: Path,
    *,
    generated_at: datetime,
    customer_name: str = "Not supplied",
    site_name: str = "Not supplied",
    author: str = "Not supplied",
    company_name: str = "CodexNet",
    confidentiality: str = "Confidential",
    document_version: str = "1.0",
    template_path: Path | None = None,
) -> ReportOutputs:
    """Generate, validate, publish, and record paired DOCX/JSON reports."""
    model = build_report_model(
        repository,
        deployment_id,
        generated_at=generated_at,
        confidentiality=confidentiality,
        document_version=document_version,
        customer_name=customer_name,
        site_name=site_name,
        author=author,
        company_name=company_name,
    )
    json_payload = deterministic_json(model)
    docx_payload = deterministic_docx(model, template_path=template_path)
    _safe_output_root(output_root)
    customer_label = safe_filename(customer_name, redactor=repository.redactor)
    site_label = safe_filename(site_name, redactor=repository.redactor)
    label = f"{customer_label}-{site_label}-Network-Discovery-{generated_at:%Y%m%d}"
    basename = safe_filename(label, redactor=repository.redactor)
    docx_path = output_root / f"{basename}.docx"
    json_path = output_root / f"{basename}.json"
    _publish(docx_path, docx_payload)
    try:
        _publish(json_path, json_payload)
        validate_docx(docx_path, redactor=repository.redactor)
    except Exception:
        docx_path.unlink(missing_ok=True)
        json_path.unlink(missing_ok=True)
        raise
    docx_digest = hashlib.sha256(docx_payload).hexdigest()
    json_digest = hashlib.sha256(json_payload).hexdigest()
    timestamp = generated_at.astimezone(UTC).isoformat()
    try:
        with repository.transaction():
            for format_name, path, digest in (
                ("docx", docx_path, docx_digest),
                ("json", json_path, json_digest),
            ):
                repository.connection.execute(
                    "INSERT INTO report_history"
                    "(deployment_id, format, relative_path, sha256_digest, document_version, "
                    "generated_at, source, observed_at) VALUES (?, ?, ?, ?, ?, ?, 'report', ?)",
                    (
                        deployment_id,
                        format_name,
                        path.name,
                        digest,
                        document_version,
                        timestamp,
                        timestamp,
                    ),
                )
    except Exception:
        docx_path.unlink(missing_ok=True)
        json_path.unlink(missing_ok=True)
        raise
    return ReportOutputs(docx_path, json_path, docx_digest, json_digest)


def _parse_package_xml(payload: bytes) -> ET.Element:
    try:
        return ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ReportError("DOCX contains a malformed XML package member") from exc


def _security_scan(payload: bytes, redactor: Redactor, *, structural_text: bool) -> None:
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ReportError("DOCX package member failed security scan")
    if any(variant and variant in payload for variant in redactor.registered_byte_variants()):
        raise ReportError("DOCX package member failed security scan")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return
    if (structural_text and redactor.text(text) != text) or _PROHIBITED_REPORT_CONTENT.search(text):
        raise ReportError("DOCX package member failed content audit")


def _validate_report_filename(path: Path, redactor: Redactor) -> None:
    match = _REPORT_FILENAME.fullmatch(path.name)
    if match is None or redactor.text(path.name) != path.name:
        raise ReportError("DOCX filename does not match the production report convention")
    try:
        datetime.strptime(match.group("date"), "%Y%m%d")
    except ValueError as exc:
        raise ReportError("DOCX filename contains an invalid report date") from exc


def _relationship_source(relationship_part: str) -> str | None:
    if relationship_part == "_rels/.rels":
        return None
    path = PurePosixPath(relationship_part)
    if path.parent.name != "_rels" or not path.name.endswith(".rels"):
        raise ReportError("DOCX relationship part is invalid")
    source_name = path.name.removesuffix(".rels")
    return (path.parent.parent / source_name).as_posix()


def _validate_required_properties(roots: dict[str, ET.Element]) -> None:
    core = roots.get("docProps/core.xml")
    app = roots.get("docProps/app.xml")
    if core is None or app is None:
        raise ReportError("DOCX is missing required document properties")
    if any(
        (node := core.find(f"{{{namespace}}}{name}")) is None or not (node.text or "").strip()
        for namespace, name in _REQUIRED_CORE_PROPERTIES
    ):
        raise ReportError("DOCX has incomplete required document properties")
    application = next((node for node in app if node.tag.endswith("}Application")), None)
    if application is None or not (application.text or "").strip():
        raise ReportError("DOCX has incomplete required document properties")


def _validate_document_semantics(
    document: ET.Element,
    roots: dict[str, ET.Element],
    relationships: dict[str, tuple[str, str]],
) -> tuple[int, int]:
    paragraphs = document.findall(f".//{{{_W}}}p")
    tables = document.findall(f".//{{{_W}}}tbl")
    if not paragraphs:
        raise ReportError("DOCX contains no document paragraphs")
    headings: set[str] = set()
    for paragraph in paragraphs:
        style = paragraph.find(f"./{{{_W}}}pPr/{{{_W}}}pStyle")
        if style is not None and style.get(f"{{{_W}}}val") == "Heading1":
            headings.add("".join(node.text or "" for node in paragraph.findall(f".//{{{_W}}}t")))
    if not _REQUIRED_REPORT_SECTIONS.issubset(headings):
        raise ReportError("DOCX is missing one or more required report sections")

    document_relations = roots.get("word/_rels/document.xml.rels")
    if document_relations is None:
        raise ReportError("DOCX is missing required document relationships")
    image_ids = {
        relation.get("Id", "")
        for relation in document_relations.findall(f"{{{_REL}}}Relationship")
        if relation.get("Type", "").endswith("/image")
    }
    embedded_ids = {
        node.get(f"{{{_R}}}embed", "")
        for node in document.findall(f".//{{{_A}}}blip")
        if node.get(f"{{{_R}}}embed")
    }
    if len(embedded_ids) < 5 or embedded_ids != image_ids:
        raise ReportError("DOCX is missing one or more required embedded images")
    if any(
        not relationships[identifier][1].startswith("word/media/") for identifier in embedded_ids
    ):
        raise ReportError("DOCX contains an invalid embedded image relationship")
    return len(paragraphs), len(tables)


def _decoded_target(target: str) -> str:
    if not target or len(target) > _MAX_RELATIONSHIP_TARGET:
        raise ReportError("DOCX relationship target is invalid")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in target):
        raise ReportError("DOCX relationship target is invalid")
    decoded = target.strip()
    for _ in range(2):
        if re.search(r"%(?![0-9A-Fa-f]{2})", decoded):
            raise ReportError("DOCX relationship target is invalid")
        updated = unquote(decoded)
        if updated == decoded:
            break
        decoded = updated
    return decoded


def _internal_relationship_target(target: str, relationship_part: str) -> str:
    decoded = _decoded_target(target)
    normalized_slashes = decoded.replace("\\", "/")
    inspected = normalized_slashes.casefold()
    if "\\" in decoded or normalized_slashes.startswith("/") or _URI_SCHEME.match(inspected):
        raise ReportError("DOCX contains an external or absolute relationship")
    for separator in ("?", "#"):
        _prefix, present, suffix = normalized_slashes.partition(separator)
        if present and (
            suffix.startswith(("/", "\\"))
            or "//" in suffix
            or "\\" in suffix
            or _EMBEDDED_URI_SCHEME.search(suffix)
        ):
            raise ReportError("DOCX contains an external or absolute relationship")
    path = re.split(r"[?#]", normalized_slashes, maxsplit=1)[0]
    if not path:
        raise ReportError("DOCX relationship target is invalid")
    relationship_path = PurePosixPath(relationship_part)
    if relationship_part == "_rels/.rels":
        base = ""
    else:
        if relationship_path.parent.name != "_rels" or not relationship_path.name.endswith(".rels"):
            raise ReportError("DOCX relationship part is invalid")
        base = relationship_path.parent.parent.as_posix()
    resolved = normpath(f"{base}/{path}" if base else path)
    if resolved in {"", ".", ".."} or resolved.startswith("../"):
        raise ReportError("DOCX relationship target escapes the package")
    return resolved


def validate_docx(path: Path, *, redactor: Redactor | None = None) -> DocxValidation:
    """Validate bounded DOCX internals, relationships, semantics, and redaction."""
    active_redactor = redactor or Redactor()
    if path.suffix.casefold() != ".docx":
        raise ReportError("DOCX filename does not match the production report convention")
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ReportError("report is not a valid DOCX ZIP package") from exc
    required = {
        "[Content_Types].xml",
        "_rels/.rels",
        "docProps/app.xml",
        "docProps/core.xml",
        "word/_rels/document.xml.rels",
        "word/document.xml",
        "word/footer1.xml",
        "word/header1.xml",
        "word/numbering.xml",
        "word/settings.xml",
        "word/styles.xml",
    }
    external: list[str] = []
    try:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(infos) > _MAX_DOCX_ENTRIES or len(set(names)) != len(names):
            raise ReportError("DOCX has too many or duplicate package entries")
        if not required.issubset(names):
            raise ReportError("DOCX is missing required package entries")
        total = 0
        roots: dict[str, ET.Element] = {}
        relationships: dict[str, tuple[str, str]] = {}
        for info in infos:
            pure = PurePosixPath(info.filename)
            if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                raise ReportError("DOCX contains an unsafe package path")
            if info.file_size > _MAX_DOCX_ENTRY:
                raise ReportError("DOCX package entry exceeds the size limit")
            total += info.file_size
            if total > _MAX_DOCX_UNCOMPRESSED:
                raise ReportError("DOCX uncompressed content exceeds the size limit")
            try:
                payload = archive.read(info)
            except (RuntimeError, zipfile.BadZipFile) as exc:
                raise ReportError("DOCX package content cannot be read safely") from exc
            is_xml = info.filename.endswith((".xml", ".rels", ".svg"))
            _security_scan(payload, active_redactor, structural_text=not is_xml)
            if active_redactor.text(info.filename) != info.filename:
                raise ReportError("DOCX package filename contains sensitive data")
            if is_xml:
                payload.decode("utf-8", errors="strict")
                root = _parse_package_xml(payload)
                roots[info.filename] = root
                for element in root.iter():
                    values = [element.text, element.tail, *element.attrib.values()]
                    if any(
                        value is not None and active_redactor.text(value) != value
                        for value in values
                    ):
                        raise ReportError("DOCX package member failed content audit")
                if info.filename.endswith(".rels"):
                    source = _relationship_source(info.filename)
                    if source is not None and source not in names:
                        external.append(info.filename)
                    identifiers: set[str] = set()
                    for relationship in root.findall(f"{{{_REL}}}Relationship"):
                        identifier = relationship.get("Id", "")
                        target = relationship.get("Target", "")
                        mode = relationship.get("TargetMode")
                        if not identifier or identifier in identifiers:
                            external.append(info.filename)
                            continue
                        identifiers.add(identifier)
                        if mode not in {None, "Internal"}:
                            external.append(info.filename)
                            continue
                        try:
                            resolved = _internal_relationship_target(target, info.filename)
                        except ReportError:
                            external.append(info.filename)
                            continue
                        if resolved not in names:
                            external.append(info.filename)
                            continue
                        if source == "word/document.xml":
                            relationships[identifier] = (relationship.get("Type", ""), resolved)
        if external:
            raise ReportError("DOCX contains external relationships or broken relationships")
        document_root = roots["word/document.xml"]
        referenced = {
            value
            for element in document_root.iter()
            for attribute, value in element.attrib.items()
            if attribute.startswith(f"{{{_R}}}")
            and attribute.rsplit("}", maxsplit=1)[-1] in {"embed", "id", "link"}
        }
        if not referenced.issubset(relationships):
            raise ReportError("DOCX contains external relationships or broken relationships")
        _validate_required_properties(roots)
        paragraphs, tables = _validate_document_semantics(document_root, roots, relationships)
        _validate_report_filename(path, active_redactor)
        return DocxValidation(tuple(sorted(names)), paragraphs, tables, tuple(external))
    except UnicodeDecodeError as exc:
        raise ReportError("DOCX package content cannot be read safely") from exc
    finally:
        archive.close()


def outputs_as_dict(outputs: ReportOutputs) -> dict[str, Any]:
    """Stable CLI representation without serializing report content."""
    return {
        "docx_path": str(outputs.docx_path),
        "json_path": str(outputs.json_path),
        "docx_sha256": outputs.docx_sha256,
        "json_sha256": outputs.json_sha256,
    }
