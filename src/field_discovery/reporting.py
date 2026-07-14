"""Deterministic inventory report model, DOCX generation, and validation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast
from xml.etree import ElementTree as ET

from field_discovery.artifacts import safe_filename
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
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_MAX_DOCX_ENTRIES = 64
_MAX_DOCX_UNCOMPRESSED = 32 * 1024 * 1024
_MAX_DOCX_ENTRY = 8 * 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_SAFE_DOCUMENT_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")

ET.register_namespace("w", _W)
ET.register_namespace("r", _R)
ET.register_namespace("cp", _CP)
ET.register_namespace("dc", _DC)
ET.register_namespace("dcterms", _DCTERMS)
ET.register_namespace("xsi", _XSI)


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
) -> dict[str, Any]:
    """Build a source/age/confidence-aware deterministic report dictionary."""
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ReportError("report generation timestamp must include a timezone")
    generated = generated_at.astimezone(UTC)
    if not _SAFE_DOCUMENT_VERSION.fullmatch(document_version):
        raise ReportError("document version is invalid")
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
        "schema_version": 1,
        "document": {
            "title": "Network Discovery Report",
            "document_version": document_version,
            "confidentiality": confidentiality,
            "generated_at": generated.isoformat(),
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
        },
        "devices": devices,
        "conflicts": conflicts,
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


def _table(headers: tuple[str, ...], rows: list[tuple[object, ...]]) -> ET.Element:
    table = _element("tbl")
    properties = _element("tblPr")
    properties.append(_element("tblStyle", val="TableGrid"))
    table.append(properties)
    for values in [headers, *rows]:
        row = _element("tr")
        for value in values:
            cell = _element("tc")
            cell.append(_paragraph(value if value not in {None, ""} else "—"))
            row.append(cell)
        table.append(row)
    return table


def _document_xml(model: dict[str, Any]) -> bytes:
    document = ET.Element(f"{{{_W}}}document")
    body = _element("body")
    document.append(body)
    metadata = model["document"]
    deployment = model["deployment"]
    body.append(_paragraph(metadata["title"], "Title"))
    body.append(_paragraph(deployment["display_name"], "Subtitle"))
    body.append(_paragraph(metadata["confidentiality"]))
    body.append(_paragraph(f"Generated: {metadata['generated_at']}"))
    body.append(_paragraph("Executive summary", "Heading1"))
    summary = model["summary"]
    body.append(
        _paragraph(
            f"Observed {summary['device_count']} devices and {summary['service_count']} services. "
            f"The report discloses {summary['conflict_count']} conflicts."
        )
    )
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
    body.append(_paragraph("Conflicts and data quality", "Heading1"))
    if model["conflicts"]:
        for conflict in model["conflicts"]:
            body.append(_paragraph(json.dumps(conflict, sort_keys=True, ensure_ascii=False)))
    else:
        body.append(_paragraph("No explicit correlation conflicts were recorded."))
    body.append(_paragraph("Limitations", "Heading1"))
    for limitation in model["limitations"]:
        body.append(_paragraph(f"• {limitation}"))
    section = _element("sectPr")
    section.append(_element("pgSz", w="12240", h="15840"))
    section.append(_element("pgMar", top="1440", right="1080", bottom="1440", left="1080"))
    body.append(section)
    return cast(bytes, ET.tostring(document, encoding="utf-8", xml_declaration=True))


def _core_xml(model: dict[str, Any]) -> bytes:
    root = ET.Element(f"{{{_CP}}}coreProperties")
    values = (
        (_DC, "title", model["document"]["title"]),
        (_DC, "subject", "Authorised network discovery inventory"),
        (_DC, "creator", "CodexNet"),
        (_CP, "lastModifiedBy", "CodexNet"),
        (_CP, "revision", model["document"]["document_version"]),
    )
    for namespace, tag, value in values:
        ET.SubElement(root, f"{{{namespace}}}{tag}").text = str(value)
    for tag in ("created", "modified"):
        node = ET.SubElement(root, f"{{{_DCTERMS}}}{tag}")
        node.set(f"{{{_XSI}}}type", "dcterms:W3CDTF")
        node.text = str(model["document"]["generated_at"])
    ET.SubElement(root, f"{{{_CP}}}keywords").text = str(model["document"]["confidentiality"])
    return cast(bytes, ET.tostring(root, encoding="utf-8", xml_declaration=True))


def _package_parts(model: dict[str, Any]) -> dict[str, bytes]:
    types = ET.Element(f"{{{_CONTENT}}}Types")
    defaults = (
        ("rels", "application/vnd.openxmlformats-package.relationships+xml"),
        ("xml", "application/xml"),
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

    styles_root = _element("styles")
    style_specs = (
        ("paragraph", "Normal", "Normal", True, False),
        ("paragraph", "Title", "Title", False, True),
        ("paragraph", "Subtitle", "Subtitle", False, False),
        ("paragraph", "Heading1", "heading 1", False, True),
        ("paragraph", "Heading2", "heading 2", False, True),
        ("table", "TableGrid", "Table Grid", False, False),
    )
    for style_type, style_id, name, default, quick in style_specs:
        attributes = {"type": style_type, "styleId": style_id}
        if default:
            attributes["default"] = "1"
        style = _element("style", **attributes)
        style.append(_element("name", val=name))
        if style_id not in {"Normal", "TableGrid"}:
            style.append(_element("basedOn", val="Normal"))
        if quick:
            style.append(_element("qFormat"))
        styles_root.append(style)

    app_namespace = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
    app_root = ET.Element(f"{{{app_namespace}}}Properties")
    ET.SubElement(app_root, f"{{{app_namespace}}}Application").text = "CodexNet"
    ET.SubElement(app_root, f"{{{app_namespace}}}AppVersion").text = "1.0"

    def serialize(element: ET.Element) -> bytes:
        return cast(bytes, ET.tostring(element, encoding="utf-8", xml_declaration=True))

    return {
        "[Content_Types].xml": serialize(types),
        "_rels/.rels": serialize(relationships),
        "docProps/app.xml": serialize(app_root),
        "docProps/core.xml": _core_xml(model),
        "word/_rels/document.xml.rels": serialize(document_relationships),
        "word/document.xml": _document_xml(model),
        "word/styles.xml": serialize(styles_root),
    }


def deterministic_docx(model: dict[str, Any]) -> bytes:
    """Create a deterministic, self-contained WordprocessingML package."""
    import io

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, payload in sorted(_package_parts(model).items()):
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
    confidentiality: str = "Confidential",
    document_version: str = "1.0",
) -> ReportOutputs:
    """Generate, validate, publish, and record paired DOCX/JSON reports."""
    model = build_report_model(
        repository,
        deployment_id,
        generated_at=generated_at,
        confidentiality=confidentiality,
        document_version=document_version,
    )
    json_payload = deterministic_json(model)
    docx_payload = deterministic_docx(model)
    _safe_output_root(output_root)
    label = f"{model['deployment']['display_name']}-Network-Discovery-{generated_at:%Y%m%d-%H%M%S}"
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


def _parse_package_xml(name: str, payload: bytes) -> ET.Element:
    upper = payload.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ReportError(f"DOCX XML contains a prohibited declaration: {name}")
    try:
        return ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ReportError(f"DOCX contains malformed XML: {name}") from exc


def validate_docx(path: Path, *, redactor: Redactor | None = None) -> DocxValidation:
    """Validate bounded DOCX internals, relationships, semantics, and redaction."""
    active_redactor = redactor or Redactor()
    if path.suffix.casefold() != ".docx" or active_redactor.text(path.name) != path.name:
        raise ReportError("DOCX filename is invalid or sensitive")
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ReportError("report is not a valid DOCX ZIP package") from exc
    required = {"[Content_Types].xml", "_rels/.rels", "word/document.xml"}
    external: list[str] = []
    try:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(infos) > _MAX_DOCX_ENTRIES or len(set(names)) != len(names):
            raise ReportError("DOCX has too many or duplicate package entries")
        if not required.issubset(names):
            raise ReportError("DOCX is missing required package entries")
        total = 0
        document_root: ET.Element | None = None
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
            if active_redactor.text(info.filename) != info.filename:
                raise ReportError("DOCX package filename contains sensitive data")
            if info.filename.endswith((".xml", ".rels")):
                payload.decode("utf-8", errors="strict")
                root = _parse_package_xml(info.filename, payload)
                for element in root.iter():
                    values = [element.text, element.tail, *element.attrib.values()]
                    if any(
                        value is not None and active_redactor.text(value) != value
                        for value in values
                    ):
                        raise ReportError(f"DOCX contains sensitive content: {info.filename}")
                if info.filename == "word/document.xml":
                    document_root = root
                if info.filename.endswith(".rels"):
                    for relationship in root.findall(f"{{{_REL}}}Relationship"):
                        target = relationship.get("Target", "")
                        if relationship.get("TargetMode") == "External" or re.match(
                            r"^[A-Za-z][A-Za-z0-9+.-]*:", target
                        ):
                            external.append(f"{info.filename}:{target}")
        if external:
            raise ReportError("DOCX contains external relationships")
        assert document_root is not None
        paragraphs = document_root.findall(f".//{{{_W}}}p")
        tables = document_root.findall(f".//{{{_W}}}tbl")
        if not paragraphs:
            raise ReportError("DOCX contains no document paragraphs")
        return DocxValidation(tuple(sorted(names)), len(paragraphs), len(tables), tuple(external))
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
