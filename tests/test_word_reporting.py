"""Production Word renderer semantics, templates, scale, and self-containment tests."""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from field_discovery import reporting
from field_discovery.reporting import (
    ReportError,
    build_report_model,
    deterministic_docx,
    validate_docx,
)
from field_discovery.repository import Repository

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
OBSERVED = "2026-07-14T00:00:00+00:00"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"


def model(tmp_path: Path, *, devices: int = 0) -> dict[str, object]:
    root = tmp_path / "data"
    root.mkdir(mode=0o700, parents=True)
    repository = Repository.open(root / "discovery.db", data_root=root)
    deployment = repository.upsert_deployment("fixture", "Repository label", OBSERVED)
    for index in range(devices):
        device = repository.upsert_device(deployment, f"device-{index:03d}", OBSERVED)
        repository.connection.execute(
            "INSERT INTO device_aliases"
            "(device_id,alias_kind,alias_value,confidence,source,observed_at) "
            "VALUES (?, 'ipv4', ?, 1.0, 'fixture', ?)",
            (device, f"192.0.2.{index % 254 + 1}", OBSERVED),
        )
        repository.connection.execute(
            "INSERT INTO services"
            "(device_id,transport,port,service_name,product,version,state,source,observed_at) "
            "VALUES (?, 'tcp', 443, 'https', 'Synthetic', '1', 'open', 'fixture', ?)",
            (device, OBSERVED),
        )
    result = build_report_model(
        repository,
        deployment,
        generated_at=NOW,
        customer_name="Example Customer",
        site_name="Adelaide Office",
        author="Example Technician",
        company_name="Example MSP",
    )
    repository.close()
    return result


def parts(payload: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def write_parts(path: Path, values: dict[str, bytes] | list[tuple[str, bytes]]) -> None:
    items = values.items() if isinstance(values, dict) else values
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in items:
            archive.writestr(name, payload)


def test_production_docx_has_metadata_toc_numbering_headers_landscape_and_diagrams(
    tmp_path: Path,
) -> None:
    payload = deterministic_docx(model(tmp_path))
    package = parts(payload)
    document = ET.fromstring(package["word/document.xml"])
    relationships = ET.fromstring(package["word/_rels/document.xml.rels"])
    styles = ET.fromstring(package["word/styles.xml"])
    settings = ET.fromstring(package["word/settings.xml"])
    footer = ET.fromstring(package["word/footer1.xml"])
    core = package["docProps/core.xml"].decode()

    instructions = {item.get(f"{{{W}}}instr") for item in document.findall(f".//{{{W}}}fldSimple")}
    assert 'TOC \\o "1-3" \\h \\z \\u' in instructions
    assert settings.find(f"{{{W}}}updateFields").get(f"{{{W}}}val") == "true"  # type: ignore[union-attr]
    assert {item.get(f"{{{W}}}instr") for item in footer.findall(f".//{{{W}}}fldSimple")} == {
        "PAGE",
        "NUMPAGES",
    }
    assert b"Example MSP | Example Customer | Adelaide Office" in package["word/header1.xml"]
    assert "Example Technician" in core
    assert "Example Customer" in core

    tables = document.findall(f".//{{{W}}}tbl")
    repeated_headers = document.findall(f".//{{{W}}}tblHeader")
    assert len(tables) == len(repeated_headers) and len(tables) >= 10
    assert len(document.findall(f".//{{{W}}}pgSz[@{{{W}}}orient='landscape']")) >= 2
    assert len(document.findall(f".//{{{W}}}headerReference[@{{{R}}}id='rId4']")) >= 3
    assert len(document.findall(f".//{{{W}}}drawing")) == 5
    assert b"TOC" in package["word/document.xml"]

    heading_styles = {
        item.get(f"{{{W}}}styleId"): item
        for item in styles.findall(f"{{{W}}}style")
        if item.get(f"{{{W}}}styleId") in {"Heading1", "Heading2"}
    }
    assert all(item.find(f".//{{{W}}}numPr") is not None for item in heading_styles.values())
    image_relations = [item for item in relationships if item.get("Type", "").endswith("/image")]
    assert len(image_relations) == 5
    assert all(item.get("Target", "").startswith("media/") for item in image_relations)
    media = sorted(name for name in package if name.startswith("word/media/"))
    assert len(media) == 5
    assert all(package[name].startswith(b"<svg") for name in media)
    assert all(
        b"http://" not in package[name].replace(b'xmlns="http://www.w3.org/2000/svg"', b"")
        for name in media
    )
    assert all(b"https://" not in package[name] for name in media)
    assert not any(
        b'TargetMode="External"' in value
        for name, value in package.items()
        if name.endswith(".rels")
    )

    target = tmp_path / "Example-Customer-Adelaide-Office-Network-Discovery-20260715.docx"
    target.write_bytes(payload)
    validation = validate_docx(target)
    assert validation.external_relationships == ()
    assert validation.table_count == len(tables)


def test_safe_docx_template_styles_are_preserved_and_required_styles_numbered(
    tmp_path: Path,
) -> None:
    report_model = model(tmp_path)
    template_parts = parts(deterministic_docx(report_model))
    styles = ET.fromstring(template_parts["word/styles.xml"])
    marker = ET.SubElement(
        styles,
        f"{{{W}}}style",
        {f"{{{W}}}type": "paragraph", f"{{{W}}}styleId": "CompanyBrand"},
    )
    ET.SubElement(marker, f"{{{W}}}name", {f"{{{W}}}val": "Company Brand Marker"})
    template_parts["word/styles.xml"] = ET.tostring(styles, encoding="utf-8", xml_declaration=True)
    template = tmp_path / "company-template.docx"
    write_parts(template, template_parts)

    rendered = parts(deterministic_docx(report_model, template_path=template))
    assert b"Company Brand Marker" in rendered["word/styles.xml"]
    output_styles = ET.fromstring(rendered["word/styles.xml"])
    for style_id in ("Heading1", "Heading2"):
        style = output_styles.find(f"{{{W}}}style[@{{{W}}}styleId='{style_id}']")
        assert style is not None and style.find(f".//{{{W}}}numPr") is not None


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "readable DOCX"),
        ("directory", "regular non-symlink"),
        ("missing_styles", "no Word styles"),
        ("external", "external relationships"),
        ("malformed_relationship", "malformed relationships"),
        ("malformed_styles", "styles are malformed"),
        ("wrong_styles_root", "styles root is invalid"),
        ("doctype", "failed security scan"),
        ("too_many", "exceeds safety bounds"),
        ("oversized", "entry exceeds safety bounds"),
    ],
)
def test_unsafe_or_malformed_templates_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, message: str
) -> None:
    report_model = model(tmp_path / "model")
    base = parts(deterministic_docx(report_model))
    template = tmp_path / f"{mutation}.docx"
    if mutation == "missing":
        pass
    elif mutation == "directory":
        template.mkdir()
    elif mutation == "missing_styles":
        base.pop("word/styles.xml")
        write_parts(template, base)
    elif mutation == "external":
        base["word/_rels/document.xml.rels"] = (
            f'<Relationships xmlns="{REL}"><Relationship Id="rIdX" Type="fixture" '
            'Target="https://example.invalid" TargetMode="External"/></Relationships>'
        ).encode()
        write_parts(template, base)
    elif mutation == "malformed_relationship":
        base["word/_rels/document.xml.rels"] = b"<Relationships>"
        write_parts(template, base)
    elif mutation == "malformed_styles":
        base["word/styles.xml"] = b"<styles>"
        write_parts(template, base)
    elif mutation == "wrong_styles_root":
        base["word/styles.xml"] = b"<root/>"
        write_parts(template, base)
    elif mutation == "doctype":
        base["word/styles.xml"] = (
            b'<!DOCTYPE x [<!ENTITY e "x">]><w:styles xmlns:w="' + W.encode() + b'"/>'
        )
        write_parts(template, base)
    elif mutation == "too_many":
        write_parts(template, [(f"part-{index}.xml", b"<x/>") for index in range(65)])
    else:
        write_parts(template, base)
        monkeypatch.setattr(reporting, "_MAX_DOCX_ENTRY", -1)
        with pytest.raises(ReportError, match=message):
            deterministic_docx(report_model, template_path=template)
        return
    with pytest.raises(ReportError, match=message):
        deterministic_docx(report_model, template_path=template)


def test_template_symlink_is_rejected(tmp_path: Path) -> None:
    report_model = model(tmp_path / "model")
    real = tmp_path / "real.docx"
    real.write_bytes(deterministic_docx(report_model))
    linked = tmp_path / "linked.docx"
    linked.symlink_to(real)
    with pytest.raises(ReportError, match="regular non-symlink"):
        deterministic_docx(report_model, template_path=linked)


def test_empty_and_large_reports_remain_bounded_deterministic_and_valid(tmp_path: Path) -> None:
    empty_model = model(tmp_path / "empty")
    large_model = model(tmp_path / "large", devices=180)
    empty = deterministic_docx(empty_model)
    large = deterministic_docx(large_model)
    assert empty == deterministic_docx(empty_model)
    assert large == deterministic_docx(large_model)
    assert len(empty) < 1_000_000
    assert len(large) < 8_000_000
    for name, payload in (("empty.docx", empty), ("large.docx", large)):
        path = tmp_path / name
        path.write_bytes(payload)
        validation = validate_docx(path)
        assert validation.external_relationships == ()
        assert validation.paragraph_count > 0
