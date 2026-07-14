"""Deterministic JSON/DOCX report generation and validation tests."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sqlite3
import stat
import subprocess
import warnings
import zipfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import pytest

from field_discovery import reporting
from field_discovery.redaction import REDACTED, Redactor
from field_discovery.reporting import (
    ReportError,
    build_report_model,
    deterministic_docx,
    deterministic_json,
    generate_reports,
    outputs_as_dict,
    validate_docx,
)
from field_discovery.repository import Repository

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)
OLD = "2026-07-01T00:00:00+00:00"
OBSERVED = "2026-07-14T00:00:00+00:00"


@pytest.fixture
def repository(tmp_path: Path) -> Iterator[Repository]:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    result = Repository.open(root / "discovery.db", data_root=root)
    yield result
    result.close()


def populated(repository: Repository) -> int:
    deployment_id = repository.upsert_deployment("fixture", "Fixture Site", OLD)
    first = repository.upsert_device(deployment_id, "device-a", OLD)
    second = repository.upsert_device(deployment_id, "device-b", OLD)
    for device_id, mac in ((first, "02:00:00:00:00:01"), (second, "02:00:00:00:00:02")):
        repository.connection.execute(
            "INSERT INTO device_aliases"
            "(device_id, alias_kind, alias_value, confidence, source, observed_at) "
            "VALUES (?, 'mac', ?, 1.0, 'nmap', ?), "
            "(?, 'ipv4', '192.0.2.10', 0.8, 'nmap', ?)",
            (device_id, mac, OBSERVED, device_id, OBSERVED),
        )
    repository.connection.execute(
        "INSERT INTO observations"
        "(deployment_id, subject_type, subject_id, fact_type, fact_value_json, confidence, "
        "inferred, source, observed_at) VALUES (?, 'device', ?, 'host_state', '" + '"up"' + "', "
        "1.0, 0, 'nmap', ?), (?, 'device', ?, 'os_guess', '" + '"Synthetic OS"' + "', "
        "0.75, 1, 'nmap', ?)",
        (deployment_id, first, OBSERVED, deployment_id, first, OBSERVED),
    )
    repository.connection.execute(
        "INSERT INTO services"
        "(device_id, transport, port, service_name, product, version, state, source, observed_at) "
        "VALUES (?, 'tcp', 22, 'ssh', 'SyntheticSSH', '1.0', 'open', 'nmap', ?)",
        (first, OBSERVED),
    )
    succeeded = repository.start_run(deployment_id, "nmap_import", OLD)
    repository.finish_run(succeeded, "succeeded", OBSERVED, 2)
    partial = repository.start_run(deployment_id, "snmp", OLD)
    repository.connection.execute(
        "INSERT INTO collector_errors"
        "(collector_run_id, category, detail, retryable, source, observed_at) "
        "VALUES (?, 'timeout', 'synthetic timeout', 1, 'snmp', ?)",
        (partial, OBSERVED),
    )
    repository.finish_run(partial, "partial", OBSERVED, 0)
    repository.connection.execute(
        "INSERT INTO correlation_decisions"
        "(deployment_id, left_device_id, right_device_id, decision, reason_json, confidence, "
        "source, observed_at) VALUES (?, ?, ?, 'conflict', '{\"reason\":\"fixture\"}', "
        "0.8, 'fixture', ?)",
        (deployment_id, first, second, OBSERVED),
    )
    return deployment_id


def test_report_model_is_deterministic_provenance_aware_and_snapshot_stable(
    repository: Repository,
) -> None:
    deployment_id = populated(repository)
    first = build_report_model(repository, deployment_id, generated_at=NOW)
    second = build_report_model(repository, deployment_id, generated_at=NOW)

    assert first == second
    assert first["summary"] == {
        "device_count": 2,
        "service_count": 1,
        "conflict_count": 2,
        "collector_run_count": 2,
    }
    assert first["coverage"][1]["status"] == "partial"
    assert first["coverage"][1]["error_count"] == 1
    assert first["devices"][0]["facts"][1]["inferred"] is True
    assert first["devices"][0]["services"][0]["source"] == "nmap"
    assert first["devices"][0]["services"][0]["age_days"] == 1.5
    assert first["conflicts"][0]["kind"] == "reused_ipv4"
    assert "Collectors with incomplete or failed runs: snmp." in first["limitations"]
    payload = deterministic_json(first)
    assert payload == deterministic_json(second)
    assert hashlib.sha256(payload).hexdigest() == (
        "2626787fc7408d6121b49deee295944377ac49c3d850102e455495802f56ae84"
    )


def test_empty_deployment_discloses_coverage_limitations(repository: Repository) -> None:
    deployment_id = repository.upsert_deployment("empty", "Empty", OLD)
    model = build_report_model(repository, deployment_id, generated_at=NOW)
    assert model["summary"]["device_count"] == 0
    assert "No devices were available for this deployment." in model["limitations"]
    assert "No services were available for this deployment." in model["limitations"]
    docx = deterministic_docx(model)
    with zipfile.ZipFile(__import__("io").BytesIO(docx)) as archive:
        assert b"No explicit correlation conflicts" in archive.read("word/document.xml")


def test_generate_reports_publishes_restrictive_valid_self_contained_outputs(
    repository: Repository, tmp_path: Path
) -> None:
    deployment_id = populated(repository)
    output_root = tmp_path / "reports"
    first = generate_reports(repository, deployment_id, output_root, generated_at=NOW)

    assert stat.S_IMODE(first.docx_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(first.json_path.stat().st_mode) == 0o600
    assert first.docx_sha256 == hashlib.sha256(first.docx_path.read_bytes()).hexdigest()
    assert first.json_sha256 == hashlib.sha256(first.json_path.read_bytes()).hexdigest()
    assert first.docx_path.name == "Fixture-Site-Network-Discovery-20260715-120000.docx"
    validation = validate_docx(first.docx_path)
    assert validation.external_relationships == ()
    assert validation.paragraph_count > 10
    assert validation.table_count >= 5
    with zipfile.ZipFile(first.docx_path) as archive:
        assert "word/document.xml" in archive.namelist()
        document = archive.read("word/document.xml").decode()
        assert "Collection coverage" in document
        assert "Inference" in document
        assert "Conflicts and data quality" in document
        assert all(
            'TargetMode="External"' not in archive.read(name).decode()
            for name in archive.namelist()
            if name.endswith(".rels")
        )
    assert json.loads(first.json_path.read_text())["summary"]["device_count"] == 2
    assert repository.connection.execute("SELECT COUNT(*) FROM report_history").fetchone()[0] == 2
    assert outputs_as_dict(first) == {
        "docx_path": str(first.docx_path),
        "json_path": str(first.json_path),
        "docx_sha256": first.docx_sha256,
        "json_sha256": first.json_sha256,
    }

    model = build_report_model(repository, deployment_id, generated_at=NOW)
    assert first.docx_path.read_bytes() == deterministic_docx(model)
    with pytest.raises(ReportError, match="new regular file"):
        generate_reports(repository, deployment_id, output_root, generated_at=NOW)


def test_report_secret_scan_covers_json_docx_properties_and_filenames(
    repository: Repository, tmp_path: Path
) -> None:
    deployment_id = populated(repository)
    repository.connection.execute(
        "UPDATE deployments SET display_name = 'Site synthetic-secret' WHERE id = ?",
        (deployment_id,),
    )
    repository.connection.execute("UPDATE services SET product = 'password=synthetic-secret'")
    repository.redactor = Redactor(["synthetic-secret"])
    outputs = generate_reports(repository, deployment_id, tmp_path / "reports", generated_at=NOW)

    assert "synthetic-secret" not in outputs.docx_path.name
    assert "synthetic-secret" not in outputs.json_path.name
    assert "synthetic-secret" not in outputs.json_path.read_text()
    assert REDACTED in outputs.json_path.read_text()
    with zipfile.ZipFile(outputs.docx_path) as archive:
        for name in archive.namelist():
            assert "synthetic-secret" not in name
            if name.endswith((".xml", ".rels")):
                assert "synthetic-secret" not in archive.read(name).decode()
    validate_docx(outputs.docx_path, redactor=repository.redactor)


def _write_package(path: Path, parts: list[tuple[str, bytes]]) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in parts:
                archive.writestr(name, payload)


def _valid_parts(repository: Repository) -> list[tuple[str, bytes]]:
    deployment_id = populated(repository)
    model = build_report_model(repository, deployment_id, generated_at=NOW)
    data = deterministic_docx(model)
    with zipfile.ZipFile(__import__("io").BytesIO(data)) as archive:
        return [(name, archive.read(name)) for name in archive.namelist()]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "missing required"),
        ("unsafe_path", "unsafe package path"),
        ("duplicate", "duplicate package"),
        ("external_mode", "external relationships"),
        ("external_uri", "external relationships"),
        ("doctype", "security scan"),
        ("malformed", "malformed XML"),
        ("no_paragraph", "no document paragraphs"),
        ("invalid_utf8", "cannot be read safely"),
    ],
)
def test_docx_validation_rejects_unsafe_packages(
    repository: Repository, tmp_path: Path, mutation: str, message: str
) -> None:
    parts = _valid_parts(repository)
    if mutation == "missing":
        parts = [(name, data) for name, data in parts if name != "word/document.xml"]
    elif mutation == "unsafe_path":
        parts.append(("../escape.xml", b"<x/>"))
    elif mutation == "duplicate":
        parts.append(parts[0])
    elif mutation in {"external_mode", "external_uri"}:
        target = "https://example.invalid/x" if mutation == "external_uri" else "remote.xml"
        mode = ' TargetMode="External"' if mutation == "external_mode" else ""
        relationship = (
            f'<Relationships xmlns="{reporting._REL}"><Relationship Id="x" '
            f'Type="fixture" Target="{target}"{mode}/></Relationships>'
        ).encode()
        parts = [
            (name, relationship if name == "word/_rels/document.xml.rels" else data)
            for name, data in parts
        ]
    elif mutation == "doctype":
        parts.append(("custom.xml", b"<!DOCTYPE x [<!ENTITY y 'z'>]><x/>"))
    elif mutation == "malformed":
        parts.append(("custom.xml", b"<x>"))
    elif mutation == "no_paragraph":
        document = f'<w:document xmlns:w="{reporting._W}"><w:body/></w:document>'.encode()
        parts = [(name, document if name == "word/document.xml" else data) for name, data in parts]
    else:
        parts.append(("custom.xml", b"\xff"))
    path = tmp_path / f"{mutation}.docx"
    _write_package(path, parts)
    with pytest.raises(ReportError, match=message):
        validate_docx(path)


def test_docx_validation_enforces_filename_entry_and_size_limits(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parts = _valid_parts(repository)
    valid = tmp_path / "valid.docx"
    _write_package(valid, parts)
    with pytest.raises(ReportError, match="filename"):
        validate_docx(tmp_path / "not-docx.zip")
    sensitive = tmp_path / "synthetic-secret.docx"
    sensitive.write_bytes(valid.read_bytes())
    with pytest.raises(ReportError, match="filename"):
        validate_docx(sensitive, redactor=Redactor(["synthetic-secret"]))

    named_secret = tmp_path / "named-secret.docx"
    _write_package(named_secret, [*parts, ("synthetic-secret.xml", b"<x/>")])
    with pytest.raises(ReportError, match="package filename"):
        validate_docx(named_secret, redactor=Redactor(["synthetic-secret"]))

    monkeypatch.setattr(reporting, "_MAX_DOCX_ENTRIES", 1)
    with pytest.raises(ReportError, match="too many"):
        validate_docx(valid)
    monkeypatch.setattr(reporting, "_MAX_DOCX_ENTRIES", 64)
    monkeypatch.setattr(reporting, "_MAX_DOCX_ENTRY", 1)
    with pytest.raises(ReportError, match="entry exceeds"):
        validate_docx(valid)
    monkeypatch.setattr(reporting, "_MAX_DOCX_ENTRY", 8 * 1024 * 1024)
    monkeypatch.setattr(reporting, "_MAX_DOCX_UNCOMPRESSED", 1)
    with pytest.raises(ReportError, match="uncompressed"):
        validate_docx(valid)


@pytest.mark.parametrize(
    ("target", "mode"),
    [
        ("//files.example.invalid/share", None),
        (r"\\files.example.invalid\share", None),
        ("/word/styles.xml", None),
        ("file:///etc/passwd", None),
        ("https://example.invalid/resource", None),
        ("%2F%2Fexample.invalid/resource", None),
        ("%252F%252Fexample.invalid/resource", None),
        ("%5C%5Cserver%5Cshare", None),
        ("C:%5CWindows%5Cfile", None),
        ("styles.xml?next=https%3A%2F%2Fexample.invalid", None),
        ("styles.xml?next=file%3Arelative", None),
        ("styles.xml?next=%2F%2Fexample.invalid", None),
        ("styles.xml#%5C%5Cexample.invalid", None),
        ("styles.xml#next=https%3Ahost", None),
        ("styles.xml", "External"),
        ("//example.invalid", "Internal"),
        ("../../../outside.xml", None),
        ("missing.xml", None),
        ("bad%GGtarget.xml", None),
        ("?next=safe", None),
        ("x" * 2_049, None),
        ("", None),
    ],
)
def test_relationship_target_audit_rejects_external_ambiguous_and_missing_targets(
    repository: Repository, tmp_path: Path, target: str, mode: str | None
) -> None:
    parts = _valid_parts(repository)
    mode_attribute = "" if mode is None else f' TargetMode="{mode}"'
    relationship = (
        f'<Relationships xmlns="{reporting._REL}"><Relationship Id="fixture" '
        f'Type="fixture" Target="{target}"{mode_attribute}/></Relationships>'
    ).encode()
    path = tmp_path / f"target-{len(target)}-{mode or 'none'}.docx"
    _write_package(
        path,
        [
            (name, relationship if name == "word/_rels/document.xml.rels" else data)
            for name, data in parts
        ],
    )
    with pytest.raises(ReportError, match="external relationships") as caught:
        validate_docx(path)
    if target:
        assert target not in str(caught.value)


def test_relationship_audit_accepts_confined_parent_and_rejects_invalid_relationship_part(
    repository: Repository, tmp_path: Path
) -> None:
    parts = _valid_parts(repository)
    parent_target = (
        f'<Relationships xmlns="{reporting._REL}"><Relationship Id="fixture" '
        'Target="../docProps/core.xml"/></Relationships>'
    ).encode()
    confined = tmp_path / "confined.docx"
    _write_package(
        confined,
        [
            (name, parent_target if name == "word/_rels/document.xml.rels" else data)
            for name, data in parts
        ],
    )
    assert validate_docx(confined).external_relationships == ()

    invalid_part = tmp_path / "invalid-part.docx"
    _write_package(invalid_part, [*parts, ("custom.rels", parent_target)])
    with pytest.raises(ReportError, match="external relationships"):
        validate_docx(invalid_part)
    with pytest.raises(ReportError, match="target is invalid"):
        reporting._internal_relationship_target("styles.xml\x00hidden", "_rels/.rels")


@pytest.mark.parametrize(
    "secret_form",
    [
        b"Synthetic Secret!",
        base64.b64encode(b"Synthetic Secret!"),
        quote("Synthetic Secret!", safe="").encode(),
        b"Synthetic Secret!".hex().encode(),
    ],
)
def test_every_package_member_is_scanned_for_registered_binary_secret_variants(
    repository: Repository, tmp_path: Path, secret_form: bytes
) -> None:
    parts = [*_valid_parts(repository), ("word/media/opaque.bin", b"\xff" + secret_form + b"\x00")]
    path = tmp_path / f"binary-secret-{len(secret_form)}.docx"
    _write_package(path, parts)
    secret = "Synthetic Secret!"
    with pytest.raises(ReportError, match="security scan") as caught:
        validate_docx(path, redactor=Redactor([secret]))
    assert secret not in str(caught.value)
    assert secret_form.decode("ascii") not in str(caught.value)


def test_prohibited_declaration_is_rejected_in_non_xml_member(
    repository: Repository, tmp_path: Path
) -> None:
    parts = [*_valid_parts(repository), ("word/media/opaque.bin", b"\x00<!entity fixture>\xff")]
    path = tmp_path / "binary-declaration.docx"
    _write_package(path, parts)
    with pytest.raises(ReportError, match="security scan"):
        validate_docx(path)


def test_invalid_model_and_zip_inputs_fail_closed(repository: Repository, tmp_path: Path) -> None:
    deployment_id = populated(repository)
    with pytest.raises(ReportError, match="does not exist"):
        build_report_model(repository, 999, generated_at=NOW)
    with pytest.raises(ReportError, match="timezone"):
        build_report_model(repository, deployment_id, generated_at=datetime(2026, 1, 1))
    with pytest.raises(ReportError, match="version"):
        build_report_model(repository, deployment_id, generated_at=NOW, document_version="bad x")
    repository.connection.execute(
        "UPDATE device_aliases SET observed_at = 'not-a-time' WHERE id = "
        "(SELECT id FROM device_aliases LIMIT 1)"
    )
    with pytest.raises(ReportError, match="timestamp"):
        build_report_model(repository, deployment_id, generated_at=NOW)
    repository.connection.execute(
        "UPDATE device_aliases SET observed_at = '2026-07-14T00:00:00' WHERE id = "
        "(SELECT id FROM device_aliases LIMIT 1)"
    )
    with pytest.raises(ReportError, match="timezone"):
        build_report_model(repository, deployment_id, generated_at=NOW)
    with pytest.raises(ReportError, match="observation JSON"):
        reporting._json_value("not-json")

    bad = tmp_path / "bad.docx"
    bad.write_text("not a zip")
    with pytest.raises(ReportError, match="valid DOCX"):
        validate_docx(bad)


def test_validator_checks_non_xml_entries_text_nodes_and_read_errors(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parts = [*_valid_parts(repository), ("payload.bin", b"\xff\x00synthetic")]
    valid = tmp_path / "with-binary.docx"
    _write_package(valid, parts)
    assert validate_docx(valid).paragraph_count > 0

    sensitive = tmp_path / "sensitive-content.docx"
    _write_package(
        sensitive,
        [*parts, ("custom.xml", b"<root><value>password=fixture-value</value></root>")],
    )
    with pytest.raises(ReportError, match="sensitive content"):
        validate_docx(sensitive)

    no_target = tmp_path / "no-target.docx"
    relationship = (
        f'<Relationships xmlns="{reporting._REL}"><Relationship Id="x"/></Relationships>'
    ).encode()
    _write_package(
        no_target,
        [
            (name, relationship if name == "word/_rels/document.xml.rels" else data)
            for name, data in parts
        ],
    )
    with pytest.raises(ReportError, match="external relationships"):
        validate_docx(no_target)

    benign = tmp_path / "benign-target.docx"
    benign_relationship = (
        f'<Relationships xmlns="{reporting._REL}"><Relationship Id="x" '
        'Target="styles.xml?theme=blue#section"/></Relationships>'
    ).encode()
    _write_package(
        benign,
        [
            (name, benign_relationship if name == "word/_rels/document.xml.rels" else data)
            for name, data in parts
        ],
    )
    assert validate_docx(benign).external_relationships == ()

    def failed_read(
        _self: zipfile.ZipFile, _name: object, *_args: object, **_kwargs: object
    ) -> bytes:
        raise RuntimeError("synthetic encrypted entry")

    monkeypatch.setattr(zipfile.ZipFile, "read", failed_read)
    with pytest.raises(ReportError, match="cannot be read safely"):
        validate_docx(valid)


def test_publish_removes_partial_file_when_sync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "partial.json"

    def fail_sync(_descriptor: int) -> None:
        raise OSError("synthetic sync failure")

    monkeypatch.setattr("field_discovery.reporting.os.fsync", fail_sync)
    with pytest.raises(OSError, match="sync failure"):
        reporting._publish(target, b"fixture")
    assert not target.exists()


def test_generation_cleans_files_on_validation_and_database_failures(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    deployment_id = populated(repository)
    first_root = tmp_path / "first"

    def fail_validation(_path: Path, *, redactor: Redactor) -> None:
        del redactor
        raise ReportError("synthetic validation")

    monkeypatch.setattr(reporting, "validate_docx", fail_validation)
    with pytest.raises(ReportError, match="synthetic validation"):
        generate_reports(repository, deployment_id, first_root, generated_at=NOW)
    assert list(first_root.iterdir()) == []

    monkeypatch.undo()
    repository.connection.execute(
        "CREATE TRIGGER report_failure BEFORE INSERT ON report_history "
        "BEGIN SELECT RAISE(ABORT, 'synthetic'); END"
    )
    second_root = tmp_path / "second"
    with pytest.raises(sqlite3.IntegrityError):
        generate_reports(repository, deployment_id, second_root, generated_at=NOW)
    assert list(second_root.iterdir()) == []
    assert repository.connection.execute("SELECT COUNT(*) FROM report_history").fetchone()[0] == 0


def test_output_root_must_be_private_and_real(repository: Repository, tmp_path: Path) -> None:
    deployment_id = populated(repository)
    permissive = tmp_path / "permissive"
    permissive.mkdir(mode=0o755)
    with pytest.raises(ReportError, match="group or other"):
        generate_reports(repository, deployment_id, permissive, generated_at=NOW)
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(ReportError, match="real directory"):
        generate_reports(repository, deployment_id, linked, generated_at=NOW)


def test_libreoffice_can_open_generated_docx_when_available(
    repository: Repository, tmp_path: Path
) -> None:
    executable = shutil.which("libreoffice") or shutil.which("soffice")
    if executable is None:
        pytest.skip("LibreOffice headless is not installed on this appliance")
    outputs = generate_reports(
        repository, populated(repository), tmp_path / "reports", generated_at=NOW
    )
    converted = tmp_path / "converted"
    converted.mkdir()
    result = subprocess.run(
        [
            executable,
            "--headless",
            "--convert-to",
            "pdf",
            "--outdir",
            str(converted),
            str(outputs.docx_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert list(converted.glob("*.pdf"))
