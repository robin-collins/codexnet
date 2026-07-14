"""Read-only, idempotent nmap artifact import tests."""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO, cast

import pytest

from field_discovery import nmap_import
from field_discovery.nmap_import import NmapImportError, import_nmap_artifacts
from field_discovery.nmap_xml import NmapScan, NmapXmlError, parse_nmap_xml
from field_discovery.redaction import Redactor
from field_discovery.repository import Repository

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"
NOW = datetime(2026, 7, 16, 1, 0, tzinfo=UTC)


@pytest.fixture
def repository(tmp_path: Path) -> Iterator[Repository]:
    data = tmp_path / "data"
    data.mkdir()
    result = Repository.open(data / "discovery.db", data_root=data)
    yield result
    result.close()


def deployment(repository: Repository) -> int:
    return repository.upsert_deployment("fixture", "Fixture", NOW.isoformat())


def old_copy(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    timestamp = (NOW - timedelta(minutes=1)).timestamp()
    os.utime(destination, (timestamp, timestamp))
    return destination


def table_count(repository: Repository, table: str) -> int:
    return int(repository.connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])


def test_recursive_import_normalizes_inventory_and_is_idempotent(
    repository: Repository, tmp_path: Path
) -> None:
    root = tmp_path / "nmap"
    artifact = old_copy(FIXTURES / "success.xml", root / "nested" / "scan.xml")
    (root / "ignored.txt").write_text("not an XML artifact")
    before = (artifact.stat().st_mode, artifact.read_bytes())

    first = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)
    second = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)

    assert (first.discovered, first.imported, first.hosts, first.issues) == (1, 1, 1, ())
    assert (second.imported, second.skipped, second.deferred) == (0, 1, 0)
    assert table_count(repository, "artifacts") == 1
    assert table_count(repository, "devices") == 1
    assert table_count(repository, "device_aliases") == 3
    assert table_count(repository, "address_assignments") == 2
    assert table_count(repository, "services") == 2
    assert table_count(repository, "observations") == 5
    artifact_row = repository.connection.execute(
        "SELECT relative_path, media_type FROM artifacts"
    ).fetchone()
    assert tuple(artifact_row) == ("nested/scan.xml", "application/xml")
    assert (artifact.stat().st_mode, artifact.read_bytes()) == before

    digest = str(repository.connection.execute("SELECT sha256_digest FROM artifacts").fetchone()[0])
    scan = parse_nmap_xml(artifact)
    observed_at = scan.finished_at
    assert observed_at is not None
    observations = tuple(
        nmap_import._host_observation(host, digest=digest, index=index, observed_at=observed_at)
        for index, host in enumerate(scan.hosts)
    )
    assert not nmap_import._persist(
        repository,
        deployment_id=deployment(repository),
        collector_run_id=None,
        relative_path="nested/scan.xml",
        digest=digest,
        size=artifact.stat().st_size,
        file_time=NOW.isoformat(),
        imported_at=NOW.isoformat(),
        scan=scan,
        observations=observations,
    )


def test_later_distinct_scan_at_same_path_retains_history(
    repository: Repository, tmp_path: Path
) -> None:
    root = tmp_path / "nmap"
    artifact = old_copy(FIXTURES / "success.xml", root / "scan.xml")
    deployment_id = deployment(repository)
    assert (
        import_nmap_artifacts(repository, root, deployment_id=deployment_id, now=NOW).imported == 1
    )

    updated = artifact.read_text().replace("1784106004", "1784107004")
    artifact.write_text(updated)
    old = (NOW - timedelta(seconds=30)).timestamp()
    os.utime(artifact, (old, old))
    later = import_nmap_artifacts(repository, root, deployment_id=deployment_id, now=NOW)

    assert later.imported == 1
    assert table_count(repository, "artifacts") == 2
    assert table_count(repository, "devices") == 1
    assert table_count(repository, "services") == 4
    assert table_count(repository, "observations") == 10


def test_unstable_and_incomplete_files_defer_without_database_writes(
    repository: Repository, tmp_path: Path
) -> None:
    root = tmp_path / "nmap"
    root.mkdir()
    recent = root / "recent.xml"
    shutil.copyfile(FIXTURES / "success.xml", recent)
    os.utime(recent, (NOW.timestamp(), NOW.timestamp()))
    incomplete = old_copy(FIXTURES / "partial.xml", root / "incomplete.xml")
    truncated = old_copy(FIXTURES / "malformed.xml", root / "truncated.xml")

    summary = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)

    assert incomplete.is_file()
    assert truncated.is_file()
    assert (summary.discovered, summary.deferred, summary.imported, summary.issues) == (3, 3, 0, ())
    assert table_count(repository, "artifacts") == 0
    assert table_count(repository, "devices") == 0


def test_malformed_and_permission_errors_are_isolated(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "nmap"
    old_copy(FIXTURES / "success.xml", root / "good.xml")
    malformed = old_copy(FIXTURES / "malformed.xml", root / "malformed.xml")
    malformed.write_text("<nmaprun><host></nmaprun>")
    old = (NOW - timedelta(minutes=1)).timestamp()
    os.utime(malformed, (old, old))
    denied = old_copy(FIXTURES / "success.xml", root / "denied.xml")
    original_open = nmap_import._open_readonly

    def selective_open(path: Path):  # type: ignore[no-untyped-def]
        if path == denied:
            raise PermissionError("synthetic private detail")
        return original_open(path)

    monkeypatch.setattr(nmap_import, "_open_readonly", selective_open)
    summary = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)

    assert summary.imported == 1
    assert len(summary.issues) == 2
    assert [(issue.relative_path, issue.category) for issue in summary.issues] == [
        ("denied.xml", "permission"),
        ("malformed.xml", "artifact"),
    ]
    assert summary.issues[0].detail == "permission denied"
    assert table_count(repository, "artifacts") == 1


def test_transaction_rolls_back_all_inventory_when_artifact_insert_fails(
    repository: Repository, tmp_path: Path
) -> None:
    root = tmp_path / "nmap"
    old_copy(FIXTURES / "success.xml", root / "scan.xml")
    repository.connection.execute(
        "CREATE TRIGGER fixture_artifact_failure BEFORE INSERT ON artifacts "
        "BEGIN SELECT RAISE(ABORT, 'synthetic'); END"
    )
    summary = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)

    assert summary.imported == 0
    assert len(summary.issues) == 1
    assert table_count(repository, "artifacts") == 0
    assert table_count(repository, "devices") == 0
    assert table_count(repository, "services") == 0
    assert table_count(repository, "observations") == 0


def test_file_changed_during_import_is_deferred(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "nmap"
    old_copy(FIXTURES / "success.xml", root / "scan.xml")
    original_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> os.stat_result:
        nonlocal calls
        result = cast(os.stat_result, original_fstat(descriptor))
        calls += 1
        if calls == 3:
            values = list(result)
            values[8] += 1
            return os.stat_result(values)
        return result

    monkeypatch.setattr(nmap_import, "_fstat", changing_fstat)
    summary = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)
    assert summary.deferred == 1
    assert table_count(repository, "artifacts") == 0


def test_content_digest_change_during_parse_is_deferred(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "nmap"
    artifact = old_copy(FIXTURES / "success.xml", root / "scan.xml")
    original_parse = nmap_import.parse_nmap_xml

    def changing_parse(stream: BinaryIO) -> NmapScan:
        result = original_parse(stream)
        artifact.write_bytes(b"<nmaprun/>")
        return result

    monkeypatch.setattr(nmap_import, "parse_nmap_xml", changing_parse)
    summary = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)
    assert summary.deferred == 1
    assert table_count(repository, "artifacts") == 0


@pytest.mark.parametrize(
    ("kind", "message"),
    [
        ("relative", "absolute"),
        ("missing", "unavailable"),
        ("non_xml", "suffix"),
        ("special", "regular file or directory"),
        ("symlink", "symlink"),
    ],
)
def test_unsafe_or_invalid_roots_fail_closed(
    repository: Repository, tmp_path: Path, kind: str, message: str
) -> None:
    target = tmp_path / "target"
    if kind == "relative":
        target = Path("relative")
    elif kind == "non_xml":
        target.write_text("fixture")
    elif kind == "special":
        target.mkdir()
        target = target / "fifo"
        os.mkfifo(target)
    elif kind == "symlink":
        real = tmp_path / "real"
        real.mkdir()
        target.symlink_to(real, target_is_directory=True)
    with pytest.raises(NmapImportError, match=message):
        import_nmap_artifacts(repository, target, deployment_id=deployment(repository), now=NOW)


def test_direct_file_import_and_invalid_stability(repository: Repository, tmp_path: Path) -> None:
    artifact = old_copy(FIXTURES / "success.xml", tmp_path / "single.xml")
    result = import_nmap_artifacts(
        repository, artifact, deployment_id=deployment(repository), now=NOW
    )
    assert (result.discovered, result.imported) == (1, 1)
    with pytest.raises(NmapImportError, match="negative"):
        import_nmap_artifacts(
            repository, artifact, deployment_id=deployment(repository), stability_seconds=-1
        )
    with pytest.raises(NmapImportError, match="finite"):
        import_nmap_artifacts(
            repository,
            artifact,
            deployment_id=deployment(repository),
            stability_seconds=float("nan"),
        )


def test_sparse_completed_scan_uses_file_time_and_safe_identity_fallback(
    repository: Repository, tmp_path: Path
) -> None:
    root = tmp_path / "nmap"
    root.mkdir()
    artifact = root / "sparse.xml"
    artifact.write_text(
        "<nmaprun><host/><host><address addr='02:00:00:00:00:22' addrtype='mac'/>"
        "<address addr='2001:db8::1' addrtype='ipv6'/><os><osmatch name='Unknown OS'/>"
        "</os><hostscript><script id='empty'/></hostscript></host>"
        "<runstats><finished exit='success'/></runstats></nmaprun>"
    )
    old = (NOW - timedelta(minutes=2)).timestamp()
    os.utime(artifact, (old, old))

    result = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)

    assert (result.imported, result.hosts, result.issues) == (1, 2, ())
    assert table_count(repository, "devices") == 2
    values = [
        row[0]
        for row in repository.connection.execute(
            "SELECT fact_value_json FROM observations ORDER BY id"
        )
    ]
    assert sorted(values) == ['"(no output)"', '"Unknown OS"']


def test_discovery_errors_and_nonregular_open_are_isolated(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "nmap"
    blocked = root / "blocked"
    blocked.mkdir(parents=True)
    old_copy(FIXTURES / "success.xml", root / "good.xml")
    original_scandir = os.scandir

    def selective_scandir(path: os.PathLike[str] | str) -> Any:
        if Path(path) == blocked:
            raise PermissionError("synthetic")
        return original_scandir(path)

    monkeypatch.setattr("field_discovery.nmap_import.os.scandir", selective_scandir)
    result = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)
    assert result.imported == 1
    assert [(item.relative_path, item.category) for item in result.issues] == [
        ("blocked", "discovery")
    ]

    monkeypatch.setattr(nmap_import, "_fstat", lambda _descriptor: blocked.stat())
    with pytest.raises(NmapImportError, match="regular file"):
        nmap_import._open_readonly(root / "good.xml")


def test_entry_inspection_error_and_root_discovery_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    root.mkdir()

    class BrokenEntry:
        name = "broken.xml"
        path = str(root / name)

        def is_dir(self, *, follow_symlinks: bool) -> bool:
            del follow_symlinks
            raise PermissionError("synthetic")

        def is_file(self, *, follow_symlinks: bool) -> bool:
            del follow_symlinks
            return False

    monkeypatch.setattr("field_discovery.nmap_import.os.scandir", lambda _path: [BrokenEntry()])
    candidates, issues = nmap_import._walk_xml(root)
    assert candidates == []
    assert issues[0].relative_path == "broken.xml"

    def denied(_path: Path) -> None:
        raise PermissionError("synthetic")

    monkeypatch.setattr("field_discovery.nmap_import.os.scandir", denied)
    candidates, issues = nmap_import._walk_xml(root)
    assert candidates == []
    assert issues[0].relative_path == "."


def test_sensitive_path_and_atomic_duplicate_race_are_refused(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "nmap"
    artifact = old_copy(FIXTURES / "success.xml", root / "secret.xml")
    repository.redactor = Redactor(["secret"])
    result = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)
    assert result.imported == 0
    assert result.issues[0].detail == "RepositoryError"

    repository.redactor = Redactor()
    monkeypatch.setattr(nmap_import, "_persist", lambda *_args, **_kwargs: False)
    result = import_nmap_artifacts(
        repository, artifact, deployment_id=deployment(repository), now=NOW
    )
    assert (result.skipped, result.imported) == (1, 0)


def test_safe_error_detail_is_bounded() -> None:
    detail = nmap_import._safe_detail(NmapXmlError("x" * 600))
    assert len(detail) == 512
    assert detail.endswith("...")


def test_service_fields_are_redacted_before_persistence(
    repository: Repository, tmp_path: Path
) -> None:
    root = tmp_path / "nmap"
    old_copy(FIXTURES / "success.xml", root / "scan.xml")
    repository.redactor = Redactor(["SyntheticSSH"])
    result = import_nmap_artifacts(repository, root, deployment_id=deployment(repository), now=NOW)
    assert result.imported == 1
    product = repository.connection.execute(
        "SELECT product FROM services WHERE port = 22"
    ).fetchone()[0]
    assert product == "[REDACTED]"
