"""Transactional repository and confined maintenance tests."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

from field_discovery.database import APPLICATION_ID
from field_discovery.redaction import REDACTED, Redactor
from field_discovery.repository import (
    Repository,
    RepositoryError,
    RetentionCutoffs,
    UnsafeRepositoryPath,
    _verify_database,
    export_digest,
)

OLD = "2026-01-01T00:00:00Z"
NEW = "2026-06-01T00:00:00Z"
CUTOFF = "2026-03-01T00:00:00Z"


@pytest.fixture
def repository(tmp_path: Path) -> Repository:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    result = Repository.open(root / "discovery.db", data_root=root)
    yield result
    result.close()


def deployment(repository: Repository) -> int:
    return repository.upsert_deployment("fixture", "Fixture Site", OLD)


def test_upserts_and_observations_are_transactional_idempotent_and_redacted(
    repository: Repository,
) -> None:
    deployment_id = deployment(repository)
    assert repository.upsert_deployment("fixture", "Renamed Fixture", NEW) == deployment_id
    assert repository.get_deployment("fixture")["display_name"] == "Renamed Fixture"  # type: ignore[index]
    assert repository.get_deployment("missing") is None
    device_id = repository.upsert_device(deployment_id, "mac:001122334455", OLD)
    assert repository.upsert_device(deployment_id, "mac:001122334455", NEW) == device_id
    assert repository.get_device(device_id)["canonical_key"] == "mac:001122334455"  # type: ignore[index]
    assert repository.get_device(999) is None
    arguments = {
        "deployment_id": deployment_id,
        "subject_type": "device",
        "subject_id": device_id,
        "fact_type": "fixture",
        "fact_value": {"password": "synthetic", "state": "up"},
        "confidence": 1.0,
        "inferred": False,
        "source": "fixture",
        "observed_at": OLD,
    }
    first = repository.record_observation(**arguments)
    duplicate = repository.record_observation(
        **(arguments | {"fact_value": {"password": "different", "state": "up"}})
    )
    later = repository.record_observation(**(arguments | {"observed_at": NEW}))
    assert duplicate == first
    assert later != first
    rows = repository.connection.execute(
        "SELECT fact_value_json FROM observations ORDER BY id"
    ).fetchall()
    assert len(rows) == 2
    assert json.loads(rows[0][0]) == {"password": REDACTED, "state": "up"}


def test_transaction_rolls_back_and_rejects_nesting(repository: Repository) -> None:
    with pytest.raises(RuntimeError, match="rollback"), repository.transaction():
        repository.connection.execute(
            "INSERT INTO deployments(site_key, display_name, started_at) "
            "VALUES ('rollback', 'Rollback', ?)",
            (OLD,),
        )
        raise RuntimeError("rollback")
    assert (
        repository.connection.execute(
            "SELECT COUNT(*) FROM deployments WHERE site_key = 'rollback'"
        ).fetchone()[0]
        == 0
    )
    with (
        repository.transaction(),
        pytest.raises(RepositoryError, match="nested"),
        repository.transaction(),
    ):
        pass


def test_run_lifecycle_and_interrupted_run_recovery(repository: Repository) -> None:
    deployment_id = deployment(repository)
    completed = repository.start_run(deployment_id, "fixture", OLD)
    repository.finish_run(completed, "succeeded", NEW, 4)
    with pytest.raises(RepositoryError, match="already final"):
        repository.finish_run(completed, "failed", NEW, 0)
    with pytest.raises(RepositoryError, match="final status"):
        repository.finish_run(999, "running", NEW, 0)
    interrupted = repository.start_run(
        deployment_id,
        "passive",
        OLD,
        interface_name="eth0",
        target_cidr="192.168.50.0/24",
    )
    assert repository.recover_interrupted_runs(NEW) == 1
    row = repository.connection.execute(
        "SELECT status, finished_at FROM collector_runs WHERE id = ?", (interrupted,)
    ).fetchone()
    assert tuple(row) == ("failed", NEW)
    error = repository.connection.execute(
        "SELECT category, retryable FROM collector_errors WHERE collector_run_id = ?",
        (interrupted,),
    ).fetchone()
    assert tuple(error) == ("interrupted", 1)
    assert repository.recover_interrupted_runs(NEW) == 0


def test_artifact_digest_tracking_and_input_validation(repository: Repository) -> None:
    deployment_id = deployment(repository)
    run_id = repository.start_run(deployment_id, "nmap", OLD)
    arguments = {
        "deployment_id": deployment_id,
        "collector_run_id": run_id,
        "relative_path": "nmap/fixture.xml",
        "sha256_digest": "a" * 64,
        "media_type": "application/xml",
        "size_bytes": 12,
        "collected_at": OLD,
        "imported_at": NEW,
        "source": "nmap",
        "observed_at": NEW,
    }
    artifact_id, created = repository.register_artifact(**arguments)
    repeated_id, repeated_created = repository.register_artifact(**arguments)
    assert (repeated_id, repeated_created) == (artifact_id, False)
    assert created
    for path in ("/absolute.xml", "../escape.xml", "folder/../escape.xml", "."):
        with pytest.raises(RepositoryError, match="relative path"):
            repository.register_artifact(**(arguments | {"relative_path": path}))
    for digest in ("short", "A" * 64, "z" * 64):
        with pytest.raises(RepositoryError, match="lowercase SHA-256"):
            repository.register_artifact(**(arguments | {"sha256_digest": digest}))


def test_known_secrets_are_redacted_or_rejected_before_persistence(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    repository = Repository.open(
        root / "discovery.db", data_root=root, redactor=Redactor(["synthetic-secret"])
    )
    deployment_id = repository.upsert_deployment(
        "site-synthetic-secret", "Name synthetic-secret", OLD
    )
    row = repository.get_deployment("site-synthetic-secret")
    assert row is not None
    assert "synthetic-secret" not in json.dumps(row)
    with pytest.raises(RepositoryError, match="sensitive data"):
        repository.register_artifact(
            deployment_id=deployment_id,
            collector_run_id=None,
            relative_path="synthetic-secret.xml",
            sha256_digest="d" * 64,
            media_type="application/xml",
            size_bytes=1,
            collected_at=OLD,
            imported_at=None,
            source="fixture",
            observed_at=OLD,
        )
    repository.close()


def test_integrity_and_consistent_backup_restore(repository: Repository) -> None:
    deployment_id = deployment(repository)
    assert repository.integrity_check().ok
    backup_path = repository.data_root / "backup.db"
    assert repository.backup(backup_path) == backup_path
    assert stat.S_IMODE(backup_path.stat().st_mode) == 0o600
    restored = sqlite3.connect(backup_path)
    assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert restored.execute("SELECT id FROM deployments").fetchone()[0] == deployment_id
    restored.close()
    restored_path = repository.data_root / "restored.db"
    assert (
        Repository.restore_backup(backup_path, restored_path, data_root=repository.data_root)
        == restored_path
    )
    assert stat.S_IMODE(restored_path.stat().st_mode) == 0o600
    restored = sqlite3.connect(restored_path)
    assert restored.execute("SELECT id FROM deployments").fetchone()[0] == deployment_id
    restored.close()
    with pytest.raises(UnsafeRepositoryPath, match="new regular file"):
        repository.backup(backup_path)


def test_backup_and_open_refuse_escape_relative_and_symlink_paths(
    repository: Repository, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside.db"
    for path in (outside, Path("relative.db"), repository.data_root / "../escape.db"):
        with pytest.raises(UnsafeRepositoryPath):
            repository.backup(path)
    real_parent = repository.data_root / "real"
    real_parent.mkdir()
    linked_parent = repository.data_root / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(UnsafeRepositoryPath, match="symlinks"):
        repository.backup(linked_parent / "backup.db")
    linked_database = repository.data_root / "linked.db"
    linked_database.symlink_to(repository.database_path)
    with pytest.raises(UnsafeRepositoryPath, match="symlinks"):
        Repository.open(linked_database, data_root=repository.data_root)
    root_link = tmp_path / "root-link"
    root_link.symlink_to(repository.data_root, target_is_directory=True)
    with pytest.raises(UnsafeRepositoryPath, match="real directory"):
        Repository.open(root_link / "new.db", data_root=root_link)
    with pytest.raises(UnsafeRepositoryPath, match="unavailable"):
        Repository.open(tmp_path / "missing" / "new.db", data_root=tmp_path / "missing")
    with pytest.raises(UnsafeRepositoryPath, match="parent does not exist"):
        repository.backup(repository.data_root / "missing" / "backup.db")
    ordinary = repository.data_root / "ordinary"
    ordinary.write_text("not a directory")
    with pytest.raises(UnsafeRepositoryPath, match="parent must be a directory"):
        repository.backup(ordinary / "backup.db")
    blocked = repository.data_root / "blocked"
    blocked.mkdir()
    original_lstat = Path.lstat

    def fail_blocked(path: Path) -> os.stat_result:
        if path == blocked:
            raise PermissionError("fixture")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fail_blocked)
    with pytest.raises(UnsafeRepositoryPath, match="cannot be inspected"):
        repository.backup(blocked / "backup.db")


def test_failed_backup_is_removed(repository: Repository, monkeypatch: pytest.MonkeyPatch) -> None:
    class Source:
        def backup(self, _target: object) -> None:
            pass

    class Target:
        def commit(self) -> None:
            pass

        def close(self) -> None:
            pass

    original = repository.connection
    repository.connection = Source()  # type: ignore[assignment]
    monkeypatch.setattr("field_discovery.repository.sqlite3.connect", lambda _path: Target())
    monkeypatch.setattr(
        "field_discovery.repository._verify_database",
        lambda _target: (_ for _ in ()).throw(RepositoryError("backup integrity check failed")),
    )
    target = repository.data_root / "failed-verification.db"
    with pytest.raises(RepositoryError, match="integrity check failed"):
        repository.backup(target)
    assert not target.exists()
    repository.connection = original


def test_restore_rejects_unsafe_corrupt_foreign_and_future_inputs(
    repository: Repository, tmp_path: Path
) -> None:
    root = repository.data_root
    destination = root / "restored.db"
    outside = tmp_path / "outside.db"
    outside.write_text("fixture")
    with pytest.raises(UnsafeRepositoryPath, match="outside"):
        Repository.restore_backup(outside, destination, data_root=root)
    directory = root / "directory-source"
    directory.mkdir()
    with pytest.raises(UnsafeRepositoryPath, match="regular file"):
        Repository.restore_backup(directory, destination, data_root=root)

    corrupt = root / "corrupt.db"
    corrupt.write_text("not sqlite")
    with pytest.raises((RepositoryError, sqlite3.DatabaseError)):
        Repository.restore_backup(corrupt, destination, data_root=root)
    assert not destination.exists()

    foreign = root / "foreign.db"
    connection = sqlite3.connect(foreign)
    connection.execute("PRAGMA application_id = 1")
    connection.close()
    with pytest.raises(RepositoryError, match="identity"):
        Repository.restore_backup(foreign, destination, data_root=root)

    future = root / "future.db"
    connection = sqlite3.connect(future)
    connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
    connection.execute("PRAGMA user_version = 999")
    connection.close()
    with pytest.raises(RepositoryError, match="schema"):
        Repository.restore_backup(future, destination, data_root=root)

    backup = repository.backup(root / "valid.db")
    linked = root / "linked.db"
    linked.symlink_to(backup)
    with pytest.raises(UnsafeRepositoryPath, match="symlinks"):
        Repository.restore_backup(linked, destination, data_root=root)
    destination.write_text("existing")
    with pytest.raises(UnsafeRepositoryPath, match="new regular"):
        Repository.restore_backup(backup, destination, data_root=root)


def test_restore_cleanup_on_final_sync_failure(
    repository: Repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = repository.backup(repository.data_root / "valid.db")
    destination = repository.data_root / "interrupted.db"
    monkeypatch.setattr(
        "field_discovery.repository.os.fsync",
        lambda _descriptor: (_ for _ in ()).throw(OSError("synthetic sync failure")),
    )
    with pytest.raises(OSError, match="sync failure"):
        Repository.restore_backup(backup, destination, data_root=repository.data_root)
    assert not destination.exists()


def test_backup_cleanup_on_final_sync_failure(
    repository: Repository, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = repository.data_root / "sync-failed.db"
    monkeypatch.setattr(
        "field_discovery.repository.os.fsync",
        lambda _descriptor: (_ for _ in ()).throw(OSError("synthetic sync failure")),
    )
    with pytest.raises(OSError, match="sync failure"):
        repository.backup(destination)
    assert not destination.exists()


def test_database_verifier_rejects_integrity_and_foreign_key_failures() -> None:
    class Rows:
        def __init__(self, values: list[tuple[object, ...]]) -> None:
            self.values = values

        def fetchone(self) -> tuple[object, ...] | None:
            return self.values[0] if self.values else None

        def __iter__(self):  # type: ignore[no-untyped-def]
            return iter(self.values)

    class Connection:
        def __init__(self, *, integrity: str = "ok", foreign_key: bool = False) -> None:
            self.integrity = integrity
            self.foreign_key = foreign_key

        def execute(self, statement: str) -> Rows:
            if statement == "PRAGMA application_id":
                return Rows([(APPLICATION_ID,)])
            if statement == "PRAGMA user_version":
                return Rows([(4,)])
            if statement == "PRAGMA integrity_check":
                return Rows([(self.integrity,)])
            return Rows([("violation",)] if self.foreign_key else [])

    with pytest.raises(RepositoryError, match="integrity"):
        _verify_database(Connection(integrity="damaged"))  # type: ignore[arg-type]
    with pytest.raises(RepositoryError, match="foreign key"):
        _verify_database(Connection(foreign_key=True))  # type: ignore[arg-type]


def test_backup_exception_is_removed(repository: Repository) -> None:
    class Source:
        def backup(self, _target: object) -> None:
            raise RuntimeError("backup failed")

    original = repository.connection
    repository.connection = Source()  # type: ignore[assignment]
    target = repository.data_root / "failed.db"
    with pytest.raises(RuntimeError, match="backup failed"):
        repository.backup(target)
    assert not target.exists()
    repository.connection = original


def test_retention_dry_run_matches_apply_for_each_class(repository: Repository) -> None:
    deployment_id = deployment(repository)
    base_observation = {
        "deployment_id": deployment_id,
        "subject_type": "deployment",
        "subject_id": deployment_id,
        "fact_type": "old",
        "fact_value": True,
        "confidence": 1.0,
        "inferred": False,
        "source": "fixture",
        "observed_at": OLD,
    }
    repository.record_observation(**base_observation)
    repository.record_observation(**(base_observation | {"fact_type": "new", "observed_at": NEW}))
    repository.register_artifact(
        deployment_id=deployment_id,
        collector_run_id=None,
        relative_path="old.xml",
        sha256_digest="b" * 64,
        media_type="application/xml",
        size_bytes=1,
        collected_at=OLD,
        imported_at=OLD,
        source="fixture",
        observed_at=OLD,
    )
    repository.connection.execute(
        "INSERT INTO report_history"
        "(deployment_id, format, relative_path, sha256_digest, document_version, "
        "generated_at, source, observed_at) VALUES (?, 'json', 'old.json', ?, '1', ?, "
        "'fixture', ?)",
        (deployment_id, "c" * 64, OLD, OLD),
    )
    cutoffs = RetentionCutoffs(CUTOFF, CUTOFF, CUTOFF)
    preview = repository.prune(cutoffs)
    assert preview.dry_run
    assert preview.counts["observations"] == 1
    assert preview.counts["artifacts"] == 1
    assert preview.counts["report_history"] == 1
    applied = repository.prune(cutoffs, dry_run=False)
    assert not applied.dry_run
    assert applied.counts == preview.counts
    assert repository.prune(cutoffs).counts == {name: 0 for name in preview.counts}
    assert repository.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 1


def test_sanitized_export_is_deterministic_restrictive_and_confined(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    repository = Repository.open(
        root / "discovery.db",
        data_root=root,
        redactor=Redactor(["synthetic-secret"]),
    )
    run_id = repository.start_run(None, "fixture", OLD)
    repository.connection.execute(
        "INSERT INTO collector_errors"
        "(collector_run_id, category, detail, retryable, source, observed_at) "
        "VALUES (?, 'fixture', 'password=synthetic-secret', 0, 'fixture', ?)",
        (run_id, OLD),
    )
    first = repository.export_sanitized_json(root / "first.json")
    second = repository.export_sanitized_json(root / "second.json")
    assert export_digest(first) == export_digest(second)
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    content = first.read_text()
    assert "synthetic-secret" not in content
    assert REDACTED in content
    assert json.loads(content)["schema_version"] == 4
    with pytest.raises(UnsafeRepositoryPath, match="new regular file"):
        repository.export_sanitized_json(first)
    outside = tmp_path / "outside.json"
    with pytest.raises(UnsafeRepositoryPath, match="outside"):
        repository.export_sanitized_json(outside)
    symlink = root / "linked.json"
    symlink.symlink_to(outside)
    with pytest.raises(UnsafeRepositoryPath, match="symlinks"):
        repository.export_sanitized_json(symlink)
    repository.close()


def test_open_closes_connection_when_migration_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "data"
    root.mkdir()
    connection = sqlite3.connect(":memory:")
    monkeypatch.setattr("field_discovery.repository.open_database", lambda _path: connection)

    def fail(_connection: sqlite3.Connection) -> int:
        raise RuntimeError("migration failed")

    monkeypatch.setattr("field_discovery.repository.migrate", fail)
    with pytest.raises(RuntimeError, match="migration failed"):
        Repository.open(root / "new.db", data_root=root)
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("SELECT 1")
