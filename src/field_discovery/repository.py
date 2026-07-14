"""Transactional normalized repository and confined maintenance operations."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, cast

from field_discovery.database import migrate, open_database
from field_discovery.redaction import Redactor

_FINAL_RUN_STATES = frozenset({"succeeded", "partial", "failed", "cancelled"})
_DETAIL_TABLES = (
    ("observations", "observed_at"),
    ("collector_errors", "observed_at"),
    ("software_observations", "observed_at"),
    ("infrastructure_readings", "observed_at"),
    ("topology_edges", "observed_at"),
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class RepositoryError(RuntimeError):
    """A repository operation was invalid or unsafe."""


class UnsafeRepositoryPath(RepositoryError):
    """A maintenance path escaped its configured real directory."""


@dataclass(frozen=True)
class IntegrityResult:
    """SQLite integrity and foreign-key check result."""

    integrity: tuple[str, ...]
    foreign_key_violations: tuple[dict[str, Any], ...]

    @property
    def ok(self) -> bool:
        return self.integrity == ("ok",) and not self.foreign_key_violations


@dataclass(frozen=True)
class RetentionCutoffs:
    """Exclusive UTC ISO-8601 cutoffs for independent retention classes."""

    detailed_before: str
    artifacts_before: str
    reports_before: str


@dataclass(frozen=True)
class PruneResult:
    """Rows selected or removed by retention class."""

    dry_run: bool
    counts: dict[str, int]


def _confined(root: Path, target: Path, *, allow_missing_leaf: bool) -> Path:
    if not root.is_absolute() or not target.is_absolute():
        raise UnsafeRepositoryPath("repository paths must be absolute")
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise UnsafeRepositoryPath("configured data root is unavailable") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise UnsafeRepositoryPath("configured data root must be a real directory")
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise UnsafeRepositoryPath("path is outside configured data root") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise UnsafeRepositoryPath("path is outside configured data root")
    current = root
    for index, component in enumerate(relative.parts):
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError:
            if allow_missing_leaf and index == len(relative.parts) - 1:
                return current
            raise UnsafeRepositoryPath("repository path parent does not exist") from None
        except OSError as exc:
            raise UnsafeRepositoryPath("repository path cannot be inspected") from exc
        if stat.S_ISLNK(info.st_mode):
            raise UnsafeRepositoryPath("repository paths must not contain symlinks")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise UnsafeRepositoryPath("repository path parent must be a directory")
    return current


class Repository:
    """Own transactional access to one migrated SQLite database."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_path: Path,
        data_root: Path,
        redactor: Redactor | None = None,
    ) -> None:
        self.connection = connection
        self.data_root = data_root
        self.database_path = _confined(data_root, database_path, allow_missing_leaf=False)
        self.redactor = redactor or Redactor()

    @classmethod
    def open(
        cls, database_path: Path, *, data_root: Path, redactor: Redactor | None = None
    ) -> Repository:
        """Open and migrate a link-safe database below the configured data root."""
        _confined(data_root, database_path, allow_missing_leaf=True)
        connection = open_database(database_path)
        try:
            migrate(connection)
            return cls(
                connection,
                database_path=database_path,
                data_root=data_root,
                redactor=redactor,
            )
        except Exception:
            connection.close()
            raise

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Commit one unit atomically, rolling back every exception."""
        if self.connection.in_transaction:
            raise RepositoryError("nested repository transactions are not supported")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            yield
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def upsert_deployment(self, site_key: str, display_name: str, started_at: str) -> int:
        site_key = self.redactor.text(site_key)
        display_name = self.redactor.text(display_name)
        with self.transaction():
            self.connection.execute(
                "INSERT INTO deployments(site_key, display_name, started_at) VALUES (?, ?, ?) "
                "ON CONFLICT(site_key) DO UPDATE SET display_name = excluded.display_name",
                (site_key, display_name, started_at),
            )
            row = self.connection.execute(
                "SELECT id FROM deployments WHERE site_key = ?", (site_key,)
            ).fetchone()
        return int(row[0])

    def get_deployment(self, site_key: str) -> dict[str, Any] | None:
        """Read one deployment by its redacted stable key."""
        row = self.connection.execute(
            "SELECT * FROM deployments WHERE site_key = ?", (self.redactor.text(site_key),)
        ).fetchone()
        return None if row is None else dict(row)

    def upsert_device(self, deployment_id: int, canonical_key: str, created_at: str) -> int:
        canonical_key = self.redactor.text(canonical_key)
        with self.transaction():
            self.connection.execute(
                "INSERT INTO devices(deployment_id, canonical_key, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(deployment_id, canonical_key) DO NOTHING",
                (deployment_id, canonical_key, created_at),
            )
            row = self.connection.execute(
                "SELECT id FROM devices WHERE deployment_id = ? AND canonical_key = ?",
                (deployment_id, canonical_key),
            ).fetchone()
        return int(row[0])

    def get_device(self, device_id: int) -> dict[str, Any] | None:
        """Read one canonical device without synthesizing missing data."""
        row = self.connection.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return None if row is None else dict(row)

    def record_observation(
        self,
        deployment_id: int,
        *,
        subject_type: str,
        subject_id: int | None,
        fact_type: str,
        fact_value: Any,
        confidence: float,
        inferred: bool,
        source: str,
        observed_at: str,
    ) -> int:
        """Insert an exact fact once while preserving observations at new times."""
        subject_type = self.redactor.text(subject_type)
        fact_type = self.redactor.text(fact_type)
        source = self.redactor.text(source)
        value_json = json.dumps(
            self.redactor.value(fact_value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        parameters = (
            deployment_id,
            subject_type,
            subject_id,
            fact_type,
            value_json,
            confidence,
            int(inferred),
            source,
            observed_at,
        )
        with self.transaction():
            self.connection.execute(
                "INSERT OR IGNORE INTO observations"
                "(deployment_id, subject_type, subject_id, fact_type, fact_value_json, "
                "confidence, inferred, source, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                parameters,
            )
            row = self.connection.execute(
                "SELECT id FROM observations WHERE deployment_id = ? AND subject_type = ? "
                "AND subject_id IS ? AND fact_type = ? AND fact_value_json = ? AND source = ? "
                "AND observed_at = ? AND confidence = ? AND inferred = ?",
                (
                    deployment_id,
                    subject_type,
                    subject_id,
                    fact_type,
                    value_json,
                    source,
                    observed_at,
                    confidence,
                    int(inferred),
                ),
            ).fetchone()
        return int(row[0])

    def start_run(
        self,
        deployment_id: int | None,
        collector: str,
        started_at: str,
        *,
        interface_name: str | None = None,
        target_cidr: str | None = None,
    ) -> int:
        collector = self.redactor.text(collector)
        interface_name = None if interface_name is None else self.redactor.text(interface_name)
        target_cidr = None if target_cidr is None else self.redactor.text(target_cidr)
        with self.transaction():
            cursor = self.connection.execute(
                "INSERT INTO collector_runs"
                "(deployment_id, collector, status, interface_name, target_cidr, started_at) "
                "VALUES (?, ?, 'running', ?, ?, ?)",
                (deployment_id, collector, interface_name, target_cidr, started_at),
            )
        return cast(int, cursor.lastrowid)

    def finish_run(self, run_id: int, status: str, finished_at: str, item_count: int) -> None:
        if status not in _FINAL_RUN_STATES:
            raise RepositoryError("collector run final status is invalid")
        with self.transaction():
            cursor = self.connection.execute(
                "UPDATE collector_runs SET status = ?, finished_at = ?, item_count = ? "
                "WHERE id = ? AND status = 'running'",
                (status, finished_at, item_count, run_id),
            )
            if cursor.rowcount != 1:
                raise RepositoryError("collector run is missing or already final")

    def recover_interrupted_runs(self, observed_at: str) -> int:
        """Mark unfinished runs failed and retain an explicit interruption error."""
        with self.transaction():
            running = self.connection.execute(
                "SELECT id, collector FROM collector_runs WHERE status = 'running' ORDER BY id"
            ).fetchall()
            for row in running:
                self.connection.execute(
                    "INSERT INTO collector_errors"
                    "(collector_run_id, category, detail, retryable, source, observed_at) "
                    "VALUES (?, 'interrupted', 'run ended before completion', 1, ?, ?)",
                    (row["id"], row["collector"], observed_at),
                )
            self.connection.execute(
                "UPDATE collector_runs SET status = 'failed', finished_at = ? "
                "WHERE status = 'running'",
                (observed_at,),
            )
        return len(running)

    def register_artifact(
        self,
        *,
        deployment_id: int | None,
        collector_run_id: int | None,
        relative_path: str,
        sha256_digest: str,
        media_type: str,
        size_bytes: int,
        collected_at: str,
        imported_at: str | None,
        source: str,
        observed_at: str,
    ) -> tuple[int, bool]:
        path = PurePosixPath(relative_path)
        if (
            path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise RepositoryError("artifact path must be a confined relative path")
        if self.redactor.text(relative_path) != relative_path:
            raise RepositoryError("artifact path contains sensitive data")
        source = self.redactor.text(source)
        if len(sha256_digest) != 64 or any(
            character not in "0123456789abcdef" for character in sha256_digest
        ):
            raise RepositoryError("artifact digest must be lowercase SHA-256")
        with self.transaction():
            cursor = self.connection.execute(
                "INSERT OR IGNORE INTO artifacts"
                "(deployment_id, collector_run_id, relative_path, sha256_digest, media_type, "
                "size_bytes, collected_at, imported_at, source, observed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    deployment_id,
                    collector_run_id,
                    relative_path,
                    sha256_digest,
                    media_type,
                    size_bytes,
                    collected_at,
                    imported_at,
                    source,
                    observed_at,
                ),
            )
            created = cursor.rowcount == 1
            row = self.connection.execute(
                "SELECT id FROM artifacts WHERE relative_path = ? AND sha256_digest = ?",
                (relative_path, sha256_digest),
            ).fetchone()
        return int(row[0]), created

    def integrity_check(self) -> IntegrityResult:
        integrity = tuple(str(row[0]) for row in self.connection.execute("PRAGMA integrity_check"))
        foreign_keys = tuple(
            dict(row) for row in self.connection.execute("PRAGMA foreign_key_check")
        )
        return IntegrityResult(integrity, foreign_keys)

    def backup(self, destination: Path) -> Path:
        """Create a consistent 0600 SQLite backup at a new confined path."""
        target_path = _confined(self.data_root, destination, allow_missing_leaf=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW
        try:
            descriptor = os.open(target_path, flags, 0o600)
        except OSError as exc:
            raise UnsafeRepositoryPath("backup destination must be a new regular file") from exc
        os.close(descriptor)
        target = sqlite3.connect(target_path)
        try:
            self.connection.backup(target)
            result = target.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                raise RepositoryError("backup integrity check failed")
            target.commit()
        except Exception:
            target.close()
            with suppress(OSError):
                target_path.unlink()
            raise
        target.close()
        return target_path

    def prune(self, cutoffs: RetentionCutoffs, *, dry_run: bool = True) -> PruneResult:
        """Count or delete expired rows; dry-run is the non-destructive default."""
        targets = (
            *_DETAIL_TABLES,
            ("artifacts", "observed_at"),
            ("report_history", "generated_at"),
        )
        counts: dict[str, int] = {}
        with self.transaction():
            for table, time_column in targets:
                cutoff = (
                    cutoffs.artifacts_before
                    if table == "artifacts"
                    else cutoffs.reports_before
                    if table == "report_history"
                    else cutoffs.detailed_before
                )
                count = self.connection.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {time_column} < ?", (cutoff,)
                ).fetchone()[0]
                counts[table] = int(count)
                if not dry_run:
                    self.connection.execute(
                        f"DELETE FROM {table} WHERE {time_column} < ?", (cutoff,)
                    )
        return PruneResult(dry_run, counts)

    def export_sanitized_json(self, destination: Path) -> Path:
        """Atomically write a deterministic, structurally redacted database export."""
        target_path = _confined(self.data_root, destination, allow_missing_leaf=True)
        tables = [
            str(row[0])
            for row in self.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        payload = {
            "schema_version": int(self.connection.execute("PRAGMA user_version").fetchone()[0]),
            "tables": {
                table: [
                    self.redactor.value(dict(row))
                    for row in self.connection.execute(f'SELECT * FROM "{table}" ORDER BY rowid')
                ]
                for table in tables
            },
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        temporary = self.data_root / f".export-{uuid.uuid4().hex}"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, target_path, follow_symlinks=False)
            except OSError as exc:
                raise UnsafeRepositoryPath("export destination must be a new regular file") from exc
        finally:
            with suppress(OSError):
                temporary.unlink()
        return target_path


def export_digest(path: Path) -> str:
    """Return the digest of an export without changing repository state."""
    return hashlib.sha256(path.read_bytes()).hexdigest()
