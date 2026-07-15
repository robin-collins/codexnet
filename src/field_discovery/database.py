"""SQLite connection and transactional numbered schema migrations."""

from __future__ import annotations

import hashlib
import importlib.resources
import os
import sqlite3
import stat
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

APPLICATION_ID = 0x434E4554  # "CNET"
BUSY_TIMEOUT_MS = 5_000
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class MigrationError(RuntimeError):
    """The database migration history is unsafe or cannot be advanced."""


@dataclass(frozen=True, order=True)
class Migration:
    """An immutable numbered migration and its source checksum."""

    version: int
    name: str
    sql: str

    @property
    def checksum(self) -> str:
        """Return a stable digest used to detect edited released migrations."""
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


def available_migrations() -> tuple[Migration, ...]:
    """Load packaged migrations in strict numeric order on explicit request."""
    directory = importlib.resources.files("field_discovery").joinpath("migrations")
    migrations: list[Migration] = []
    for resource in sorted(directory.iterdir(), key=lambda item: item.name):
        if resource.name.endswith(".sql"):
            prefix, separator, name = resource.name[:-4].partition("_")
            if not separator or not prefix.isdigit() or not name:
                raise MigrationError(f"invalid migration filename: {resource.name}")
            migrations.append(Migration(int(prefix), name, resource.read_text(encoding="utf-8")))
    _validate_migration_set(migrations)
    return tuple(migrations)


def open_database(path: Path) -> sqlite3.Connection:
    """Open a database with required safety pragmas; no migration is implicit."""
    if str(path) != ":memory:":
        try:
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | _NOFOLLOW, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise MigrationError("database path is not a regular file")
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise MigrationError("database path cannot be opened safely") from exc
    connection = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1_000, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).casefold()
    if mode != "wal":
        connection.close()
        raise MigrationError(f"SQLite refused WAL journal mode (reported {mode})")
    if str(path) != ":memory:":
        try:
            for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
                if candidate.exists():
                    candidate.chmod(0o600, follow_symlinks=False)
        except OSError as exc:
            connection.close()
            raise MigrationError("database files cannot be restricted") from exc
    return connection


def migrate(connection: sqlite3.Connection, migrations: Iterable[Migration] | None = None) -> int:
    """Transactionally apply every unapplied migration and return schema version."""
    selected = tuple(available_migrations() if migrations is None else migrations)
    _validate_migration_set(selected)
    try:
        _bootstrap_history(connection)
        applied = {
            int(row["version"]): (str(row["name"]), str(row["checksum"]))
            for row in connection.execute(
                "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
            )
        }
    except sqlite3.Error as exc:
        raise MigrationError("cannot read migration history") from exc
    known_versions = {migration.version for migration in selected}
    unknown = sorted(set(applied) - known_versions)
    if unknown:
        raise MigrationError(f"database contains unknown migration version {unknown[0]}")
    if sorted(applied) != list(range(1, len(applied) + 1)):
        raise MigrationError("database migration history is not contiguous")
    for migration in selected:
        previous = applied.get(migration.version)
        if previous is not None:
            if previous != (migration.name, migration.checksum):
                raise MigrationError(f"migration {migration.version} checksum or name mismatch")
            continue
        _apply_one(connection, migration)
    return selected[-1].version if selected else 0


def _validate_migration_set(migrations: Iterable[Migration]) -> None:
    selected = tuple(migrations)
    expected = list(range(1, len(selected) + 1))
    actual = [migration.version for migration in selected]
    if actual != expected:
        raise MigrationError("migrations must be ordered, unique, and contiguous from version 1")
    if any(not migration.name or not migration.sql.strip() for migration in selected):
        raise MigrationError("migration name and SQL must not be empty")


def _bootstrap_history(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL CHECK(length(checksum) = 64),
            applied_at TEXT NOT NULL
        )
        """
    )


def _sql_statements(script: str) -> Iterator[str]:
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            yield statement
            buffer = ""
    if buffer.strip():
        raise MigrationError("migration ends with an incomplete SQL statement")


def _apply_one(connection: sqlite3.Connection, migration: Migration) -> None:
    try:
        connection.execute("BEGIN IMMEDIATE")
        for statement in _sql_statements(migration.sql):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at) "
            "VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            (migration.version, migration.name, migration.checksum),
        )
        connection.execute(f"PRAGMA user_version = {migration.version}")
        connection.commit()
    except (sqlite3.Error, MigrationError) as exc:
        connection.rollback()
        raise MigrationError(f"migration {migration.version} ({migration.name}) failed") from exc
