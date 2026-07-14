"""Migration, schema integrity, and provenance contract tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from field_discovery import database
from field_discovery.database import Migration, MigrationError

EXPECTED_TABLES = {
    "ad_domains",
    "ad_entities",
    "ad_relationships",
    "address_assignments",
    "artifacts",
    "collector_errors",
    "collector_runs",
    "correlation_decisions",
    "deployments",
    "device_aliases",
    "devices",
    "infrastructure_readings",
    "interface_vlan_observations",
    "interfaces",
    "observations",
    "report_history",
    "schema_migrations",
    "services",
    "software_observations",
    "subnets",
    "topology_edges",
    "vlans",
}

OBSERVED_TABLES = EXPECTED_TABLES - {
    "deployments",
    "devices",
    "collector_runs",
    "schema_migrations",
}
FORBIDDEN_COLUMN_PARTS = {
    "api_key",
    "auth_key",
    "community",
    "cookie",
    "credential",
    "hash",
    "passphrase",
    "password",
    "private_key",
    "secret",
    "ticket",
    "token",
}


@pytest.fixture
def connection(tmp_path: Path) -> sqlite3.Connection:
    result = database.open_database(tmp_path / "discovery.db")
    yield result
    result.close()


def columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in connection.execute(f'PRAGMA table_info("{table}")')}


def test_packaged_migrations_are_numbered_and_immutable() -> None:
    migrations = database.available_migrations()
    assert [item.version for item in migrations] == [1, 2, 3]
    assert [item.name for item in migrations] == [
        "core_inventory",
        "directory_infrastructure_reports",
        "repository_idempotency",
    ]
    assert all(len(item.checksum) == 64 for item in migrations)
    assert migrations == database.available_migrations()


def test_empty_database_migrates_to_latest_and_rerun_is_safe(
    connection: sqlite3.Connection,
) -> None:
    assert database.migrate(connection) == 3
    first_history = connection.execute(
        "SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version"
    ).fetchall()
    assert len(first_history) == 3
    assert database.migrate(connection) == 3
    assert (
        connection.execute("SELECT * FROM schema_migrations ORDER BY version").fetchall()
        == first_history
    )
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    assert tables == EXPECTED_TABLES
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
    assert connection.execute("PRAGMA application_id").fetchone()[0] == database.APPLICATION_ID


def test_connection_enforces_wal_foreign_keys_and_integrity(
    connection: sqlite3.Connection,
) -> None:
    database.migrate(connection)
    assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == database.BUSY_TIMEOUT_MS
    assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO devices(deployment_id, canonical_key, created_at) VALUES (999, 'x', 't')"
        )


def test_observed_facts_require_source_and_time_and_schema_has_no_secret_columns(
    connection: sqlite3.Connection,
) -> None:
    database.migrate(connection)
    for table in OBSERVED_TABLES:
        table_columns = columns(connection, table)
        assert {"source", "observed_at"} <= table_columns, table
    all_columns = {
        column.casefold() for table in EXPECTED_TABLES for column in columns(connection, table)
    }
    assert not {
        column for column in all_columns if any(part in column for part in FORBIDDEN_COLUMN_PARTS)
    }


def test_schema_accepts_historical_facts_and_preserves_distinct_observations(
    connection: sqlite3.Connection,
) -> None:
    database.migrate(connection)
    deployment_id = connection.execute(
        "INSERT INTO deployments(site_key, display_name, started_at) "
        "VALUES ('fixture', 'Fixture', '2026-01-01T00:00:00Z') RETURNING id"
    ).fetchone()[0]
    device_id = connection.execute(
        "INSERT INTO devices(deployment_id, canonical_key, created_at) "
        "VALUES (?, 'mac:001122334455', '2026-01-01T00:00:00Z') RETURNING id",
        (deployment_id,),
    ).fetchone()[0]
    for observed_at, value in (("2026-01-01T01:00:00Z", "1.0"), ("2026-01-02T01:00:00Z", "1.1")):
        connection.execute(
            "INSERT INTO software_observations"
            "(device_id, software_kind, product, version, source, observed_at) "
            "VALUES (?, 'firmware', 'FixtureOS', ?, 'fixture', ?)",
            (device_id, value, observed_at),
        )
    assert [
        row[0]
        for row in connection.execute(
            "SELECT version FROM software_observations ORDER BY observed_at"
        )
    ] == ["1.0", "1.1"]
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            "INSERT INTO software_observations"
            "(device_id, software_kind, source, observed_at) "
            "VALUES (?, 'firmware', NULL, '2026-01-03T00:00:00Z')",
            (device_id,),
        )


def test_failed_migration_rolls_back_schema_and_history(connection: sqlite3.Connection) -> None:
    broken = Migration(
        1,
        "broken",
        "CREATE TABLE should_rollback(id INTEGER PRIMARY KEY);\nTHIS IS NOT SQL;\n",
    )
    with pytest.raises(MigrationError, match=r"migration 1 \(broken\) failed"):
        database.migrate(connection, [broken])
    assert (
        connection.execute(
            "SELECT name FROM sqlite_schema WHERE name = 'should_rollback'"
        ).fetchone()
        is None
    )
    assert connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 0


def test_history_guards_unknown_and_changed_migrations(connection: sqlite3.Connection) -> None:
    migrations = database.available_migrations()
    database.migrate(connection, migrations)
    connection.execute(
        "INSERT INTO schema_migrations(version, name, checksum, applied_at) "
        "VALUES (99, 'future', ?, 'now')",
        ("0" * 64,),
    )
    with pytest.raises(MigrationError, match="unknown migration version 99"):
        database.migrate(connection, migrations)
    connection.execute("DELETE FROM schema_migrations WHERE version = 99")
    connection.execute("UPDATE schema_migrations SET name = 'edited' WHERE version = 1")
    with pytest.raises(MigrationError, match="checksum or name mismatch"):
        database.migrate(connection, migrations)


def test_history_guards_gaps_and_malformed_history(tmp_path: Path) -> None:
    migrations = database.available_migrations()
    connection = database.open_database(tmp_path / "gap.db")
    database.migrate(connection, [])
    connection.execute(
        "INSERT INTO schema_migrations(version, name, checksum, applied_at) "
        "VALUES (2, ?, ?, 'now')",
        (migrations[1].name, migrations[1].checksum),
    )
    with pytest.raises(MigrationError, match="history is not contiguous"):
        database.migrate(connection, migrations)
    connection.close()

    malformed = database.open_database(tmp_path / "malformed.db")
    malformed.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY)")
    with pytest.raises(MigrationError, match="cannot read migration history"):
        database.migrate(malformed, migrations)
    malformed.close()


@pytest.mark.parametrize(
    "migrations",
    [
        [Migration(2, "late", "SELECT 1;")],
        [Migration(1, "one", "SELECT 1;"), Migration(1, "again", "SELECT 1;")],
        [Migration(1, "", "SELECT 1;")],
        [Migration(1, "empty", "")],
    ],
)
def test_invalid_migration_sets_are_rejected(migrations: list[Migration]) -> None:
    with pytest.raises(MigrationError):
        database._validate_migration_set(migrations)


def test_empty_migration_set_and_incomplete_sql(connection: sqlite3.Connection) -> None:
    assert database.migrate(connection, []) == 0
    incomplete = Migration(1, "incomplete", "CREATE TABLE incomplete(id INTEGER)")
    with pytest.raises(MigrationError, match="failed") as caught:
        database.migrate(connection, [incomplete])
    assert isinstance(caught.value.__cause__, MigrationError)


def test_invalid_packaged_filename_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "migrations"
    directory.mkdir()
    (directory / "bad.sql").write_text("SELECT 1;")
    monkeypatch.setattr(database.importlib.resources, "files", lambda _package: tmp_path)
    with pytest.raises(MigrationError, match="invalid migration filename"):
        database.available_migrations()


def test_wal_refusal_closes_connection() -> None:
    with pytest.raises(MigrationError, match="refused WAL"):
        database.open_database(Path(":memory:"))
