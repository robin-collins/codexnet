"""T204 restart-safe nmap import timer and packaging checks."""

from __future__ import annotations

import os
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from field_discovery.nmap_import import import_nmap_artifacts
from field_discovery.repository import Repository

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "tests/fixtures/nmap"
SERVICE = ROOT / "packaging/systemd/field-discovery-nmap-import.service"
TIMER = ROOT / "packaging/systemd/field-discovery-nmap-import.timer"
REPORT_DROP_IN = ROOT / "packaging/systemd/optional-report-refresh.conf"
NOW = datetime(2026, 7, 15, 1, 0, tzinfo=UTC)


def _aged_copy(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    timestamp = (NOW - timedelta(minutes=1)).timestamp()
    os.utime(destination, (timestamp, timestamp))
    return destination


def test_repeated_restart_pass_imports_completed_once_and_waits_for_partial(
    tmp_path: Path,
) -> None:
    """Independent passes model timer restart without process-local state."""
    source = tmp_path / "protected-nmap-input"
    complete = _aged_copy(FIXTURES / "success.xml", source / "nested/complete.xml")
    partial = _aged_copy(FIXTURES / "partial.xml", source / "nested/partial.xml")
    data_root = tmp_path / "data"
    data_root.mkdir()
    deployment_key = "monitor-fixture"

    first_repository = Repository.open(data_root / "discovery.db", data_root=data_root)
    deployment_id = first_repository.upsert_deployment(
        deployment_key, "Monitor fixture", NOW.isoformat()
    )
    first = import_nmap_artifacts(
        first_repository,
        source,
        deployment_id=deployment_id,
        stability_seconds=30,
        now=NOW,
    )
    first_repository.close()

    assert (first.discovered, first.imported, first.deferred) == (2, 1, 1)
    assert complete.exists() and partial.exists()

    # A fresh repository/process catches up from durable database state.
    restarted_repository = Repository.open(data_root / "discovery.db", data_root=data_root)
    deployment_id = restarted_repository.upsert_deployment(
        deployment_key, "Monitor fixture", NOW.isoformat()
    )
    second = import_nmap_artifacts(
        restarted_repository,
        source,
        deployment_id=deployment_id,
        stability_seconds=30,
        now=NOW,
    )
    assert (second.imported, second.skipped, second.deferred) == (0, 1, 1)

    # Completion between timer passes is imported on the next pass, and only once.
    completed_xml = (FIXTURES / "success.xml").read_text().replace("1784106004", "1784107004")
    partial.write_text(completed_xml)
    timestamp = (NOW - timedelta(minutes=1)).timestamp()
    os.utime(partial, (timestamp, timestamp))
    third = import_nmap_artifacts(
        restarted_repository,
        source,
        deployment_id=deployment_id,
        stability_seconds=30,
        now=NOW,
    )
    fourth = import_nmap_artifacts(
        restarted_repository,
        source,
        deployment_id=deployment_id,
        stability_seconds=30,
        now=NOW,
    )
    artifact_count = restarted_repository.connection.execute(
        "SELECT COUNT(*) FROM artifacts"
    ).fetchone()[0]
    restarted_repository.close()

    assert (third.imported, third.skipped, third.deferred) == (1, 1, 0)
    assert (fourth.imported, fourth.skipped, fourth.deferred) == (0, 2, 0)
    assert artifact_count == 2


def test_systemd_timer_is_persistent_bounded_and_never_launches_nmap() -> None:
    service = SERVICE.read_text()
    timer = TIMER.read_text()

    assert " import nmap --stability-seconds 30" in service
    assert "scan nmap" not in service
    assert "network-discovery-scan.sh" not in service
    assert "User=field-discovery" in service
    assert "ReadOnlyPaths=/var/log/network-discovery /etc/field-discovery" in service
    assert "ReadWritePaths=/var/lib/field-discovery" in service
    assert "RestrictAddressFamilies=AF_UNIX" in service
    assert "CapabilityBoundingSet=\n" in service
    assert "StartLimitIntervalSec=15min" in service
    assert "StartLimitBurst=5" in service
    assert "TimeoutStartSec=5min" in service

    assert "Persistent=true" in timer
    assert "OnBootSec=2min" in timer
    assert "OnUnitInactiveSec=2min" in timer
    assert "RandomizedDelaySec=30s" in timer
    assert "Unit=field-discovery-nmap-import.service" in timer
    assert "scan" not in timer.casefold()


def test_report_refresh_is_explicit_optional_and_failure_isolated() -> None:
    drop_in = REPORT_DROP_IN.read_text()

    assert "ExecStartPost=-" in drop_in
    assert "report generate --format docx" in drop_in
    assert "scan nmap" not in drop_in
    assert "network-discovery-scan.sh" not in drop_in
