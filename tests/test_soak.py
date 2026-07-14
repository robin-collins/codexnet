"""T605 accelerated multi-day replay and resource-budget tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from field_discovery.diagnostics import DiagnosticCheck
from field_discovery.soak import SoakBudget, run_accelerated_soak

ROOT = Path(__file__).parents[1]
NMAP = ROOT / "tests/fixtures/nmap/success.xml"
PASSIVE = ROOT / "tests/fixtures/passive/link-layer.json"
SCRIPT = ROOT / "scripts/run_t605_soak.py"


def protected() -> tuple[DiagnosticCheck, ...]:
    return (
        DiagnosticCheck("nmap_script", "coexistence", "ok", "baseline", {}),
        DiagnosticCheck("nmap_schedule", "coexistence", "ok", "absent", {}),
        DiagnosticCheck("scanopy", "coexistence", "ok", "healthy", {}),
    )


def test_accelerated_soak_is_bounded_isolated_and_restart_safe(tmp_path: Path) -> None:
    before = hashlib.sha256(NMAP.read_bytes()).hexdigest()
    result = run_accelerated_soak(
        tmp_path,
        days=2,
        cycles_per_day=3,
        nmap_fixture=NMAP,
        passive_fixture=PASSIVE,
        protected_probe=protected,
    )
    assert result.passed and result.violations == ()
    assert result.schema_version == 1 and result.nmap_imported == 2
    assert result.collector_runs == 13 and result.collector_failures == 2
    assert result.isolated_outages == result.recovered_outages == 2
    assert result.interrupted_runs_recovered == result.transaction_rollbacks == 1
    assert result.passive_submitted == 24 and result.passive_emitted == 8
    assert result.passive_queue_peak <= 256
    assert result.passive_final_depth == result.passive_final_in_flight == 0
    assert result.passive_incomplete == 0 and result.running_runs == 0
    assert result.integrity_ok and result.log_files == 0
    assert result.report_files == 4 and result.report_max_bytes < 5 * 1024 * 1024
    assert result.protected_unchanged and result.protected_before == result.protected_after
    assert result.as_dict()["database_growth_per_day"] == result.database_growth_per_day
    assert hashlib.sha256(NMAP.read_bytes()).hexdigest() == before


def test_soak_validates_inputs_and_reports_budget_and_baseline_failures(tmp_path: Path) -> None:
    for days, cycles in ((0, 2), (1, 1)):
        with pytest.raises(ValueError, match="soak days"):
            run_accelerated_soak(
                tmp_path,
                days=days,
                cycles_per_day=cycles,
                nmap_fixture=NMAP,
                passive_fixture=PASSIVE,
            )

    calls = 0

    def changed() -> tuple[DiagnosticCheck, ...]:
        nonlocal calls
        calls += 1
        status = "ok" if calls == 1 else "error"
        return (DiagnosticCheck("scanopy", "coexistence", status, status, {}),)

    result = run_accelerated_soak(
        tmp_path / "tight",
        days=1,
        cycles_per_day=2,
        nmap_fixture=NMAP,
        passive_fixture=PASSIVE,
        budget=SoakBudget(
            peak_rss_bytes=1,
            peak_python_bytes=1,
            passive_queue_peak=1,
            passive_retained_bytes=1,
            report_seconds=0,
            report_bytes=1,
            projected_30_day_database_bytes=1,
        ),
        protected_probe=changed,
    )
    assert not result.passed
    assert "protected appliance state changed" in result.violations
    assert "peak RSS exceeded budget" in result.violations
    assert "report size exceeded budget" in result.violations


def test_subprocess_harness_emits_machine_readable_result() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--days",
            "1",
            "--cycles-per-day",
            "2",
            "--skip-protected-probe",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    payload = json.loads(completed.stdout)
    assert completed.returncode == 0
    assert payload["passed"] is True and payload["days"] == 1
