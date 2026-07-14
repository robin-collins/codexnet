"""Fixture-only accelerated soak and failure-isolation harness."""

from __future__ import annotations

import asyncio
import json
import os
import resource
import shutil
import time
import tracemalloc
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from field_discovery.artifacts import ArtifactStore
from field_discovery.collectors import (
    CollectorContext,
    CollectorOrchestrator,
    CollectorRequest,
    CollectorResult,
    RetryableCollectorError,
)
from field_discovery.diagnostics import DiagnosticCheck
from field_discovery.nmap_import import import_nmap_artifacts
from field_discovery.passive_service import _repository_sink, build_runtime
from field_discovery.reporting import generate_reports
from field_discovery.repository import Repository


@dataclass(frozen=True)
class SoakBudget:
    peak_rss_bytes: int = 512 * 1024 * 1024
    peak_python_bytes: int = 128 * 1024 * 1024
    passive_queue_peak: int = 256
    passive_retained_bytes: int = 2_359_296
    report_seconds: float = 10.0
    report_bytes: int = 5 * 1024 * 1024
    projected_30_day_database_bytes: int = 128 * 1024 * 1024


DEFAULT_BUDGET = SoakBudget()


@dataclass(frozen=True)
class SoakResult:
    schema_version: int
    days: int
    cycles_per_day: int
    cpu_seconds: float
    wall_seconds: float
    peak_rss_bytes: int
    peak_python_bytes: int
    database_bytes: int
    database_growth_per_day: int
    projected_30_day_database_bytes: int
    data_root_bytes: int
    report_max_seconds: float
    report_max_bytes: int
    report_files: int
    collector_runs: int
    collector_failures: int
    isolated_outages: int
    recovered_outages: int
    interrupted_runs_recovered: int
    transaction_rollbacks: int
    passive_submitted: int
    passive_emitted: int
    passive_parser_failures: int
    passive_queue_peak: int
    passive_final_depth: int
    passive_final_in_flight: int
    passive_incomplete: int
    passive_retained_bytes: int
    nmap_imported: int
    artifact_files: int
    log_files: int
    integrity_ok: bool
    running_runs: int
    protected_before: tuple[dict[str, object], ...]
    protected_after: tuple[dict[str, object], ...]
    protected_unchanged: bool
    violations: tuple[str, ...]
    passed: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


ProtectedProbe = Callable[[], Sequence[DiagnosticCheck]]


class _SyntheticCollector:
    def __init__(
        self,
        name: str,
        repository: Repository,
        deployment_id: int,
        artifacts: ArtifactStore,
        cycle: list[int],
        clock: Callable[[], datetime],
        outage_cycles: set[int],
    ) -> None:
        self.name = name
        self.repository = repository
        self.deployment_id = deployment_id
        self.artifacts = artifacts
        self.cycle = cycle
        self.clock = clock
        self.outage_cycles = outage_cycles

    async def collect(self, context: CollectorContext) -> CollectorResult:
        current = self.cycle[0]
        if current in self.outage_cycles:
            raise RetryableCollectorError("synthetic endpoint unavailable")
        observed = self.clock()
        self.repository.record_observation(
            self.deployment_id,
            subject_type="soak_collector",
            subject_id=None,
            fact_type=f"soak.{self.name}",
            fact_value={"cycle": current, "target": context.target},
            confidence=1.0,
            inferred=False,
            source=self.name,
            observed_at=observed.isoformat(),
        )
        self.artifacts.write_json(
            f"{self.name}-{current:05d}.json",
            {"cycle": current, "status": "ok"},
            category="soak",
            retention=timedelta(days=30),
            now=observed,
        )
        return CollectorResult(1)


def _tree_bytes(root: Path) -> int:
    return sum(item.stat().st_size for item in root.rglob("*") if item.is_file())


def _snapshot(probe: ProtectedProbe | None) -> tuple[dict[str, object], ...]:
    return () if probe is None else tuple(item.as_dict() for item in probe())


def _database_bytes(repository: Repository) -> int:
    page_count = int(repository.connection.execute("PRAGMA page_count").fetchone()[0])
    page_size = int(repository.connection.execute("PRAGMA page_size").fetchone()[0])
    return page_count * page_size


async def _run_days(
    root: Path,
    *,
    days: int,
    cycles_per_day: int,
    start: datetime,
    nmap_fixture: Path,
    passive_fixtures: Mapping[str, Mapping[str, object]],
) -> dict[str, Any]:
    data_root = root / "data"
    data_root.mkdir(mode=0o700, parents=True)
    nmap_root = root / "nmap-input"
    nmap_root.mkdir()
    artifact_root = data_root / "artifacts" / "soak"
    artifact_root.mkdir(parents=True, mode=0o700)
    artifacts = ArtifactStore(artifact_root, max_bytes=1024)
    database_path = data_root / "discovery.db"
    repository = Repository.open(database_path, data_root=data_root)
    deployment_id = repository.upsert_deployment("soak", "Synthetic Soak", start.isoformat())
    initial_database_bytes = _database_bytes(repository)
    passive_totals = {
        "submitted": 0,
        "emitted": 0,
        "parser_failures": 0,
        "queue_peak": 0,
        "incomplete": 0,
        "retained": 0,
        "final_depth": 0,
        "final_in_flight": 0,
    }
    collector_failures = isolated_outages = recovered_outages = imported = recovered = rollbacks = 0
    report_times: list[float] = []
    report_sizes: list[int] = []
    cycle = [0]
    clock = [start]

    for day in range(days):
        runtime = build_runtime(_repository_sink(repository, deployment_id))
        await runtime.pipeline.start()
        stable = _SyntheticCollector(
            "stable", repository, deployment_id, artifacts, cycle, lambda: clock[0], set()
        )
        recovering = _SyntheticCollector(
            "recovering",
            repository,
            deployment_id,
            artifacts,
            cycle,
            lambda: clock[0],
            {day * cycles_per_day},
        )
        orchestrator = CollectorOrchestrator(
            repository=repository,
            deployment_id=deployment_id,
            approved_ranges=("192.0.2.0/24",),
            collectors={"stable": stable, "recovering": recovering},
            concurrency=2,
            timeout_seconds=2,
            retries=0,
            clock=lambda: clock[0],
        )
        for hour in range(cycles_per_day):
            cycle[0] = day * cycles_per_day + hour
            clock[0] = start + timedelta(days=day, hours=hour)
            for fixture in passive_fixtures.values():
                await runtime.pipeline.submit(
                    str(fixture["protocol"]),
                    bytes.fromhex(str(fixture["payload_hex"])),
                    observed_at=clock[0],
                    interface="fixture0",
                )
            summaries = await orchestrator.run(
                (
                    CollectorRequest("stable", "192.0.2.10"),
                    CollectorRequest("recovering", "192.0.2.11"),
                )
            )
            stable_summary, recovering_summary = summaries
            if recovering_summary.status == "failed":
                collector_failures += 1
                isolated_outages += int(stable_summary.status == "succeeded")
            elif hour == 1 and recovering_summary.status == "succeeded":
                recovered_outages += 1
        metrics = await runtime.pipeline.stop()
        passive_totals["submitted"] += metrics.submitted_frames
        passive_totals["emitted"] += metrics.emitted_observations
        passive_totals["parser_failures"] += metrics.parser_failures
        passive_totals["queue_peak"] = max(passive_totals["queue_peak"], metrics.queue_peak)
        passive_totals["incomplete"] += metrics.incomplete_frames
        passive_totals["retained"] = max(
            passive_totals["retained"], runtime.pipeline.retained_payload_capacity
        )
        passive_totals["final_depth"] = metrics.queue_depth
        passive_totals["final_in_flight"] = metrics.in_flight

        artifact = nmap_root / f"day-{day:03d}.xml"
        shutil.copyfile(nmap_fixture, artifact)
        aged = (clock[0] - timedelta(minutes=1)).timestamp()
        os.utime(artifact, (aged, aged))
        imported += import_nmap_artifacts(
            repository,
            nmap_root,
            deployment_id=deployment_id,
            stability_seconds=0,
            now=clock[0],
        ).imported

        report_started = time.perf_counter()
        outputs = generate_reports(
            repository,
            deployment_id,
            data_root / "reports",
            generated_at=start + timedelta(days=day),
            customer_name="Synthetic Customer",
            site_name="Soak Site",
            author="Synthetic Operator",
        )
        report_times.append(time.perf_counter() - report_started)
        report_sizes.append(outputs.docx_path.stat().st_size)

        if day == days // 2:
            repository.connection.execute("BEGIN")
            repository.connection.execute(
                "INSERT INTO deployments(site_key, display_name, started_at) "
                "VALUES ('rollback-fixture', 'Rollback Fixture', ?)",
                (clock[0].isoformat(),),
            )
            repository.connection.rollback()
            rollbacks += 1
            repository.start_run(deployment_id, "interrupted-fixture", clock[0].isoformat())
            repository.close()
            repository = Repository.open(database_path, data_root=data_root)
            recovered += repository.recover_interrupted_runs(
                (clock[0] + timedelta(seconds=1)).isoformat()
            )
            recovered += repository.recover_interrupted_runs(
                (clock[0] + timedelta(seconds=2)).isoformat()
            )

    integrity = repository.integrity_check()
    final_database_bytes = _database_bytes(repository)
    running = int(
        repository.connection.execute(
            "SELECT COUNT(*) FROM collector_runs WHERE status = 'running'"
        ).fetchone()[0]
    )
    collector_runs = int(
        repository.connection.execute("SELECT COUNT(*) FROM collector_runs").fetchone()[0]
    )
    rollback_rows = int(
        repository.connection.execute(
            "SELECT COUNT(*) FROM deployments WHERE site_key = 'rollback-fixture'"
        ).fetchone()[0]
    )
    repository.close()
    return {
        "data_root": data_root,
        "database_bytes": final_database_bytes,
        "database_growth_per_day": max(0, (final_database_bytes - initial_database_bytes) // days),
        "report_times": report_times,
        "report_sizes": report_sizes,
        "collector_runs": collector_runs,
        "collector_failures": collector_failures,
        "isolated_outages": isolated_outages,
        "recovered_outages": recovered_outages,
        "recovered": recovered,
        "rollbacks": rollbacks if rollback_rows == 0 else 0,
        "passive": passive_totals,
        "imported": imported,
        "integrity": integrity.ok,
        "running": running,
    }


def run_accelerated_soak(
    root: Path,
    *,
    days: int,
    cycles_per_day: int,
    nmap_fixture: Path,
    passive_fixture: Path,
    budget: SoakBudget = DEFAULT_BUDGET,
    start: datetime = datetime(2026, 7, 1, tzinfo=UTC),
    protected_probe: ProtectedProbe | None = None,
) -> SoakResult:
    """Run a deterministic fixture replay without opening sockets or installing services."""
    if days < 1 or cycles_per_day < 2:
        raise ValueError("soak days must be positive and cycles_per_day must be at least two")
    protected_before = _snapshot(protected_probe)
    passive_fixtures = json.loads(passive_fixture.read_text())
    tracemalloc.start()
    cpu_started = time.process_time()
    wall_started = time.perf_counter()
    measurements = asyncio.run(
        _run_days(
            root,
            days=days,
            cycles_per_day=cycles_per_day,
            start=start,
            nmap_fixture=nmap_fixture,
            passive_fixtures=passive_fixtures,
        )
    )
    cpu_seconds = time.process_time() - cpu_started
    wall_seconds = time.perf_counter() - wall_started
    _current, peak_python = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) * 1024
    protected_after = _snapshot(protected_probe)
    data_root = measurements["data_root"]
    report_files = len(tuple((data_root / "reports").iterdir()))
    artifact_files = len(tuple((data_root / "artifacts" / "soak").iterdir()))
    log_files = len(tuple(data_root.rglob("*.log")))
    projected = int(measurements["database_growth_per_day"]) * 30
    passive = measurements["passive"]
    violations: list[str] = []
    comparisons = (
        (peak_rss <= budget.peak_rss_bytes, "peak RSS exceeded budget"),
        (peak_python <= budget.peak_python_bytes, "Python allocation peak exceeded budget"),
        (passive["queue_peak"] <= budget.passive_queue_peak, "passive queue exceeded budget"),
        (passive["retained"] <= budget.passive_retained_bytes, "passive capacity exceeded budget"),
        (max(measurements["report_times"]) <= budget.report_seconds, "report time exceeded budget"),
        (max(measurements["report_sizes"]) <= budget.report_bytes, "report size exceeded budget"),
        (
            projected <= budget.projected_30_day_database_bytes,
            "database projection exceeded budget",
        ),
        (
            passive["final_depth"] == 0 and passive["final_in_flight"] == 0,
            "passive queue did not drain",
        ),
        (passive["incomplete"] == 0, "passive replay left incomplete frames"),
        (measurements["isolated_outages"] == days, "collector outage was not isolated"),
        (measurements["recovered_outages"] == days, "collector did not recover"),
        (
            measurements["recovered"] == 1 and measurements["rollbacks"] == 1,
            "restart recovery failed",
        ),
        (measurements["integrity"] and measurements["running"] == 0, "database final state failed"),
        (artifact_files <= measurements["collector_runs"] * 2, "artifact count is unbounded"),
        (log_files == 0, "unexpected file logs were retained"),
        (protected_before == protected_after, "protected appliance state changed"),
    )
    violations.extend(message for passed, message in comparisons if not passed)
    return SoakResult(
        schema_version=1,
        days=days,
        cycles_per_day=cycles_per_day,
        cpu_seconds=round(cpu_seconds, 6),
        wall_seconds=round(wall_seconds, 6),
        peak_rss_bytes=peak_rss,
        peak_python_bytes=peak_python,
        database_bytes=int(measurements["database_bytes"]),
        database_growth_per_day=int(measurements["database_growth_per_day"]),
        projected_30_day_database_bytes=projected,
        data_root_bytes=_tree_bytes(data_root),
        report_max_seconds=round(max(measurements["report_times"]), 6),
        report_max_bytes=max(measurements["report_sizes"]),
        report_files=report_files,
        collector_runs=int(measurements["collector_runs"]),
        collector_failures=int(measurements["collector_failures"]),
        isolated_outages=int(measurements["isolated_outages"]),
        recovered_outages=int(measurements["recovered_outages"]),
        interrupted_runs_recovered=int(measurements["recovered"]),
        transaction_rollbacks=int(measurements["rollbacks"]),
        passive_submitted=int(passive["submitted"]),
        passive_emitted=int(passive["emitted"]),
        passive_parser_failures=int(passive["parser_failures"]),
        passive_queue_peak=int(passive["queue_peak"]),
        passive_final_depth=int(passive["final_depth"]),
        passive_final_in_flight=int(passive["final_in_flight"]),
        passive_incomplete=int(passive["incomplete"]),
        passive_retained_bytes=int(passive["retained"]),
        nmap_imported=int(measurements["imported"]),
        artifact_files=artifact_files,
        log_files=log_files,
        integrity_ok=bool(measurements["integrity"]),
        running_runs=int(measurements["running"]),
        protected_before=protected_before,
        protected_after=protected_after,
        protected_unchanged=protected_before == protected_after,
        violations=tuple(violations),
        passed=not violations,
    )
