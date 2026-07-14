"""Offline fake-collector lifecycle and scheduler verification."""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CollectorError,
    CollectorIssue,
    CollectorOrchestrator,
    CollectorRequest,
    CollectorResult,
    CollectorScheduler,
    CredentialReference,
    RetryableCollectorError,
    TargetApprovalError,
    UnknownCollectorError,
    approve_target,
)
from field_discovery.redaction import REDACTED, Redactor
from field_discovery.repository import Repository, RepositoryError

NOW = datetime(2026, 7, 15, 1, 2, 3, tzinfo=UTC)
RANGE = ("192.168.50.0/24",)


def repository(tmp_path: Path, *, redactor: Redactor | None = None) -> tuple[Repository, int]:
    root = tmp_path / "data"
    root.mkdir()
    repo = Repository.open(root / "discovery.db", data_root=root, redactor=redactor)
    deployment = repo.upsert_deployment("fixture", "Fixture", NOW.isoformat())
    return repo, deployment


class FakeCollector:
    def __init__(self, name: str, actions: Sequence[object]) -> None:
        self.name = name
        self.actions = list(actions)
        self.calls = 0
        self.contexts: list[CollectorContext] = []

    async def collect(self, context: CollectorContext) -> CollectorResult:
        self.contexts.append(context)
        action = self.actions[min(self.calls, len(self.actions) - 1)]
        self.calls += 1
        if isinstance(action, BaseException):
            raise action
        if isinstance(action, float):
            await asyncio.sleep(action)
            return CollectorResult(1)
        return cast(CollectorResult, action)


def orchestrator(
    repo: Repository,
    deployment: int,
    collectors: dict[str, FakeCollector],
    **overrides: object,
) -> CollectorOrchestrator:
    values: dict[str, object] = {
        "repository": repo,
        "deployment_id": deployment,
        "approved_ranges": RANGE,
        "collectors": collectors,
        "concurrency": 2,
        "timeout_seconds": 0.01,
        "retries": 1,
        "interface_name": "eth0",
        "clock": lambda: NOW,
    }
    values.update(overrides)
    return CollectorOrchestrator(**values)  # type: ignore[arg-type]


def test_target_approval_is_canonical_and_strictly_scoped() -> None:
    assert approve_target("192.168.50.9", RANGE) == "192.168.50.9"
    assert approve_target("192.168.50.9/28", RANGE) == "192.168.50.0/28"
    with pytest.raises(TargetApprovalError, match="outside approved"):
        approve_target("192.168.51.1", RANGE)
    with pytest.raises(TargetApprovalError, match="IPv4 address or CIDR"):
        approve_target("host.example.invalid", RANGE)
    with pytest.raises(TargetApprovalError, match="must be IPv4"):
        approve_target("2001:db8::1", RANGE)


def test_credential_reference_accepts_only_opaque_reference_shape() -> None:
    assert CredentialReference.from_mapping(None) is None
    assert CredentialReference.from_mapping({"provider": "env", "key": "SSH_PROFILE"}) == (
        CredentialReference("env", "SSH_PROFILE")
    )
    for value in ({"provider": "env"}, {"provider": 1, "key": "X"}, {"provider": "x", "key": 2}):
        with pytest.raises(CollectorError, match="provider and key"):
            CredentialReference.from_mapping(value)
    with pytest.raises(ValueError, match="cannot be negative"):
        CollectorResult(-1)


def test_constructor_bounds_and_empty_cycle(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    with pytest.raises(ValueError, match="concurrency"):
        orchestrator(repo, deployment, {}, concurrency=0)
    with pytest.raises(ValueError, match="timeout"):
        orchestrator(repo, deployment, {}, timeout_seconds=0)
    with pytest.raises(ValueError, match="retries"):
        orchestrator(repo, deployment, {}, retries=-1)
    assert asyncio.run(orchestrator(repo, deployment, {}).run([])) == ()
    repo.close()


def test_success_partial_auth_and_failure_are_isolated(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    collectors = {
        "success": FakeCollector("success", [CollectorResult(3)]),
        "partial": FakeCollector(
            "partial", [CollectorResult(2, (CollectorIssue("decode", "one row malformed"),))]
        ),
        "auth": FakeCollector("auth", [CollectorAuthenticationError("do not persist this")]),
        "failure": FakeCollector("failure", [RuntimeError("unexpected fixture failure")]),
        "controlled": FakeCollector("controlled", [CollectorError("unsupported response")]),
    }
    requests = [CollectorRequest(name, "192.168.50.10") for name in collectors]
    summaries = asyncio.run(orchestrator(repo, deployment, collectors).run(requests))
    assert {summary.collector: summary.status for summary in summaries} == {
        "success": "succeeded",
        "partial": "partial",
        "auth": "failed",
        "failure": "failed",
        "controlled": "failed",
    }
    assert [(summary.item_count, summary.error_count) for summary in summaries[:2]] == [
        (3, 0),
        (2, 1),
    ]
    categories = {
        row[0]
        for row in repo.connection.execute("SELECT category FROM collector_errors ORDER BY id")
    }
    assert categories == {"decode", "authentication", "collector_failure", "collector"}
    assert collectors["success"].contexts[0].target == "192.168.50.10"
    assert collectors["success"].contexts[0].credential_ref is None
    repo.close()


def test_timeout_and_retryable_failure_retry_with_bounded_attempts(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    retry_delays: list[float] = []

    async def retry_sleep(delay: float) -> None:
        retry_delays.append(delay)

    collectors = {
        "timeout": FakeCollector("timeout", [0.1]),
        "recover": FakeCollector(
            "recover", [RetryableCollectorError("temporary"), CollectorResult(4)]
        ),
        "exhausted": FakeCollector(
            "exhausted", [RetryableCollectorError("first"), RetryableCollectorError("last")]
        ),
    }
    summaries = asyncio.run(
        orchestrator(repo, deployment, collectors, retry_sleep=retry_sleep).run(
            [CollectorRequest(name, "192.168.50.11") for name in collectors]
        )
    )
    by_name = {summary.collector: summary for summary in summaries}
    assert (by_name["timeout"].status, by_name["timeout"].attempts) == ("failed", 2)
    assert (by_name["recover"].status, by_name["recover"].attempts) == ("succeeded", 2)
    assert (by_name["exhausted"].status, by_name["exhausted"].attempts) == ("failed", 2)
    assert retry_delays == [0, 0, 0]
    assert by_name["timeout"].error_count == 2
    repo.close()


def test_concurrency_is_bounded(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    active = 0
    maximum = 0

    class MeasuringCollector:
        name = "measure"

        async def collect(self, _context: CollectorContext) -> CollectorResult:
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0)
            active -= 1
            return CollectorResult(1)

    runner = CollectorOrchestrator(
        repo, deployment, RANGE, {"measure": MeasuringCollector()}, 1, 1, 0, clock=lambda: NOW
    )
    results = asyncio.run(
        runner.run([CollectorRequest("measure", f"192.168.50.{index}") for index in range(1, 5)])
    )
    assert maximum == 1
    assert all(result.status == "succeeded" for result in results)
    repo.close()


def test_cancellation_finishes_inflight_and_queued_runs(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    started = asyncio.Event()

    class BlockingCollector:
        name = "block"

        async def collect(self, _context: CollectorContext) -> CollectorResult:
            started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    async def scenario() -> tuple[str, ...]:
        stop = asyncio.Event()
        runner = CollectorOrchestrator(
            repo,
            deployment,
            RANGE,
            {"block": BlockingCollector()},
            1,
            10,
            0,
            clock=lambda: NOW,
        )
        task = asyncio.create_task(
            runner.run(
                [
                    CollectorRequest("block", "192.168.50.1"),
                    CollectorRequest("block", "192.168.50.2"),
                ],
                cancellation=stop,
            )
        )
        await started.wait()
        stop.set()
        return tuple(summary.status for summary in await task)

    assert asyncio.run(scenario()) == ("cancelled", "cancelled")
    assert [row[0] for row in repo.connection.execute("SELECT status FROM collector_runs")] == [
        "cancelled",
        "cancelled",
    ]
    repo.close()


def test_parent_task_cancellation_is_propagated_but_runs_are_finalized(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    started = asyncio.Event()

    class BlockingCollector:
        name = "block"

        async def collect(self, _context: CollectorContext) -> CollectorResult:
            started.set()
            await asyncio.Event().wait()
            return CollectorResult()

    async def scenario() -> None:
        runner = CollectorOrchestrator(
            repo, deployment, RANGE, {"block": BlockingCollector()}, 1, 10, 0, clock=lambda: NOW
        )
        task = asyncio.create_task(runner.run([CollectorRequest("block", "192.168.50.1")]))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert repo.connection.execute("SELECT status FROM collector_runs").fetchone()[0] == "cancelled"
    repo.close()


def test_refusal_and_unknown_collector_start_no_runs(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    fake = FakeCollector("known", [CollectorResult()])
    runner = orchestrator(repo, deployment, {"known": fake})
    with pytest.raises(TargetApprovalError):
        asyncio.run(runner.run([CollectorRequest("known", "10.0.0.1")]))
    with pytest.raises(UnknownCollectorError):
        asyncio.run(runner.run([CollectorRequest("missing", "192.168.50.1")]))
    assert repo.connection.execute("SELECT COUNT(*) FROM collector_runs").fetchone()[0] == 0
    assert fake.calls == 0
    repo.close()


def test_credential_values_are_absent_from_logs_and_database(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    secret = "swordfish-value"
    repo, deployment = repository(tmp_path, redactor=Redactor([secret]))
    fake = FakeCollector("safe", [RuntimeError(f"password={secret}; raw {secret}")])
    reference = CredentialReference("appliance_env", "SSH_SITE_PROFILE")
    with caplog.at_level(logging.INFO, logger="field_discovery"):
        result = asyncio.run(
            orchestrator(repo, deployment, {"safe": fake}).run(
                [CollectorRequest("safe", "192.168.50.4", reference)]
            )
        )
    assert result[0].status == "failed"
    assert fake.contexts[0].credential_ref == reference
    database_text = " ".join(
        str(value)
        for row in repo.connection.execute("SELECT category, detail, source FROM collector_errors")
        for value in row
    )
    assert secret not in database_text + caplog.text
    assert REDACTED in database_text
    repo.close()


def test_recent_status_is_bounded_and_aggregates_errors(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    run_id = repo.start_run(deployment, "fixture", NOW.isoformat(), target_cidr="192.168.50.1")
    repo.record_collector_error(
        run_id,
        category="fixture",
        detail="safe",
        retryable=False,
        source="fixture",
        observed_at=NOW.isoformat(),
    )
    repo.finish_run(run_id, "partial", NOW.isoformat(), 2)
    status = repo.recent_collector_runs(limit=1)
    assert status[0]["status"] == "partial"
    assert status[0]["error_count"] == 1
    with pytest.raises(RepositoryError, match="limit"):
        repo.recent_collector_runs(limit=0)
    with pytest.raises(RepositoryError, match="limit"):
        repo.recent_collector_runs(limit=1001)
    repo.close()


def test_scheduler_jitter_bounds_and_cycles_until_stopped(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    fake = FakeCollector("safe", [CollectorResult(1)])
    runner = orchestrator(repo, deployment, {"safe": fake}, retries=0, timeout_seconds=1)
    scheduler = CollectorScheduler(runner, 0.001, 0.0005, random.Random(7))
    delay = scheduler.next_delay()
    assert 0.001 <= delay <= 0.0015

    async def scenario() -> None:
        stop = asyncio.Event()

        def requests() -> Sequence[CollectorRequest]:
            if fake.calls >= 1:
                stop.set()
            return [CollectorRequest("safe", "192.168.50.2")]

        await scheduler.serve(requests, stop)

    asyncio.run(scenario())
    assert fake.calls == 1
    already_stopped = asyncio.Event()
    already_stopped.set()
    asyncio.run(scheduler.serve(lambda: (), already_stopped))
    with pytest.raises(ValueError, match="interval/jitter"):
        CollectorScheduler(runner, 0, 0)
    with pytest.raises(ValueError, match="interval/jitter"):
        CollectorScheduler(runner, 1, 1)
    repo.close()
