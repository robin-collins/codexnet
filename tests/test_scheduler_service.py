"""Scheduled collector runtime, isolation, and packaging tests."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from field_discovery import scheduler_service
from field_discovery.scheduler_service import (
    ScheduledInvocation,
    build_invocations,
    run_cycle,
    serve,
)

ROOT = Path(__file__).parents[1]


def configuration(*, enabled: bool = True) -> dict[str, Any]:
    return {
        "scheduler": {
            "interval_seconds": 60,
            "jitter_seconds": 5,
            "timeout_seconds": 2,
            "retries": 1,
            "concurrency": 2,
        },
        "collectors": {
            "snmp": {
                "enabled": enabled,
                "targets": ["192.168.50.11", "192.168.50.10", "192.168.50.11"],
            },
            "unifi": {
                "enabled": enabled,
                "endpoints": [
                    {"url": "https://z.example.invalid"},
                    {"url": "https://a.example.invalid"},
                ],
            },
            "ad": {
                "enabled": enabled,
                "target": "192.168.50.20",
                "domain": "example.invalid",
                "server_name": "dc.example.invalid",
            },
            "ssh": {
                "enabled": enabled,
                "targets": [
                    {"address": "192.168.50.32", "platform": "cisco_ios"},
                    {"address": "192.168.50.31", "platform": "cisco_ios"},
                    {"address": "192.168.50.40", "platform": "aruba_aos"},
                ],
            },
        },
    }


def test_build_invocations_is_deterministic_bounded_and_secret_free() -> None:
    invocations = build_invocations(configuration())
    assert invocations == (
        ScheduledInvocation(
            "snmp",
            (
                "collect",
                "snmp",
                "--target",
                "192.168.50.10",
                "--target",
                "192.168.50.11",
            ),
        ),
        ScheduledInvocation(
            "unifi", ("collect", "unifi", "--controller", "https://a.example.invalid")
        ),
        ScheduledInvocation(
            "unifi", ("collect", "unifi", "--controller", "https://z.example.invalid")
        ),
        ScheduledInvocation(
            "ad",
            (
                "collect",
                "ad",
                "--target",
                "192.168.50.20",
                "--domain",
                "example.invalid",
                "--server-name",
                "dc.example.invalid",
            ),
        ),
        ScheduledInvocation(
            "ssh",
            ("collect", "ssh", "--platform", "aruba_aos", "--target", "192.168.50.40"),
        ),
        ScheduledInvocation(
            "ssh",
            (
                "collect",
                "ssh",
                "--platform",
                "cisco_ios",
                "--target",
                "192.168.50.31",
                "--target",
                "192.168.50.32",
            ),
        ),
    )
    assert "PROFILE" not in repr(invocations)
    assert build_invocations(configuration(enabled=False)) == ()


def test_build_invocations_omits_optional_ad_names_and_empty_target_sets() -> None:
    value = configuration()
    value["collectors"]["snmp"]["targets"] = []
    value["collectors"]["ad"]["domain"] = None
    value["collectors"]["ad"]["server_name"] = None
    value["collectors"]["ssh"]["targets"] = []
    invocations = build_invocations(value)
    assert ScheduledInvocation("ad", ("collect", "ad", "--target", "192.168.50.20")) in invocations
    assert all(item.collector not in {"snmp", "ssh"} for item in invocations)


def test_run_cycle_passes_only_config_and_nonsecret_arguments() -> None:
    seen: list[tuple[tuple[str, ...], float]] = []

    async def runner(arguments: Sequence[str], timeout: float) -> tuple[int, bool]:
        seen.append((tuple(arguments), timeout))
        return (0, False) if "snmp" in arguments else (7, True)

    invocations = (
        ScheduledInvocation("snmp", ("collect", "snmp", "--target", "192.168.50.10")),
        ScheduledInvocation("ssh", ("collect", "ssh", "--target", "192.168.50.20")),
    )
    outcomes = asyncio.run(
        run_cycle(
            invocations,
            executable=Path("/safe/field-discovery"),
            config_path=Path("/safe/config.yaml"),
            concurrency=1,
            timeout=12,
            runner=runner,
        )
    )
    assert [(item.collector, item.returncode, item.timed_out) for item in outcomes] == [
        ("snmp", 0, False),
        ("ssh", 7, True),
    ]
    assert seen[0][0][:4] == (
        "/safe/field-discovery",
        "--json",
        "--config",
        "/safe/config.yaml",
    )
    assert all(item[1] == 12 for item in seen)


def test_process_runner_handles_success_timeout_and_cancellation() -> None:
    async def exercise() -> None:
        assert await scheduler_service._run_process(("/bin/true",), 2) == (0, False)
        timeout_result = await scheduler_service._run_process(
            (sys.executable, "-c", "import time; time.sleep(60)"), 0.01
        )
        assert timeout_result == (124, True)
        task = asyncio.create_task(
            scheduler_service._run_process(
                (sys.executable, "-c", "import time; time.sleep(60)"), 60
            )
        )
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())


def test_process_runner_kills_a_child_that_ignores_termination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        returncode: int | None = None
        terminated = False
        killed = False

        async def wait(self) -> int:
            return -9 if self.killed else 0

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True

    process = FakeProcess()
    monkeypatch.setattr(
        scheduler_service.asyncio,
        "create_subprocess_exec",
        lambda *_args, **_kwargs: asyncio.sleep(0, result=process),
    )
    real_wait_for = asyncio.wait_for
    calls = 0

    async def fake_wait_for(awaitable: Any, *, timeout: float) -> Any:
        nonlocal calls
        del timeout
        calls += 1
        if calls <= 2:
            if hasattr(awaitable, "close"):
                awaitable.close()
            raise TimeoutError
        return await real_wait_for(awaitable, timeout=1)

    monkeypatch.setattr(scheduler_service.asyncio, "wait_for", fake_wait_for)
    assert asyncio.run(scheduler_service._run_process(("fixture",), 1)) == (124, True)
    assert process.terminated is True and process.killed is True


def test_serve_logs_isolated_outcomes_and_stops_after_cycle() -> None:
    stop = asyncio.Event()
    records: list[tuple[str, dict[str, object]]] = []

    class RecordingLogger:
        def info(self, event: str, *, extra: dict[str, object]) -> None:
            records.append((event, extra))

    async def runner(arguments: Sequence[str], timeout: float) -> tuple[int, bool]:
        del arguments, timeout
        stop.set()
        return 9, True

    asyncio.run(
        serve(
            configuration(),
            config_path=Path("/safe/config.yaml"),
            stop=stop,
            executable=Path("/safe/field-discovery"),
            runner=runner,
            logger=cast(logging.Logger, RecordingLogger()),
        )
    )
    assert records == [
        (
            "scheduler_cycle_finished",
            {"collectors": 6, "failed": 6, "timed_out": 6},
        )
    ]


def test_serve_waits_with_jitter_and_an_initial_stop_is_noop() -> None:
    class FixedRandom:
        def uniform(self, lower: float, upper: float) -> float:
            assert (lower, upper) == (0, 5)
            return 0

    async def exercise() -> None:
        already_stopped = asyncio.Event()
        already_stopped.set()
        await serve(
            configuration(enabled=False),
            config_path=Path("/safe/config.yaml"),
            stop=already_stopped,
            executable=Path("/safe/field-discovery"),
        )

        stop = asyncio.Event()
        asyncio.get_running_loop().call_later(0.01, stop.set)
        value = configuration(enabled=False)
        value["scheduler"]["interval_seconds"] = 0.001
        await serve(
            value,
            config_path=Path("/safe/config.yaml"),
            stop=stop,
            executable=Path("/safe/field-discovery"),
            random_source=FixedRandom(),  # type: ignore[arg-type]
        )

    asyncio.run(exercise())


def test_scheduler_unit_and_installer_are_least_privilege() -> None:
    unit = (ROOT / "packaging/systemd/field-discovery-scheduler.service").read_text()
    assert "User=field-discovery" in unit
    assert "NoNewPrivileges=true" in unit
    assert "CapabilityBoundingSet=\n" in unit
    assert "AmbientCapabilities=\n" in unit
    assert "ReadWritePaths=/var/lib/field-discovery" in unit
    assert "Restart=on-failure" in unit
    assert "field-discovery-scheduler" in unit
    installer = ROOT / "packaging/install/install-scheduler-service.sh"
    assert installer.stat().st_mode & 0o777 == 0o755


def test_main_reports_configuration_failure_and_clean_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, dict[str, object] | None]] = []

    class RecordingLogger:
        def info(self, event: str, *, extra: dict[str, object] | None = None) -> None:
            events.append((event, extra))

        def error(self, event: str, *, extra: dict[str, object]) -> None:
            events.append((event, extra))

    logger = cast(logging.Logger, RecordingLogger())
    monkeypatch.setattr(scheduler_service, "configure_logging", lambda **_values: logger)
    monkeypatch.setattr(
        scheduler_service,
        "load_config",
        lambda _path: (_ for _ in ()).throw(scheduler_service.ConfigurationError("safe")),
    )
    assert scheduler_service.main(["--config", "/safe/config.yaml"]) == 1
    assert events[-1][0] == "scheduler_service_failed"

    class FakeLoop:
        def __init__(self) -> None:
            self.signals: list[object] = []
            self.closed = False

        def add_signal_handler(self, selected: object, callback: object) -> None:
            del callback
            self.signals.append(selected)

        def run_until_complete(self, awaitable: Any) -> None:
            awaitable.close()

        def close(self) -> None:
            self.closed = True

    loop = FakeLoop()
    monkeypatch.setattr(scheduler_service, "load_config", lambda _path: SimpleNamespace(data={}))
    monkeypatch.setattr(scheduler_service.asyncio, "new_event_loop", lambda: loop)
    monkeypatch.setattr(scheduler_service.asyncio, "set_event_loop", lambda _loop: None)
    assert scheduler_service.main(["--config", "/safe/config.yaml"]) == 0
    assert loop.signals == [signal.SIGTERM, signal.SIGINT]
    assert loop.closed is True
    assert events[-1][0] == "scheduler_service_stopped"
