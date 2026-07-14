"""Mock-only tests for the explicit protected-script wrapper."""

from __future__ import annotations

import fcntl
import os
import signal
import sqlite3
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from field_discovery import nmap_scan
from field_discovery.nmap_scan import ScanLaunchError
from field_discovery.subnet import SubnetDescription, SubnetResolutionError


def approved_description() -> SubnetDescription:
    return SubnetDescription(
        interface="eth0",
        address="192.0.2.10",
        cidr="192.0.2.0/24",
        gateway="192.0.2.1",
        dns_servers=("192.0.2.1",),
        address_source="kernel",
        route_source="static",
        route_metric=100,
        active_target_permitted=True,
        active_target_reasons=(),
    )


def config(tmp_path: Path) -> dict[str, Any]:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    return {
        "paths": {"data_root": str(root), "database": str(root / "discovery.db")},
        "interface": {"name": "eth0", "allow_excluded_interface": False},
        "active": {"approved_ranges": ["192.0.2.0/24"], "max_hosts": 256},
    }


def mock_script(tmp_path: Path) -> Path:
    path = tmp_path / "mock-scan"
    path.write_text("#!/bin/sh\nexit 99\n")
    path.chmod(0o700)
    return path


class FakeProcess:
    pid = 43210

    def __init__(self, return_code: int = 0, *, times_out: bool = False) -> None:
        self.returncode: int | None = None
        self.return_code = return_code
        self.times_out = times_out
        self.waits = 0

    def wait(self, timeout: float | None = None) -> int:
        self.waits += 1
        if self.times_out and self.waits == 1:
            raise subprocess.TimeoutExpired("mock-scan", timeout or 0.0)
        self.returncode = self.return_code
        return self.return_code


def statuses(configuration: dict[str, Any]) -> list[str]:
    connection = sqlite3.connect(configuration["paths"]["database"])
    try:
        return [
            row[0] for row in connection.execute("SELECT status FROM collector_runs ORDER BY id")
        ]
    finally:
        connection.close()


def test_success_uses_approved_context_isolated_environment_and_audits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = config(tmp_path)
    script = mock_script(tmp_path)
    captured: dict[str, Any] = {}

    def factory(arguments: list[str], **kwargs: Any) -> FakeProcess:
        captured.update(arguments=arguments, **kwargs)
        return FakeProcess()

    monkeypatch.setattr(nmap_scan, "resolve_subnet", lambda _config: approved_description())
    result = nmap_scan.run_nmap_scan(
        configuration, timeout_seconds=12, script=script, process_factory=factory
    )
    assert result.status == "succeeded"
    assert result.exit_code == 0
    assert result.script_sha256 is not None
    assert captured["arguments"] == [str(script)]
    assert captured["env"] == {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "INTERFACE_OVERRIDE": "eth0",
        "CIDR_OVERRIDE": "192.0.2.0/24",
    }
    assert captured["stdin"] is subprocess.DEVNULL
    assert captured["stdout"] is subprocess.DEVNULL
    assert captured["stderr"] is subprocess.DEVNULL
    assert captured["start_new_session"] is True
    assert statuses(configuration) == ["succeeded"]


@pytest.mark.parametrize(("return_code", "expected"), [(31, 31), (-15, 143)])
def test_failure_and_signal_status_propagate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    return_code: int,
    expected: int,
) -> None:
    configuration = config(tmp_path)
    monkeypatch.setattr(nmap_scan, "resolve_subnet", lambda _config: approved_description())
    result = nmap_scan.run_nmap_scan(
        configuration,
        timeout_seconds=2,
        script=mock_script(tmp_path),
        process_factory=lambda *_args, **_kwargs: FakeProcess(return_code),
    )
    assert result.exit_code == expected
    assert result.status == "failed"
    assert statuses(configuration) == ["failed"]


def test_timeout_terminates_process_group_and_is_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = config(tmp_path)
    process = FakeProcess(times_out=True)
    terminated: list[FakeProcess] = []
    monkeypatch.setattr(nmap_scan, "resolve_subnet", lambda _config: approved_description())
    monkeypatch.setattr(nmap_scan, "_terminate_group", terminated.append)
    result = nmap_scan.run_nmap_scan(
        configuration,
        timeout_seconds=1,
        script=mock_script(tmp_path),
        process_factory=lambda *_args, **_kwargs: process,
    )
    assert result.exit_code == nmap_scan.EXIT_TIMEOUT
    assert result.status == "cancelled"
    assert terminated == [process]
    assert statuses(configuration) == ["cancelled"]


@pytest.mark.parametrize("kind", ["missing", "non_executable", "symlink"])
def test_missing_or_unsafe_script_never_starts_process_and_is_audited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    configuration = config(tmp_path)
    target = tmp_path / "script"
    if kind == "non_executable":
        target.write_text("fixture")
    elif kind == "symlink":
        real = mock_script(tmp_path)
        target.symlink_to(real)

    def forbidden(*_args: object, **_kwargs: object) -> FakeProcess:
        raise AssertionError("process must not start")

    monkeypatch.setattr(nmap_scan, "resolve_subnet", lambda _config: approved_description())
    result = nmap_scan.run_nmap_scan(
        configuration, timeout_seconds=1, script=target, process_factory=forbidden
    )
    assert result.exit_code == nmap_scan.EXIT_MISSING
    assert result.status == "failed"
    assert statuses(configuration) == ["failed"]


def test_concurrent_wrapper_lock_refuses_without_starting_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = config(tmp_path)
    lock_path = Path(configuration["paths"]["data_root"]) / nmap_scan.LOCK_FILENAME
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    monkeypatch.setattr(nmap_scan, "resolve_subnet", lambda _config: approved_description())
    try:
        result = nmap_scan.run_nmap_scan(
            configuration,
            timeout_seconds=1,
            script=mock_script(tmp_path),
            process_factory=lambda *_args, **_kwargs: pytest.fail("process started"),
        )
    finally:
        os.close(descriptor)
    assert result.exit_code == nmap_scan.EXIT_CONCURRENT
    assert result.status == "concurrent"
    assert statuses(configuration) == ["failed"]


def test_unapproved_target_and_invalid_timeout_refuse_before_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = config(tmp_path)
    description = approved_description()
    refused = SubnetDescription(
        interface=description.interface,
        address=description.address,
        cidr=description.cidr,
        gateway=description.gateway,
        dns_servers=description.dns_servers,
        address_source=description.address_source,
        route_source=description.route_source,
        route_metric=description.route_metric,
        active_target_permitted=False,
        active_target_reasons=("synthetic unapproved range",),
    )
    monkeypatch.setattr(nmap_scan, "resolve_subnet", lambda _config: refused)
    with pytest.raises(SubnetResolutionError, match="synthetic unapproved"):
        nmap_scan.run_nmap_scan(configuration, timeout_seconds=1, script=mock_script(tmp_path))
    with pytest.raises(ScanLaunchError, match="integer"):
        nmap_scan.run_nmap_scan(configuration, timeout_seconds=True, script=mock_script(tmp_path))
    with pytest.raises(ScanLaunchError, match="1 to 86400"):
        nmap_scan.run_nmap_scan(configuration, timeout_seconds=86_401, script=mock_script(tmp_path))


def test_process_start_os_error_and_negative_duration_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = config(tmp_path)
    monkeypatch.setattr(nmap_scan, "resolve_subnet", lambda _config: approved_description())
    ticks = iter((10.0, 9.0))

    def fail(*_args: object, **_kwargs: object) -> FakeProcess:
        raise OSError("synthetic process failure")

    result = nmap_scan.run_nmap_scan(
        configuration,
        timeout_seconds=1,
        script=mock_script(tmp_path),
        process_factory=fail,
        monotonic=lambda: next(ticks),
    )
    assert result.exit_code == nmap_scan.EXIT_MISSING
    assert result.duration_seconds == 0.0
    assert statuses(configuration) == ["failed"]


def test_lock_path_errors_close_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    configuration = config(tmp_path)
    monkeypatch.setattr(nmap_scan, "resolve_subnet", lambda _config: approved_description())
    monkeypatch.setattr(
        nmap_scan,
        "_open_lock",
        lambda _root: (_ for _ in ()).throw(ScanLaunchError("synthetic lock failure")),
    )
    with pytest.raises(ScanLaunchError, match="synthetic lock failure"):
        nmap_scan.run_nmap_scan(configuration, timeout_seconds=1, script=mock_script(tmp_path))
    monkeypatch.undo()

    missing = tmp_path / "missing-root"
    with pytest.raises(ScanLaunchError, match="prepare the scan invocation lock"):
        nmap_scan._open_lock(missing)

    ordinary = tmp_path / "ordinary"
    ordinary.write_text("not a directory")
    with pytest.raises(ScanLaunchError, match="real directory"):
        nmap_scan._open_lock(ordinary)

    link = tmp_path / "root-link"
    link.symlink_to(tmp_path)
    with pytest.raises(ScanLaunchError, match="real directory"):
        nmap_scan._open_lock(link)


def test_script_inspection_and_read_errors_are_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = mock_script(tmp_path)
    original_lstat = Path.lstat
    original_open = Path.open

    def fail_lstat(path: Path) -> os.stat_result:
        if path == script:
            raise PermissionError("synthetic")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fail_lstat)
    with pytest.raises(ScanLaunchError, match="cannot be inspected"):
        nmap_scan._script_digest(script)
    monkeypatch.setattr(Path, "lstat", original_lstat)

    def fail_open(path: Path, *_args: object, **_kwargs: object) -> Any:
        if path == script:
            raise PermissionError("synthetic")
        return cast(Any, original_open)(path, *_args, **_kwargs)

    monkeypatch.setattr(Path, "open", fail_open)
    with pytest.raises(ScanLaunchError, match="cannot be read"):
        nmap_scan._script_digest(script)


def test_termination_handles_races_and_escalates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()

    def gone(_pid: int, _sig: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr("field_discovery.nmap_scan.os.killpg", gone)
    nmap_scan._terminate_group(process)
    assert process.waits == 0

    signals: list[int] = []
    process = FakeProcess()
    monkeypatch.setattr(
        "field_discovery.nmap_scan.os.killpg", lambda _pid, sig: signals.append(sig)
    )
    nmap_scan._terminate_group(process)
    assert signals == [signal.SIGTERM]
    assert process.waits == 1

    class StubbornProcess(FakeProcess):
        def wait(self, timeout: float | None = None) -> int:
            self.waits += 1
            if timeout is not None:
                raise subprocess.TimeoutExpired("mock", timeout)
            return 0

    stubborn = StubbornProcess()
    signals.clear()
    nmap_scan._terminate_group(stubborn)
    assert signals == [signal.SIGTERM, signal.SIGKILL]
    assert stubborn.waits == 2

    stubborn = StubbornProcess()
    calls = 0

    def gone_after_term(_pid: int, _sig: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ProcessLookupError

    monkeypatch.setattr("field_discovery.nmap_scan.os.killpg", gone_after_term)
    nmap_scan._terminate_group(stubborn)
    assert stubborn.waits == 1


def test_default_process_factory_delegates_to_popen(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = FakeProcess()
    captured: list[tuple[list[str], dict[str, Any]]] = []

    def fake_popen(arguments: list[str], **kwargs: Any) -> FakeProcess:
        captured.append((arguments, kwargs))
        return expected

    monkeypatch.setattr("field_discovery.nmap_scan.subprocess.Popen", fake_popen)
    assert nmap_scan._start_process(["synthetic"], env={}) is expected
    assert captured == [(["synthetic"], {"env": {}})]


def test_deterministic_clock_is_reflected_in_audit_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configuration = config(tmp_path)
    instant = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)
    monkeypatch.setattr(nmap_scan, "resolve_subnet", lambda _config: approved_description())
    result = nmap_scan.run_nmap_scan(
        configuration,
        timeout_seconds=1,
        script=mock_script(tmp_path),
        process_factory=lambda *_args, **_kwargs: FakeProcess(),
        now=lambda: instant,
        monotonic=lambda: 1.0,
    )
    assert result.started_at == instant.isoformat()
    assert result.finished_at == instant.isoformat()
