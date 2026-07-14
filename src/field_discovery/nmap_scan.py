"""Explicit, audited launcher for the protected nmap discovery script.

This module never schedules scans.  It invokes one fixed script only after the
caller's confirmation and the normal interface/range resolver have approved
the directly connected target.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import signal
import stat
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO, Protocol

from field_discovery.repository import Repository
from field_discovery.subnet import SubnetDescription, SubnetResolutionError, resolve_subnet

PROTECTED_NMAP_SCRIPT = Path("/usr/local/sbin/network-discovery-scan.sh")
LOCK_FILENAME = ".nmap-scan-wrapper.lock"
EXIT_TIMEOUT = 124
EXIT_MISSING = 127
EXIT_CONCURRENT = 75


class ScanLaunchError(RuntimeError):
    """The wrapper could not establish a safe, auditable launch boundary."""


@dataclass(frozen=True)
class ScanResult:
    """Secret-free outcome of one attempted script invocation."""

    status: str
    exit_code: int
    interface: str
    cidr: str
    started_at: str
    finished_at: str
    duration_seconds: float
    script_sha256: str | None


class Process(Protocol):
    """Small subprocess boundary used by deterministic launcher tests."""

    pid: int
    returncode: int | None

    def wait(self, timeout: float | None = None) -> int: ...  # pragma: no cover


class ProcessFactory(Protocol):
    def __call__(self, arguments: list[str], **kwargs: Any) -> Process: ...  # pragma: no cover


def _start_process(arguments: list[str], **kwargs: Any) -> Process:
    """Typed default process boundary."""
    return subprocess.Popen(arguments, **kwargs)


def _open_lock(data_root: Path) -> BinaryIO:
    """Open a non-link lock file below the already provisioned data root."""
    try:
        root_info = data_root.lstat()
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise ScanLaunchError("configured data root must be a real directory")
        descriptor = os.open(
            data_root / LOCK_FILENAME,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise ScanLaunchError("cannot prepare the scan invocation lock") from exc
    return os.fdopen(descriptor, "rb+", closefd=True)


def _script_digest(script: Path) -> str:
    """Validate and hash the exact regular executable that will be invoked."""
    try:
        info = script.lstat()
    except FileNotFoundError as exc:
        raise FileNotFoundError("protected nmap script is not installed") from exc
    except OSError as exc:
        raise ScanLaunchError("protected nmap script cannot be inspected") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ScanLaunchError("protected nmap script must be a regular non-link file")
    if not os.access(script, os.X_OK):
        raise ScanLaunchError("protected nmap script is not executable")
    digest = hashlib.sha256()
    try:
        with script.open("rb") as stream:
            for chunk in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ScanLaunchError("protected nmap script cannot be read") from exc
    return digest.hexdigest()


def _safe_environment(description: SubnetDescription) -> dict[str, str]:
    """Provide only operational values required by the protected script."""
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "INTERFACE_OVERRIDE": description.interface,
        "CIDR_OVERRIDE": description.cidr,
    }


def _terminate_group(process: Process) -> None:
    """Stop the whole script process group after the outer wall-clock timeout."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait()


def run_nmap_scan(
    config: dict[str, Any],
    *,
    timeout_seconds: int,
    script: Path = PROTECTED_NMAP_SCRIPT,
    process_factory: ProcessFactory = _start_process,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
) -> ScanResult:
    """Resolve, serialize, audit, and invoke one explicit active scan.

    Standard output and error are discarded because the protected script owns
    its own restricted log and scan artifacts.  No inherited environment is
    passed to the script.
    """
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool):
        raise ScanLaunchError("scan timeout must be an integer")
    if not 1 <= timeout_seconds <= 86_400:
        raise ScanLaunchError("scan timeout must be from 1 to 86400 seconds")
    description = resolve_subnet(config)
    if not description.active_target_permitted:
        reasons = "; ".join(description.active_target_reasons)
        raise SubnetResolutionError(f"active scan target refused: {reasons}")

    paths = config["paths"]
    data_root = Path(paths["data_root"])
    repository = Repository.open(Path(paths["database"]), data_root=data_root)
    try:
        lock = _open_lock(data_root)
    except Exception:
        repository.close()
        raise
    try:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            timestamp = now().astimezone(UTC).isoformat()
            run_id = repository.start_run(
                None,
                "nmap-script",
                timestamp,
                interface_name=description.interface,
                target_cidr=description.cidr,
            )
            repository.finish_run(run_id, "failed", timestamp, 0)
            return ScanResult(
                "concurrent",
                EXIT_CONCURRENT,
                description.interface,
                description.cidr,
                timestamp,
                timestamp,
                0.0,
                None,
            )

        started = now().astimezone(UTC)
        started_text = started.isoformat()
        run_id = repository.start_run(
            None,
            "nmap-script",
            started_text,
            interface_name=description.interface,
            target_cidr=description.cidr,
        )
        start_tick = monotonic()
        digest: str | None = None
        exit_code = EXIT_MISSING
        status = "failed"
        try:
            digest = _script_digest(script)
            process = process_factory(
                [str(script)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_safe_environment(description),
                start_new_session=True,
            )
            try:
                return_code = process.wait(timeout=timeout_seconds)
                exit_code = return_code if return_code >= 0 else 128 + abs(return_code)
                status = "succeeded" if exit_code == 0 else "failed"
            except subprocess.TimeoutExpired:
                _terminate_group(process)
                exit_code = EXIT_TIMEOUT
                status = "cancelled"
        except (FileNotFoundError, ScanLaunchError):
            exit_code = EXIT_MISSING
            status = "failed"
        except OSError:
            exit_code = EXIT_MISSING
            status = "failed"
        finished = now().astimezone(UTC)
        duration = max(0.0, monotonic() - start_tick)
        repository.finish_run(run_id, status, finished.isoformat(), 0)
        return ScanResult(
            status=status,
            exit_code=exit_code,
            interface=description.interface,
            cidr=description.cidr,
            started_at=started_text,
            finished_at=finished.isoformat(),
            duration_seconds=round(duration, 3),
            script_sha256=digest,
        )
    finally:
        lock.close()
        repository.close()
