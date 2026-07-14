"""Read-only operational status and appliance diagnostics."""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import re
import shutil
import sqlite3
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from field_discovery.database import APPLICATION_ID, available_migrations
from field_discovery.subnet import SubnetResolutionError, resolve_subnet

BASELINE_NMAP_SHA256 = "09bfdfd6d034c38882dfddf7cb648d64fc326fcf164f4c68ae49cb103eb2e526"
NMAP_SCRIPT = Path("/usr/local/sbin/network-discovery-scan.sh")
DEPENDENCIES = (
    "cryptography",
    "dnspython",
    "ldap3",
    "netmiko",
    "ntc-templates",
    "pysnmp",
    "PyYAML",
)
CODEXNET_UNITS = (
    "field-discovery-passive.service",
    "field-discovery-nmap-import.service",
    "field-discovery-nmap-import.timer",
)
SCANOPY_CONTAINERS = ("scanopy-server-1", "scanopy-postgres-1", "scanopy-daemon")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    reason: str | None = None


@dataclass(frozen=True)
class DiagnosticCheck:
    name: str
    category: str
    status: str
    message: str
    details: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class DiagnosticProbe(Protocol):  # pragma: no cover - injectable structural boundary
    def now(self) -> datetime: ...

    def network(self, configuration: Mapping[str, Any]) -> Mapping[str, object]: ...

    def path(self, path: Path, *, expected: str) -> Mapping[str, object]: ...

    def disk(self, path: Path) -> Mapping[str, object]: ...

    def database(self, path: Path) -> Mapping[str, object]: ...

    def dependency(self, name: str) -> str | None: ...

    def service(self, name: str) -> Mapping[str, object]: ...

    def clock_sync(self) -> bool | None: ...

    def protected_state(self) -> Sequence[DiagnosticCheck]: ...


Runner = Callable[[Sequence[str], float], CommandResult]


def _run(arguments: Sequence[str], timeout: float) -> CommandResult:
    try:
        completed = subprocess.run(
            list(arguments),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        return CommandResult(127, "")
    reason = (
        "no_crontab"
        if re.fullmatch(r"no crontab for [A-Za-z0-9_.-]+", completed.stderr.strip())
        else None
    )
    return CommandResult(completed.returncode, completed.stdout[:65_536], reason)


@dataclass(frozen=True)
class LocalDiagnosticProbe:
    """Local read-only probe. It never starts a service or opens a network connection."""

    runner: Runner = _run
    nmap_script: Path = NMAP_SCRIPT
    nmap_sha256: str = BASELINE_NMAP_SHA256

    def now(self) -> datetime:
        return datetime.now(UTC)

    def network(self, configuration: Mapping[str, Any]) -> Mapping[str, object]:
        return resolve_subnet(dict(configuration)).as_dict()

    def path(self, path: Path, *, expected: str) -> Mapping[str, object]:
        try:
            metadata = path.lstat()
        except OSError:
            return {"path": str(path), "exists": False, "expected": expected}
        linked = stat.S_ISLNK(metadata.st_mode)
        actual = "directory" if stat.S_ISDIR(metadata.st_mode) else "file"
        return {
            "path": str(path),
            "exists": True,
            "expected": expected,
            "actual": actual,
            "symlink": linked,
            "readable": os.access(path, os.R_OK),
            "writable": os.access(path, os.W_OK),
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        }

    def disk(self, path: Path) -> Mapping[str, object]:
        candidate = path
        while not candidate.exists() and candidate != candidate.parent:
            candidate = candidate.parent
        usage = shutil.disk_usage(candidate)
        return {
            "path": str(path),
            "checked_path": str(candidate),
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "free_percent": round(usage.free * 100 / usage.total, 2) if usage.total else 0.0,
        }

    def database(self, path: Path) -> Mapping[str, object]:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise OSError("database is not a regular file")
        connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only = ON")
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            integrity = tuple(
                str(row[0]) for row in connection.execute("PRAGMA integrity_check").fetchall()
            )
            foreign_keys = len(connection.execute("PRAGMA foreign_key_check").fetchall())
            rows = connection.execute(
                "SELECT r.collector,r.status,r.started_at,r.finished_at,r.item_count,"
                "COUNT(e.id) AS error_count FROM collector_runs r "
                "LEFT JOIN collector_errors e ON e.collector_run_id=r.id "
                "GROUP BY r.id ORDER BY r.id"
            ).fetchall()
        finally:
            connection.close()
        collectors: dict[str, dict[str, object]] = {}
        for row in rows:
            name = str(row["collector"])
            summary = collectors.setdefault(
                name,
                {
                    "collector": name,
                    "run_count": 0,
                    "success_count": 0,
                    "partial_count": 0,
                    "failure_count": 0,
                    "running_count": 0,
                    "item_count": 0,
                    "error_count": 0,
                    "last_status": None,
                    "last_run_at": None,
                },
            )
            summary["run_count"] = int(str(summary["run_count"])) + 1
            status_value = str(row["status"])
            key = {
                "succeeded": "success_count",
                "partial": "partial_count",
                "running": "running_count",
            }.get(status_value, "failure_count")
            summary[key] = int(str(summary[key])) + 1
            summary["item_count"] = int(str(summary["item_count"])) + int(row["item_count"])
            summary["error_count"] = int(str(summary["error_count"])) + int(row["error_count"])
            summary["last_status"] = status_value
            summary["last_run_at"] = row["finished_at"] or row["started_at"]
        return {
            "path": str(path),
            "application_id": application_id,
            "schema_version": schema_version,
            "expected_schema_version": len(available_migrations()),
            "integrity": list(integrity),
            "foreign_key_violations": foreign_keys,
            "collectors": [collectors[name] for name in sorted(collectors)],
        }

    def dependency(self, name: str) -> str | None:
        try:
            return importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            return None

    def service(self, name: str) -> Mapping[str, object]:
        result = self.runner(
            ("systemctl", "show", "--property=LoadState,ActiveState,SubState", "--value", name),
            5,
        )
        values = result.stdout.splitlines()
        if result.returncode != 0 or len(values) < 3:
            return {"unit": name, "available": False}
        return {
            "unit": name,
            "available": values[0] != "not-found",
            "load_state": values[0],
            "active_state": values[1],
            "sub_state": values[2],
        }

    def clock_sync(self) -> bool | None:
        result = self.runner(("timedatectl", "show", "--property=NTPSynchronized", "--value"), 5)
        if result.returncode != 0:
            return None
        value = result.stdout.strip().casefold()
        return True if value == "yes" else False if value == "no" else None

    def protected_state(self) -> Sequence[DiagnosticCheck]:
        return (
            self._nmap_script_check(),
            self._nmap_schedule_check(),
            self._scanopy_check(),
        )

    def _nmap_script_check(self) -> DiagnosticCheck:
        try:
            metadata = self.nmap_script.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise OSError("unsafe script path")
            digest = hashlib.sha256(self.nmap_script.read_bytes()).hexdigest()
        except OSError:
            return _check("nmap_script", "coexistence", "error", "Protected nmap script missing")
        status_value = "ok" if digest == self.nmap_sha256 else "error"
        message = (
            "Protected nmap script matches baseline"
            if status_value == "ok"
            else "Protected nmap script differs from baseline"
        )
        return _check(
            "nmap_script",
            "coexistence",
            status_value,
            message,
            {"sha256": digest, "matches_baseline": digest == self.nmap_sha256},
        )

    def _nmap_schedule_check(self) -> DiagnosticCheck:
        commands = (
            ("crontab", "-l"),
            ("sudo", "-n", "crontab", "-l"),
            ("systemctl", "list-timers", "--all", "--no-pager", "--plain"),
            (
                "rg",
                "--files-with-matches",
                "--no-messages",
                "--ignore-case",
                r"network-discovery|network-discovery-scan|\bnmap\b",
                "/etc/crontab",
                "/etc/cron.d",
                "/etc/cron.hourly",
                "/etc/cron.daily",
                "/etc/cron.weekly",
                "/etc/cron.monthly",
                "/var/spool/cron",
            ),
        )
        results = [self.runner(command, 5) for command in commands]
        lines = [
            line
            for result in results
            for line in result.stdout.casefold().splitlines()
            if "field-discovery-nmap-import" not in line
        ]
        found = results[3].returncode == 0 or any(
            "network-discovery-scan" in line or re.search(r"\bnmap\b", line) for line in lines
        )
        readable = (
            all(result.returncode == 0 or result.reason == "no_crontab" for result in results[:2])
            and results[2].returncode == 0
            and results[3].returncode in {0, 1}
        )
        if found:
            return _check(
                "nmap_schedule",
                "coexistence",
                "error",
                "Unexpected nmap schedule detected",
            )
        if not readable:
            return _check(
                "nmap_schedule",
                "coexistence",
                "warning",
                "Nmap schedule could not be fully inspected",
            )
        return _check("nmap_schedule", "coexistence", "ok", "No competing nmap schedule detected")

    def _scanopy_check(self) -> DiagnosticCheck:
        result = self.runner(
            (
                "docker",
                "inspect",
                "--format",
                "{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}"
                "{{else}}none{{end}}|{{.HostConfig.RestartPolicy.Name}}",
                *SCANOPY_CONTAINERS,
            ),
            10,
        )
        if result.returncode != 0:
            return _check("scanopy", "coexistence", "warning", "Scanopy status is unavailable")
        rows = [line.strip().lstrip("/").split("|") for line in result.stdout.splitlines()]
        healthy = {
            row[0]
            for row in rows
            if len(row) == 4
            and row[1] == "running"
            and row[2] in {"healthy", "none"}
            and row[3] == "unless-stopped"
        }
        ok = healthy == set(SCANOPY_CONTAINERS)
        return _check(
            "scanopy",
            "coexistence",
            "ok" if ok else "error",
            "Scanopy containers are healthy" if ok else "Scanopy containers are not healthy",
            {"healthy_count": len(healthy), "expected_count": len(SCANOPY_CONTAINERS)},
        )


def _check(
    name: str,
    category: str,
    status: str,
    message: str,
    details: Mapping[str, object] | None = None,
) -> DiagnosticCheck:
    return DiagnosticCheck(name, category, status, message, details or {})


def _with_age(summary: Mapping[str, object], now: datetime) -> dict[str, object]:
    result = dict(summary)
    value = result.get("last_run_at")
    try:
        observed = datetime.fromisoformat(str(value))
        if observed.tzinfo is None:
            raise ValueError
        result["age_seconds"] = max(0, int((now - observed.astimezone(UTC)).total_seconds()))
    except (TypeError, ValueError):
        result["age_seconds"] = None
    return result


def collect_status(
    configuration: Mapping[str, Any], *, probe: DiagnosticProbe | None = None
) -> dict[str, object]:
    active = probe or LocalDiagnosticProbe()
    now = active.now().astimezone(UTC)
    checks: list[DiagnosticCheck] = []
    try:
        network = dict(active.network(configuration))
        checks.append(_check("network", "network", "ok", "Interface and subnet resolved"))
    except (SubnetResolutionError, OSError, ValueError):
        network = {}
        checks.append(_check("network", "network", "error", "Interface and subnet unavailable"))

    paths = configuration["paths"]
    path_results: list[Mapping[str, object]] = []
    for key, expected in (("data_root", "directory"), ("nmap_results", "directory")):
        result = active.path(Path(paths[key]), expected=expected)
        path_results.append(result)
        valid = (
            bool(result.get("exists"))
            and not bool(result.get("symlink"))
            and result.get("actual") == expected
            and bool(result.get("readable"))
            and (key != "data_root" or bool(result.get("writable")))
        )
        checks.append(
            _check(
                f"path_{key}",
                "paths",
                "ok" if valid else "error",
                f"{key} path is usable" if valid else f"{key} path is unavailable or unsafe",
            )
        )

    try:
        database = dict(active.database(Path(paths["database"])))
        database_ok = (
            database.get("application_id") == APPLICATION_ID
            and database.get("schema_version") == database.get("expected_schema_version")
            and database.get("integrity") == ["ok"]
            and not database.get("foreign_key_violations")
        )
        checks.append(
            _check(
                "database",
                "database",
                "ok" if database_ok else "error",
                "Database integrity is healthy" if database_ok else "Database integrity failed",
            )
        )
    except (OSError, sqlite3.Error, KeyError, ValueError):
        database = {"path": str(paths["database"]), "collectors": []}
        checks.append(_check("database", "database", "error", "Database is unavailable"))

    try:
        disk = dict(active.disk(Path(paths["data_root"])))
        storage = cast(Mapping[str, object], configuration.get("storage", {}))
        minimum_bytes = cast(int, storage.get("minimum_free_bytes", 0))
        minimum_percent = cast(int, storage.get("minimum_free_percent", 0))
        disk_ok = (
            int(cast(int, disk.get("free_bytes", 0))) >= minimum_bytes
            and float(cast(float, disk.get("free_percent", 0.0))) >= minimum_percent
        )
        checks.append(
            _check(
                "disk",
                "storage",
                "ok" if disk_ok else "error",
                "Disk reserve is healthy"
                if disk_ok
                else "Disk reserve is below the configured threshold",
                {
                    "minimum_free_bytes": minimum_bytes,
                    "minimum_free_percent": minimum_percent,
                },
            )
        )
    except OSError:
        disk = {}
        checks.append(_check("disk", "storage", "error", "Disk usage is unavailable"))

    database_collectors = cast(Sequence[object], database.get("collectors", []))
    collectors = [_with_age(item, now) for item in database_collectors if isinstance(item, Mapping)]
    errors = sum(item.status == "error" for item in checks)
    warnings = sum(item.status == "warning" for item in checks)
    return {
        "schema_version": 1,
        "generated_at": now.isoformat(),
        "ok": errors == 0,
        "summary": {"checks": len(checks), "errors": errors, "warnings": warnings},
        "network": network,
        "paths": path_results,
        "database": database,
        "disk": disk,
        "collectors": collectors,
        "checks": [item.as_dict() for item in checks],
    }


def collect_doctor(
    configuration: Mapping[str, Any], *, probe: DiagnosticProbe | None = None
) -> dict[str, object]:
    active = probe or LocalDiagnosticProbe()
    report = collect_status(configuration, probe=active)
    checks = [DiagnosticCheck(**item) for item in cast(list[dict[str, Any]], report["checks"])]
    dependencies: dict[str, str | None] = {}
    for name in DEPENDENCIES:
        version = active.dependency(name)
        dependencies[name] = version
        checks.append(
            _check(
                f"dependency_{name.casefold()}",
                "dependencies",
                "ok" if version else "error",
                f"Dependency {name} is installed" if version else f"Dependency {name} is missing",
                {"version": version} if version else {},
            )
        )
    services: list[Mapping[str, object]] = []
    for name in CODEXNET_UNITS:
        service = active.service(name)
        services.append(service)
        available = bool(service.get("available"))
        running = service.get("active_state") == "active"
        checks.append(
            _check(
                f"service_{name}",
                "services",
                "ok" if running else "warning" if not available else "error",
                f"{name} is active"
                if running
                else f"{name} is not installed"
                if not available
                else f"{name} is not active",
            )
        )
    synchronized = active.clock_sync()
    checks.append(
        _check(
            "clock",
            "clock",
            "ok" if synchronized is True else "warning" if synchronized is None else "error",
            "System clock is synchronized"
            if synchronized is True
            else "Clock synchronization status is unavailable"
            if synchronized is None
            else "System clock is not synchronized",
        )
    )
    checks.extend(active.protected_state())
    errors = sum(item.status == "error" for item in checks)
    warnings = sum(item.status == "warning" for item in checks)
    report.update(
        {
            "ok": errors == 0,
            "summary": {"checks": len(checks), "errors": errors, "warnings": warnings},
            "dependencies": dependencies,
            "services": services,
            "clock": {"synchronized": synchronized},
            "checks": [item.as_dict() for item in checks],
        }
    )
    return report
