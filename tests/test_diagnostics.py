"""Read-only status and doctor probes, schemas, and failure isolation tests."""

from __future__ import annotations

import hashlib
import sqlite3
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from field_discovery import diagnostics
from field_discovery.database import APPLICATION_ID
from field_discovery.diagnostics import (
    CODEXNET_UNITS,
    DEPENDENCIES,
    SCANOPY_CONTAINERS,
    CommandResult,
    DiagnosticCheck,
    LocalDiagnosticProbe,
    collect_doctor,
    collect_status,
)
from field_discovery.repository import Repository
from field_discovery.subnet import SubnetResolutionError

NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)


def configuration(tmp_path: Path) -> dict[str, Any]:
    return {
        "interface": {"name": "eth0", "allow_excluded_interface": False},
        "active": {"approved_ranges": ["192.0.2.0/24"], "max_hosts": 256},
        "storage": {"minimum_free_bytes": 100, "minimum_free_percent": 10},
        "paths": {
            "data_root": str(tmp_path / "data"),
            "database": str(tmp_path / "data" / "discovery.db"),
            "nmap_results": str(tmp_path / "nmap"),
        },
    }


class FakeProbe:
    def __init__(self, tmp_path: Path) -> None:
        self.now_value = NOW
        self.network_value: object = {
            "interface": "eth0",
            "address": "192.0.2.10",
            "cidr": "192.0.2.0/24",
            "gateway": "192.0.2.1",
            "dns_servers": ["192.0.2.53"],
            "active_target_permitted": True,
        }
        self.path_values: dict[str, MappingValue] = {
            "data": {
                "exists": True,
                "actual": "directory",
                "symlink": False,
                "readable": True,
                "writable": True,
            },
            "nmap": {
                "exists": True,
                "actual": "directory",
                "symlink": False,
                "readable": True,
                "writable": False,
            },
        }
        self.database_value: object = {
            "application_id": APPLICATION_ID,
            "schema_version": 4,
            "expected_schema_version": 4,
            "integrity": ["ok"],
            "foreign_key_violations": 0,
            "collectors": [
                {
                    "collector": "snmp",
                    "run_count": 2,
                    "success_count": 1,
                    "partial_count": 1,
                    "failure_count": 0,
                    "running_count": 0,
                    "item_count": 8,
                    "error_count": 1,
                    "last_status": "partial",
                    "last_run_at": (NOW - timedelta(seconds=90)).isoformat(),
                },
                {
                    "collector": "bad-time",
                    "run_count": 1,
                    "success_count": 0,
                    "partial_count": 0,
                    "failure_count": 1,
                    "running_count": 0,
                    "item_count": 0,
                    "error_count": 1,
                    "last_status": "failed",
                    "last_run_at": "malformed",
                },
            ],
        }
        self.disk_value: object = {
            "total_bytes": 1000,
            "used_bytes": 250,
            "free_bytes": 750,
            "free_percent": 75.0,
        }
        self.missing_dependencies: set[str] = set()
        self.service_values: dict[str, MappingValue] = {
            name: {
                "unit": name,
                "available": True,
                "active_state": "active",
                "sub_state": "running",
            }
            for name in CODEXNET_UNITS
        }
        self.clock_value: bool | None = True
        self.protected_values: list[DiagnosticCheck] = [
            DiagnosticCheck("nmap", "coexistence", "ok", "baseline", {})
        ]

    def now(self) -> datetime:
        return self.now_value

    def network(self, configuration: object) -> MappingValue:
        del configuration
        if isinstance(self.network_value, BaseException):
            raise self.network_value
        return self.network_value  # type: ignore[return-value]

    def path(self, path: Path, *, expected: str) -> MappingValue:
        del expected
        return {"path": str(path), **self.path_values[path.name]}

    def disk(self, path: Path) -> MappingValue:
        del path
        if isinstance(self.disk_value, BaseException):
            raise self.disk_value
        return self.disk_value  # type: ignore[return-value]

    def database(self, path: Path) -> MappingValue:
        del path
        if isinstance(self.database_value, BaseException):
            raise self.database_value
        return self.database_value  # type: ignore[return-value]

    def dependency(self, name: str) -> str | None:
        return None if name in self.missing_dependencies else "fixture-version"

    def service(self, name: str) -> MappingValue:
        return self.service_values[name]

    def clock_sync(self) -> bool | None:
        return self.clock_value

    def protected_state(self) -> list[DiagnosticCheck]:
        return self.protected_values


MappingValue = dict[str, object]


def setup_repository(tmp_path: Path) -> tuple[Repository, Path]:
    root = tmp_path / "data"
    root.mkdir()
    path = root / "discovery.db"
    repository = Repository.open(path, data_root=root)
    return repository, path


def test_status_schema_collector_aggregates_and_ages_are_deterministic(tmp_path: Path) -> None:
    probe = FakeProbe(tmp_path)
    report = collect_status(configuration(tmp_path), probe=probe)
    assert report["schema_version"] == 1
    assert report["generated_at"] == NOW.isoformat()
    assert report["ok"] is True
    assert report["summary"] == {"checks": 5, "errors": 0, "warnings": 0}
    collectors = report["collectors"]
    assert collectors[0]["age_seconds"] == 90  # type: ignore[index]
    assert collectors[1]["age_seconds"] is None  # type: ignore[index]
    assert report["network"]["cidr"] == "192.0.2.0/24"  # type: ignore[index]
    assert [item["name"] for item in report["checks"]] == [  # type: ignore[index]
        "network",
        "path_data_root",
        "path_nmap_results",
        "database",
        "disk",
    ]


def test_status_isolates_every_probe_failure_and_rejects_unsafe_paths(tmp_path: Path) -> None:
    probe = FakeProbe(tmp_path)
    probe.network_value = SubnetResolutionError("password=must-not-escape")
    probe.path_values["data"]["writable"] = False
    probe.path_values["nmap"]["symlink"] = True
    probe.database_value = sqlite3.DatabaseError("token=must-not-escape")
    probe.disk_value = OSError("secret=must-not-escape")
    report = collect_status(configuration(tmp_path), probe=probe)
    assert report["ok"] is False
    assert report["summary"] == {"checks": 5, "errors": 5, "warnings": 0}
    serialized = str(report)
    assert "must-not-escape" not in serialized
    assert report["collectors"] == []
    assert report["database"]["collectors"] == []  # type: ignore[index]


def test_status_detects_wrong_database_identity_schema_integrity_and_foreign_keys(
    tmp_path: Path,
) -> None:
    for replacement in (
        {"application_id": 0},
        {"schema_version": 3},
        {"integrity": ["damaged"]},
        {"foreign_key_violations": 1},
    ):
        probe = FakeProbe(tmp_path)
        assert isinstance(probe.database_value, dict)
        probe.database_value.update(replacement)
        report = collect_status(configuration(tmp_path), probe=probe)
        database_check = next(
            item
            for item in report["checks"]
            if item["name"] == "database"  # type: ignore[union-attr]
        )
        assert database_check["status"] == "error"

    probe = FakeProbe(tmp_path)
    probe.disk_value = {"free_bytes": 99, "free_percent": 9.9}
    report = collect_status(configuration(tmp_path), probe=probe)
    disk_check = next(item for item in report["checks"] if item["name"] == "disk")  # type: ignore[union-attr]
    assert disk_check["status"] == "error"
    assert disk_check["details"] == {
        "minimum_free_bytes": 100,
        "minimum_free_percent": 10,
    }


def test_doctor_classifies_dependencies_services_clock_and_protected_checks(
    tmp_path: Path,
) -> None:
    probe = FakeProbe(tmp_path)
    healthy = collect_doctor(configuration(tmp_path), probe=probe)
    assert healthy["ok"] is True
    assert healthy["dependencies"] == {name: "fixture-version" for name in DEPENDENCIES}
    assert healthy["clock"] == {"synchronized": True}

    probe.missing_dependencies.add(DEPENDENCIES[0])
    probe.service_values[CODEXNET_UNITS[0]] = {
        "unit": CODEXNET_UNITS[0],
        "available": False,
    }
    probe.service_values[CODEXNET_UNITS[1]] = {
        "unit": CODEXNET_UNITS[1],
        "available": True,
        "active_state": "failed",
    }
    probe.clock_value = False
    probe.protected_values = [
        DiagnosticCheck("scanopy", "coexistence", "warning", "unavailable", {})
    ]
    degraded = collect_doctor(configuration(tmp_path), probe=probe)
    assert degraded["ok"] is False
    statuses = {item["name"]: item["status"] for item in degraded["checks"]}  # type: ignore[index]
    assert statuses[f"dependency_{DEPENDENCIES[0].casefold()}"] == "error"
    assert statuses[f"service_{CODEXNET_UNITS[0]}"] == "warning"
    assert statuses[f"service_{CODEXNET_UNITS[1]}"] == "error"
    assert statuses["clock"] == "error"
    probe.clock_value = None
    unknown = collect_doctor(configuration(tmp_path), probe=probe)
    assert (
        next(item for item in unknown["checks"] if item["name"] == "clock")[  # type: ignore[union-attr]
            "status"
        ]
        == "warning"
    )


def test_local_path_and_disk_probes_are_read_only_and_symlink_visible(tmp_path: Path) -> None:
    probe = LocalDiagnosticProbe()
    assert probe.now().tzinfo is UTC
    missing = probe.path(tmp_path / "missing", expected="directory")
    assert missing == {
        "path": str(tmp_path / "missing"),
        "exists": False,
        "expected": "directory",
    }
    directory = tmp_path / "directory"
    directory.mkdir(mode=0o700)
    result = probe.path(directory, expected="directory")
    assert result["actual"] == "directory" and result["mode"] == "0700"
    regular = tmp_path / "regular"
    regular.write_text("fixture")
    assert probe.path(regular, expected="file")["actual"] == "file"
    linked = tmp_path / "linked"
    linked.symlink_to(regular)
    assert probe.path(linked, expected="file")["symlink"] is True
    usage = probe.disk(tmp_path / "not-created" / "child")
    assert usage["checked_path"] == str(tmp_path)
    assert int(usage["total_bytes"]) > 0


def test_local_database_probe_is_query_only_and_aggregates_runs(tmp_path: Path) -> None:
    repository, path = setup_repository(tmp_path)
    deployment = repository.upsert_deployment("fixture", "Fixture", NOW.isoformat())
    succeeded = repository.start_run(deployment, "snmp", NOW.isoformat())
    repository.finish_run(succeeded, "succeeded", NOW.isoformat(), 3)
    partial = repository.start_run(deployment, "snmp", NOW.isoformat())
    repository.record_collector_error(
        partial,
        category="fixture",
        detail="safe",
        retryable=False,
        source="snmp",
        observed_at=NOW.isoformat(),
    )
    repository.finish_run(partial, "partial", NOW.isoformat(), 2)
    failed = repository.start_run(deployment, "ssh", NOW.isoformat())
    repository.finish_run(failed, "failed", NOW.isoformat(), 0)
    repository.start_run(deployment, "running", NOW.isoformat())
    repository.close()

    before = path.stat().st_mtime_ns
    result = LocalDiagnosticProbe().database(path)
    after = path.stat().st_mtime_ns
    assert before == after
    assert result["application_id"] == APPLICATION_ID
    assert result["schema_version"] == result["expected_schema_version"]
    assert result["integrity"] == ["ok"]
    snmp = next(  # type: ignore[union-attr]
        item for item in result["collectors"] if item["collector"] == "snmp"
    )
    assert (snmp["run_count"], snmp["success_count"], snmp["partial_count"]) == (2, 1, 1)
    assert (snmp["item_count"], snmp["error_count"], snmp["last_status"]) == (5, 1, "partial")
    running = next(  # type: ignore[union-attr]
        item for item in result["collectors"] if item["collector"] == "running"
    )
    assert (running["running_count"], running["failure_count"]) == (1, 0)

    linked = tmp_path / "database-link"
    linked.symlink_to(path)
    with pytest.raises(OSError, match="regular"):
        LocalDiagnosticProbe().database(linked)
    with pytest.raises(OSError, match="regular"):
        LocalDiagnosticProbe().database(tmp_path)


def test_local_dependency_service_and_clock_parsers_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], float]] = []
    responses = iter(
        (
            CommandResult(0, "loaded\nactive\nrunning\nextra-private\n"),
            CommandResult(1, "secret-value"),
            CommandResult(0, "yes\n"),
            CommandResult(0, "no\n"),
            CommandResult(0, "unknown\n"),
            CommandResult(1, "secret-value"),
        )
    )

    def runner(arguments: Sequence[str], timeout: float) -> CommandResult:
        calls.append((tuple(arguments), timeout))
        return next(responses)

    probe = LocalDiagnosticProbe(runner=runner)
    service = probe.service("fixture.service")
    assert service["active_state"] == "active"
    assert probe.service("missing.service") == {"unit": "missing.service", "available": False}
    assert probe.clock_sync() is True
    assert probe.clock_sync() is False
    assert probe.clock_sync() is None
    assert probe.clock_sync() is None
    assert calls[0][0][:2] == ("systemctl", "show")

    monkeypatch.setattr(diagnostics.importlib.metadata, "version", lambda _name: "1.2.3")
    assert probe.dependency("fixture") == "1.2.3"

    def missing(_name: str) -> str:
        raise diagnostics.importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(diagnostics.importlib.metadata, "version", missing)
    assert probe.dependency("fixture") is None


def test_local_network_delegates_to_read_only_subnet_resolver(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: list[object] = []

    class Description:
        def as_dict(self) -> dict[str, object]:
            return {"interface": "fixture", "cidr": "192.0.2.0/24"}

    def resolver(value: object) -> Description:
        captured.append(value)
        return Description()

    monkeypatch.setattr(diagnostics, "resolve_subnet", resolver)
    config = configuration(tmp_path)
    assert LocalDiagnosticProbe().network(config)["interface"] == "fixture"
    assert captured == [config]


def test_local_nmap_script_baseline_mismatch_missing_and_unsafe(tmp_path: Path) -> None:
    script = tmp_path / "scan.sh"
    script.write_text("fixture")
    digest = hashlib.sha256(b"fixture").hexdigest()
    matching = LocalDiagnosticProbe(nmap_script=script, nmap_sha256=digest)._nmap_script_check()
    assert matching.status == "ok"
    assert matching.details["matches_baseline"] is True
    assert LocalDiagnosticProbe(
        nmap_script=script, nmap_sha256="0" * 64
    )._nmap_script_check().status == ("error")
    script.unlink()
    assert LocalDiagnosticProbe(nmap_script=script)._nmap_script_check().status == "error"
    target = tmp_path / "target"
    target.write_text("fixture")
    script.symlink_to(target)
    assert LocalDiagnosticProbe(nmap_script=script)._nmap_script_check().status == "error"


@pytest.mark.parametrize(
    ("responses", "status"),
    [
        (
            (
                CommandResult(1, "", "no_crontab"),
                CommandResult(1, "", "no_crontab"),
                CommandResult(0, "timers"),
                CommandResult(1, ""),
            ),
            "ok",
        ),
        (
            (
                CommandResult(0, "nmap scan"),
                CommandResult(1, "", "no_crontab"),
                CommandResult(0, ""),
                CommandResult(1, ""),
            ),
            "error",
        ),
        (
            (
                CommandResult(1, "", "no_crontab"),
                CommandResult(1, "", "no_crontab"),
                CommandResult(0, ""),
                CommandResult(0, "/etc/cron.d/fixture"),
            ),
            "error",
        ),
        (
            (
                CommandResult(127, ""),
                CommandResult(1, ""),
                CommandResult(0, ""),
                CommandResult(2, ""),
            ),
            "warning",
        ),
    ],
)
def test_local_nmap_schedule_classification(
    responses: tuple[CommandResult, ...], status: str
) -> None:
    values = iter(responses)
    probe = LocalDiagnosticProbe(runner=lambda _args, _timeout: next(values))
    assert probe._nmap_schedule_check().status == status


def test_local_scanopy_inspection_is_narrow_and_classified() -> None:
    calls: list[tuple[str, ...]] = []

    def healthy(arguments: Sequence[str], _timeout: float) -> CommandResult:
        calls.append(tuple(arguments))
        return CommandResult(
            0,
            "\n".join(f"/{name}|running|healthy|unless-stopped" for name in SCANOPY_CONTAINERS),
        )

    result = LocalDiagnosticProbe(runner=healthy)._scanopy_check()
    assert result.status == "ok" and result.details["healthy_count"] == 3
    assert calls[0][0:2] == ("docker", "inspect")
    assert "Config.Env" not in " ".join(calls[0])

    unavailable = LocalDiagnosticProbe(
        runner=lambda _args, _timeout: CommandResult(1, "private")
    )._scanopy_check()
    assert unavailable.status == "warning"
    unhealthy = LocalDiagnosticProbe(
        runner=lambda _args, _timeout: CommandResult(
            0, "/scanopy-server-1|exited|none|unless-stopped"
        )
    )._scanopy_check()
    assert unhealthy.status == "error"
    wrong_restart = LocalDiagnosticProbe(
        runner=lambda _args, _timeout: CommandResult(
            0,
            "\n".join(f"/{name}|running|healthy|no" for name in SCANOPY_CONTAINERS),
        )
    )._scanopy_check()
    assert wrong_restart.status == "error"


def test_protected_state_order_is_stable(tmp_path: Path) -> None:
    script = tmp_path / "scan"
    script.write_text("fixture")
    digest = hashlib.sha256(b"fixture").hexdigest()
    responses = iter(
        (
            CommandResult(1, ""),
            CommandResult(1, ""),
            CommandResult(0, "timers"),
            CommandResult(1, ""),
            CommandResult(
                0,
                "\n".join(f"/{name}|running|healthy|unless-stopped" for name in SCANOPY_CONTAINERS),
            ),
        )
    )
    probe = LocalDiagnosticProbe(
        runner=lambda _args, _timeout: next(responses),
        nmap_script=script,
        nmap_sha256=digest,
    )
    assert [item.name for item in probe.protected_state()] == [
        "nmap_script",
        "nmap_schedule",
        "scanopy",
    ]


def test_command_runner_discards_errors_and_bounds_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def success(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["fixture"], 0, "x" * 70_000, "private")

    monkeypatch.setattr(diagnostics.subprocess, "run", success)
    result = diagnostics._run(("fixture",), 1)
    assert result.returncode == 0 and len(result.stdout) == 65_536 and result.reason is None

    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["crontab"], 1, "", "no crontab for root"
        ),
    )
    assert diagnostics._run(("crontab", "-l"), 1).reason == "no_crontab"

    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("secret")),
    )
    assert diagnostics._run(("fixture",), 1) == CommandResult(127, "")


def test_future_and_naive_collector_times_are_safe() -> None:
    future = diagnostics._with_age({"last_run_at": (NOW + timedelta(days=1)).isoformat()}, NOW)
    assert future["age_seconds"] == 0
    assert (
        diagnostics._with_age({"last_run_at": NOW.replace(tzinfo=None).isoformat()}, NOW)[
            "age_seconds"
        ]
        is None
    )
    assert DiagnosticCheck("a", "b", "ok", "c", {}).as_dict()["name"] == "a"
