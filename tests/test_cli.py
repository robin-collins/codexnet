"""Offline and unprivileged CLI contract tests."""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import sqlite3
from pathlib import Path

import pytest
import yaml

from field_discovery import cli
from field_discovery.repository import IntegrityResult, RepositoryError
from field_discovery.subnet import SubnetDescription, SubnetResolutionError

ROOT = Path(__file__).parents[1]
CONFIG = ROOT / "config/example.yaml"
NMAP_FIXTURE = ROOT / "tests/fixtures/nmap/success.xml"


def invoke(*arguments: str) -> int:
    return cli.run(["--config", str(CONFIG), *arguments], run_id="test-run")


def database_config(tmp_path: Path) -> tuple[Path, Path]:
    document = yaml.safe_load(CONFIG.read_text())
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    document["paths"]["data_root"] = str(root)
    document["paths"]["database"] = str(root / "discovery.db")
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(document))
    return path, root


def test_help_and_version_do_not_load_configuration_or_network(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network or config loading attempted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(cli, "load_config", forbidden)
    with pytest.raises(SystemExit) as help_exit:
        cli.run(["--help"])
    assert help_exit.value.code == 0
    assert "collect" in capsys.readouterr().out
    with pytest.raises(SystemExit) as version_exit:
        cli.run(["--version"])
    assert version_exit.value.code == 0
    assert "field-discovery 0.1.0" in capsys.readouterr().out


def test_usage_errors_have_stable_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.run(["unknown"])
    assert caught.value.code == cli.ExitCode.USAGE
    assert "usage:" in capsys.readouterr().err


def test_validate_human_output_is_offline_and_unprivileged(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def network_forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network attempted")

    monkeypatch.setattr(socket, "socket", network_forbidden)
    monkeypatch.setattr("os.geteuid", lambda: 65534)
    assert invoke("config", "validate") == cli.ExitCode.SUCCESS
    captured = capsys.readouterr()
    assert captured.out == "Configuration is valid.\n"
    assert "configuration_valid" in captured.err
    assert "run_id=test-run" in captured.err


def test_validate_json_output_and_logs_are_machine_readable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        cli.run(["--json", "--config", str(CONFIG), "config", "validate"], run_id="json-run")
        == cli.ExitCode.SUCCESS
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "command": "config validate",
        "message": "Configuration is valid.",
        "ok": True,
    }
    log = json.loads(captured.err)
    assert log["event"] == "configuration_valid"
    assert log["run_id"] == "json-run"
    assert "\x1b" not in captured.out + captured.err


@pytest.mark.parametrize(
    "arguments",
    [
        ("status",),
        ("collect", "passive", "status"),
        ("collect", "snmp", "--target", "192.168.50.10"),
        ("collect", "unifi", "--controller", "https://controller.invalid"),
        ("collect", "ad", "--domain", "example.invalid"),
        ("collect", "ssh", "--target", "192.168.50.20"),
        ("report", "generate", "--format", "docx"),
        ("report", "validate", "/tmp/report.docx"),
        ("doctor",),
    ],
)
def test_spec_placeholder_commands_are_present_and_explicit(
    arguments: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    assert invoke(*arguments) == cli.ExitCode.NOT_IMPLEMENTED
    captured = capsys.readouterr()
    assert "not implemented yet" in captured.out
    assert "command_unavailable" in captured.err


def test_scan_requires_explicit_noninteractive_confirmation(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert invoke("scan", "nmap") == cli.ExitCode.SCAN_REFUSED
    captured = capsys.readouterr()
    assert "rerun with --yes" in captured.out


def test_scan_interactive_confirmation_and_cancellation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from field_discovery.nmap_scan import ScanResult

    class InteractiveInput:
        @staticmethod
        def isatty() -> bool:
            return True

    result = ScanResult(
        status="succeeded",
        exit_code=0,
        interface="eth0",
        cidr="192.168.50.0/24",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        duration_seconds=1.0,
        script_sha256="a" * 64,
    )
    monkeypatch.setattr(cli.sys, "stdin", InteractiveInput())
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    assert invoke("scan", "nmap") == cli.ExitCode.SCAN_REFUSED
    assert "cancelled" in capsys.readouterr().out

    monkeypatch.setattr("builtins.input", lambda _prompt: "SCAN")
    monkeypatch.setattr(cli, "run_nmap_scan", lambda *_args, **_kwargs: result)
    assert invoke("scan", "nmap") == cli.ExitCode.SUCCESS
    assert "succeeded" in capsys.readouterr().out


def test_scan_cli_propagates_result_and_emits_audit_context(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from field_discovery.nmap_scan import ScanResult

    result = ScanResult(
        status="failed",
        exit_code=23,
        interface="eth0",
        cidr="192.168.50.0/24",
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        duration_seconds=1.0,
        script_sha256="a" * 64,
    )
    monkeypatch.setattr(cli, "run_nmap_scan", lambda *_args, **_kwargs: result)
    assert invoke("scan", "nmap", "--yes", "--timeout", "9") == 23
    captured = capsys.readouterr()
    assert "exit code 23" in captured.out
    assert "nmap_scan_finished" in captured.err


def test_scan_cli_json_never_prompts_and_maps_safe_launch_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from field_discovery.nmap_scan import ScanLaunchError

    assert (
        cli.run(["--json", "--config", str(CONFIG), "scan", "nmap"], run_id="scan-no-confirm")
        == cli.ExitCode.SCAN_REFUSED
    )
    assert json.loads(capsys.readouterr().out)["ok"] is False

    def fail(*_args: object, **_kwargs: object) -> None:
        raise ScanLaunchError("synthetic refusal")

    monkeypatch.setattr(cli, "run_nmap_scan", fail)
    assert invoke("scan", "nmap", "--yes") == cli.ExitCode.SCAN_REFUSED
    captured = capsys.readouterr()
    assert "synthetic refusal" in captured.out
    assert "nmap_scan_refused" in captured.err


def test_invalid_configuration_is_actionable_and_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("schema_version: 99\n")
    assert (
        cli.run(["--json", "--config", str(invalid), "config", "validate"], run_id="invalid-run")
        == cli.ExitCode.CONFIGURATION
    )
    captured = capsys.readouterr()
    assert json.loads(captured.out)["ok"] is False
    assert json.loads(captured.err)["event"] == "configuration_invalid"
    assert "schema_version" in captured.out


def test_missing_configuration_is_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli.run(["--config", "/does/not/exist", "status"], run_id="missing-run")
    assert code == cli.ExitCode.CONFIGURATION
    assert "cannot read configuration" in capsys.readouterr().out


def test_discover_subnet_human_and_json_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    description = SubnetDescription(
        interface="eth0",
        address="192.168.50.9",
        cidr="192.168.50.0/24",
        gateway="192.168.50.1",
        dns_servers=("192.168.50.1",),
        address_source="dhcp",
        route_source="dhcp",
        route_metric=100,
        active_target_permitted=True,
        active_target_reasons=(),
    )
    monkeypatch.setattr("field_discovery.cli.resolve_subnet", lambda _config: description)
    assert invoke("discover", "subnet") == cli.ExitCode.SUCCESS
    assert "active target permitted" in capsys.readouterr().out

    assert (
        cli.run(["--json", "--config", str(CONFIG), "discover", "subnet"], run_id="subnet-run")
        == cli.ExitCode.SUCCESS
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["subnet"]["cidr"] == "192.168.50.0/24"


def test_discover_subnet_failure_is_stable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(_config: object) -> None:
        raise SubnetResolutionError("synthetic unavailable")

    monkeypatch.setattr("field_discovery.cli.resolve_subnet", fail)
    assert invoke("discover", "subnet") == cli.ExitCode.RESOLUTION
    captured = capsys.readouterr()
    assert "synthetic unavailable" in captured.out
    assert "subnet_resolution_failed" in captured.err


def test_nmap_import_cli_reports_idempotent_summary(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, root = database_config(tmp_path)
    scan_root = tmp_path / "nmap"
    scan_root.mkdir()
    artifact = scan_root / "scan.xml"
    shutil.copyfile(NMAP_FIXTURE, artifact)
    os.utime(artifact, (1_700_000_000, 1_700_000_000))
    arguments = [
        "--json",
        "--config",
        str(config),
        "import",
        "nmap",
        "--path",
        str(scan_root),
    ]

    assert cli.run(arguments, run_id="import-first") == cli.ExitCode.SUCCESS
    first = json.loads(capsys.readouterr().out)
    assert (first["imported"], first["hosts"], first["errors"]) == (1, 1, 0)
    assert cli.run(arguments, run_id="import-repeat") == cli.ExitCode.SUCCESS
    repeated = json.loads(capsys.readouterr().out)
    assert (repeated["imported"], repeated["skipped"]) == (0, 1)
    malformed = scan_root / "malformed.xml"
    malformed.write_text("<nmaprun><host></nmaprun>")
    os.utime(malformed, (1_700_000_000, 1_700_000_000))
    assert cli.run(arguments, run_id="import-partial") == cli.ExitCode.SUCCESS
    partial = json.loads(capsys.readouterr().out)
    assert (partial["errors"], partial["imported"]) == (1, 0)
    connection = sqlite3.connect(root / "discovery.db")
    assert connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0] == 1
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM collector_runs WHERE status = 'succeeded'"
        ).fetchone()[0]
        == 2
    )
    assert (
        connection.execute(
            "SELECT COUNT(*) FROM collector_runs WHERE status = 'partial'"
        ).fetchone()[0]
        == 1
    )
    assert connection.execute("SELECT COUNT(*) FROM collector_errors").fetchone()[0] == 1
    connection.close()


def test_nmap_import_cli_failure_has_stable_exit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, _root = database_config(tmp_path)
    missing = tmp_path / "missing"
    code = cli.run(
        ["--config", str(config), "import", "nmap", "--path", str(missing)],
        run_id="import-failed",
    )
    assert code == cli.ExitCode.IMPORT
    captured = capsys.readouterr()
    assert "path is unavailable" in captured.out
    assert "nmap_import_failed" in captured.err

    document = yaml.safe_load(CONFIG.read_text())
    absent_root = tmp_path / "absent-data"
    document["paths"]["data_root"] = str(absent_root)
    document["paths"]["database"] = str(absent_root / "discovery.db")
    unavailable_config = tmp_path / "unavailable-config.yaml"
    unavailable_config.write_text(yaml.safe_dump(document))
    code = cli.run(
        ["--config", str(unavailable_config), "import", "nmap", "--path", str(missing)],
        run_id="import-repository-failed",
    )
    assert code == cli.ExitCode.IMPORT
    assert "data root is unavailable" in capsys.readouterr().out


def test_database_cli_check_backup_and_prune(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, root = database_config(tmp_path)
    prefix = ["--json", "--config", str(config), "db"]
    assert cli.run([*prefix, "check"], run_id="db-check") == cli.ExitCode.SUCCESS
    checked = json.loads(capsys.readouterr().out)
    assert checked["integrity"] == ["ok"]
    assert checked["foreign_key_violations"] == []

    explicit = root / "explicit-backup.db"
    assert (
        cli.run([*prefix, "backup", "--output", str(explicit)], run_id="db-backup")
        == cli.ExitCode.SUCCESS
    )
    assert explicit.is_file()
    assert json.loads(capsys.readouterr().out)["path"] == str(explicit)

    assert cli.run([*prefix, "backup"], run_id="db-backup-default") == cli.ExitCode.SUCCESS
    assert "discovery-backup-" in json.loads(capsys.readouterr().out)["path"]

    assert cli.run([*prefix, "prune"], run_id="db-prune") == cli.ExitCode.SUCCESS
    assert json.loads(capsys.readouterr().out)["dry_run"] is True
    assert cli.run([*prefix, "prune", "--apply"], run_id="db-prune") == cli.ExitCode.SUCCESS
    assert json.loads(capsys.readouterr().out)["dry_run"] is False


def test_database_cli_failed_integrity_and_operation_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, _root = database_config(tmp_path)

    class FailedRepository:
        def integrity_check(self) -> IntegrityResult:
            return IntegrityResult(("damaged",), ({"table": "fixture"},))

        def close(self) -> None:
            pass

    monkeypatch.setattr(cli.Repository, "open", lambda *_args, **_kwargs: FailedRepository())
    arguments = ["--json", "--config", str(config), "db", "check"]
    assert cli.run(arguments, run_id="db-failed") == cli.ExitCode.DATABASE
    assert json.loads(capsys.readouterr().out)["ok"] is False

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RepositoryError("synthetic failure")

    monkeypatch.setattr(cli.Repository, "open", fail)
    assert cli.run(arguments, run_id="db-error") == cli.ExitCode.DATABASE
    captured = capsys.readouterr()
    assert "synthetic failure" in captured.out
    assert "database_operation_failed" in captured.err


def test_main_maps_interrupt_and_unexpected_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli, "run", lambda: 7)
    with pytest.raises(SystemExit, match="7"):
        cli.main()

    def interrupt() -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "run", interrupt)
    with pytest.raises(SystemExit, match="130"):
        cli.main()

    def fail() -> int:
        raise RuntimeError("synthetic")

    logger = logging.getLogger("field_discovery")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    monkeypatch.setattr(cli, "run", fail)
    with pytest.raises(SystemExit, match=str(cli.ExitCode.INTERNAL)):
        cli.main()
