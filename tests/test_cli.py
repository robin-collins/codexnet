"""Offline and unprivileged CLI contract tests."""

from __future__ import annotations

import json
import logging
import socket
from pathlib import Path

import pytest
import yaml

from field_discovery import cli
from field_discovery.repository import IntegrityResult, RepositoryError
from field_discovery.subnet import SubnetDescription, SubnetResolutionError

ROOT = Path(__file__).parents[1]
CONFIG = ROOT / "config/example.yaml"


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
        ("import", "nmap", "--path", "/tmp/fixture.xml"),
        ("scan", "nmap"),
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
