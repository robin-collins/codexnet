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
from field_discovery.ad_detection import (
    ADDetectionError,
    ADDetectionResult,
    DetectionIssue,
    DomainControllerCandidate,
)
from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CollectorIssue,
    CollectorResult,
)
from field_discovery.repository import IntegrityResult, Repository, RepositoryError
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
        ("collect", "passive", "status"),
    ],
)
def test_spec_placeholder_commands_are_present_and_explicit(
    arguments: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    assert invoke(*arguments) == cli.ExitCode.NOT_IMPLEMENTED
    captured = capsys.readouterr()
    assert "not implemented yet" in captured.out
    assert "command_unavailable" in captured.err


def test_collect_ad_cli_uses_approved_target_and_opaque_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, root = database_config(tmp_path)
    contexts: list[CollectorContext] = []
    constructor: dict[str, object] = {}

    class FakeCollector:
        async def collect(self, collector_context: CollectorContext) -> CollectorResult:
            contexts.append(collector_context)
            return CollectorResult(9)

    def make_collector(*args: object, **kwargs: object) -> FakeCollector:
        constructor.update({"args": args, **kwargs})
        return FakeCollector()

    monkeypatch.setattr(cli, "ActiveDirectoryCollector", make_collector)
    code = cli.run(
        [
            "--json",
            "--config",
            str(config_path),
            "collect",
            "ad",
            "--target",
            "192.168.50.10",
        ],
        run_id="ad-collect",
    )
    assert code == cli.ExitCode.SUCCESS
    payload = json.loads(capsys.readouterr().out)
    assert (payload["records"], payload["limitations"], payload["transport"]) == (9, 0, "ldaps")
    assert payload["security_notice"] is None
    assert constructor["server_name"] == "dc1.example.invalid"
    assert constructor["documentation_groups"] == ["Documentation"]
    collector_context = contexts[0]
    assert collector_context.target == "192.168.50.10"
    assert collector_context.credential_ref is not None
    assert collector_context.credential_ref.key == "AD_SITE_PROFILE"
    connection = sqlite3.connect(root / "discovery.db")
    assert connection.execute("SELECT status FROM collector_runs").fetchone()[0] == "succeeded"
    connection.close()


def test_collect_ad_cli_partial_plaintext_notice_and_failed_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, _root = database_config(tmp_path)
    document = yaml.safe_load(config_path.read_text())
    document["collectors"]["ad"].update({"transport": "ldap", "allow_plaintext_ldap": True})
    config_path.write_text(yaml.safe_dump(document))

    class PartialCollector:
        async def collect(self, _context: object) -> CollectorResult:
            return CollectorResult(3, (CollectorIssue("partial", "fixture"),))

    monkeypatch.setattr(
        cli, "ActiveDirectoryCollector", lambda *_args, **_kwargs: PartialCollector()
    )
    arguments = [
        "--json",
        "--config",
        str(config_path),
        "collect",
        "ad",
        "--target",
        "192.168.50.10",
        "--server-name",
        "override.example.invalid",
        "--domain",
        "example.invalid",
    ]
    assert cli.run(arguments, run_id="ad-partial") == cli.ExitCode.SUCCESS
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "partial"
    assert "not transport encrypted" in payload["security_notice"]
    assert "ad_plaintext_ldap_explicitly_enabled" in captured.err

    class ExpiredCollector:
        async def collect(self, _context: object) -> CollectorResult:
            raise CollectorAuthenticationError("expired")

    monkeypatch.setattr(
        cli, "ActiveDirectoryCollector", lambda *_args, **_kwargs: ExpiredCollector()
    )
    assert cli.run(arguments, run_id="ad-expired") == cli.ExitCode.COLLECTOR
    assert json.loads(capsys.readouterr().out)["status"] == "failed"


def test_collect_ad_cli_refuses_missing_config_target_and_repository_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, _root = database_config(tmp_path)
    document = yaml.safe_load(config_path.read_text())
    document["collectors"]["ad"]["credential_ref"] = None
    config_path.write_text(yaml.safe_dump(document))
    arguments = [
        "--config",
        str(config_path),
        "collect",
        "ad",
        "--target",
        "192.168.50.10",
    ]
    assert cli.run(arguments, run_id="ad-no-ref") == cli.ExitCode.CONFIGURATION
    assert "credential reference" in capsys.readouterr().out

    document["collectors"]["ad"]["credential_ref"] = {
        "provider": "appliance_env",
        "key": "AD_SITE_PROFILE",
    }
    document["collectors"]["ad"]["server_name"] = None
    config_path.write_text(yaml.safe_dump(document))
    assert cli.run(arguments, run_id="ad-no-name") == cli.ExitCode.CONFIGURATION
    assert "domain, base DN, and server name" in capsys.readouterr().out

    document["collectors"]["ad"]["server_name"] = "dc1.example.invalid"
    config_path.write_text(yaml.safe_dump(document))
    outside = [*arguments[:-1], "10.0.0.1"]
    assert cli.run(outside, run_id="ad-outside") == cli.ExitCode.COLLECTOR
    assert "outside approved" in capsys.readouterr().out

    monkeypatch.setattr(
        cli.Repository, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline"))
    )
    assert cli.run(arguments, run_id="ad-offline") == cli.ExitCode.COLLECTOR
    assert "offline" in capsys.readouterr().out


def test_collect_snmp_cli_uses_common_scope_and_opaque_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, root = database_config(tmp_path)
    calls: list[object] = []

    class FakeCollector:
        async def collect(self, context: object) -> CollectorResult:
            calls.append(context)
            return CollectorResult(2)

    monkeypatch.setattr(cli, "SnmpCollector", lambda **_kwargs: FakeCollector())
    code = cli.run(
        [
            "--json",
            "--config",
            str(config_path),
            "collect",
            "snmp",
            "--target",
            "192.168.50.10",
        ],
        run_id="snmp-run",
    )
    assert code == cli.ExitCode.SUCCESS
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert (payload["facts"], payload["failures"], payload["protocol"]) == (2, 0, "v3")
    assert payload["security_notice"] is None
    assert len(calls) == 1
    connection = sqlite3.connect(root / "discovery.db")
    assert connection.execute("SELECT status FROM collector_runs").fetchone()[0] == "succeeded"
    connection.close()


def test_collect_snmp_cli_refuses_unapproved_target_and_missing_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, _root = database_config(tmp_path)
    monkeypatch.setattr(
        cli, "SnmpCollector", lambda **_kwargs: (_ for _ in ()).throw(AssertionError("called"))
    )
    document = yaml.safe_load(config_path.read_text())
    document["collectors"]["snmp"]["credential_ref"] = None
    config_path.write_text(yaml.safe_dump(document))
    code = cli.run(
        ["--config", str(config_path), "collect", "snmp", "--target", "192.168.50.10"],
        run_id="snmp-no-ref",
    )
    assert code == cli.ExitCode.CONFIGURATION
    assert "credential reference" in capsys.readouterr().out

    document["collectors"]["snmp"]["credential_ref"] = {
        "provider": "appliance_env",
        "key": "SNMP_SITE_PROFILE",
    }
    config_path.write_text(yaml.safe_dump(document))
    monkeypatch.setattr(cli, "SnmpCollector", lambda **_kwargs: object())
    code = cli.run(
        ["--config", str(config_path), "collect", "snmp", "--target", "10.0.0.1"],
        run_id="snmp-outside",
    )
    assert code == cli.ExitCode.COLLECTOR
    assert "outside approved" in capsys.readouterr().out


def test_collect_snmp_v2c_notice_and_failure_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, _root = database_config(tmp_path)
    document = yaml.safe_load(config_path.read_text())
    document["collectors"]["snmp"].update({"protocol": "v2c", "allow_insecure_v2c": True})
    config_path.write_text(yaml.safe_dump(document))

    class FailingCollector:
        async def collect(self, _context: object) -> CollectorResult:
            raise cli.CollectorError("synthetic refusal")

    monkeypatch.setattr(cli, "SnmpCollector", lambda **_kwargs: FailingCollector())
    code = cli.run(
        [
            "--json",
            "--config",
            str(config_path),
            "collect",
            "snmp",
            "--target",
            "192.168.50.10",
        ],
        run_id="snmp-v2c",
    )
    assert code == cli.ExitCode.COLLECTOR
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "unencrypted" in payload["security_notice"]
    assert payload["failures"] == 1
    assert "snmp_v2c_explicitly_enabled" in captured.err


def test_collect_snmp_repository_failure_is_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, _root = database_config(tmp_path)
    monkeypatch.setattr(
        cli.Repository, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline"))
    )
    code = cli.run(
        ["--config", str(config_path), "collect", "snmp", "--target", "192.168.50.10"],
        run_id="snmp-db-fail",
    )
    assert code == cli.ExitCode.COLLECTOR
    captured = capsys.readouterr()
    assert "SNMP collection failed" in captured.out
    assert "snmp_collection_failed" in captured.err


def test_collect_unifi_cli_runs_only_configured_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, root = database_config(tmp_path)

    class FakeCollector:
        async def collect(self, _context: object) -> object:
            issue = type(
                "Issue",
                (),
                {"category": "permission_denied", "detail": "synthetic", "retryable": False},
            )()
            return type("Result", (), {"item_count": 2, "issues": (issue,)})()

    monkeypatch.setattr(cli, "UniFiInventoryCollector", lambda *_args, **_kwargs: FakeCollector())
    monkeypatch.setattr(cli, "resolve_credentials", lambda *_args, **_kwargs: object())
    code = cli.run(["--json", "--config", str(config_path), "collect", "unifi"], run_id="unifi-run")
    assert code == cli.ExitCode.SUCCESS
    payload = json.loads(capsys.readouterr().out)
    assert (payload["entities"], payload["failures"]) == (2, 0)
    connection = sqlite3.connect(root / "discovery.db")
    assert connection.execute("SELECT status FROM collector_runs").fetchone()[0] == "partial"
    connection.close()

    code = cli.run(
        [
            "--config",
            str(config_path),
            "collect",
            "unifi",
            "--controller",
            "https://not-configured.invalid",
        ],
        run_id="unifi-none",
    )
    assert code == cli.ExitCode.CONFIGURATION
    assert "No matching" in capsys.readouterr().out


def test_collect_unifi_cli_records_safe_controller_and_repository_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, root = database_config(tmp_path)

    class FailingCollector:
        async def collect(self, _context: object) -> object:
            raise cli.UniFiError("synthetic controller refusal")

    monkeypatch.setattr(
        cli, "UniFiInventoryCollector", lambda *_args, **_kwargs: FailingCollector()
    )
    code = cli.run(["--config", str(config_path), "collect", "unifi"], run_id="unifi-fail")
    assert code == cli.ExitCode.COLLECTOR
    assert "1 failed" in capsys.readouterr().out
    connection = sqlite3.connect(root / "discovery.db")
    assert connection.execute("SELECT status FROM collector_runs").fetchone()[0] == "failed"
    connection.close()

    document = yaml.safe_load(config_path.read_text())
    document["collectors"]["unifi"]["endpoints"][0]["credential_ref"] = None
    config_path.write_text(yaml.safe_dump(document))
    assert (
        cli.run(["--config", str(config_path), "collect", "unifi"], run_id="unifi-no-ref")
        == cli.ExitCode.COLLECTOR
    )
    capsys.readouterr()

    monkeypatch.setattr(
        cli.Repository, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline"))
    )
    assert (
        cli.run(["--config", str(config_path), "collect", "unifi"], run_id="unifi-db-fail")
        == cli.ExitCode.COLLECTOR
    )
    assert "offline" in capsys.readouterr().out


def test_collect_ssh_cli_uses_explicit_platform_and_opaque_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, root = database_config(tmp_path)
    connections: list[tuple[str, str, object, str]] = []

    class FakeSession:
        async def run(self, command: str, *, structured: bool) -> object:
            return [{"command": command}] if structured else "paging disabled"

        async def close(self) -> None:
            return None

    class FakeFactory:
        async def connect(
            self,
            target: str,
            platform: str,
            credential: object,
            *,
            host_key_policy: str,
        ) -> FakeSession:
            connections.append((target, platform, credential, host_key_policy))
            return FakeSession()

    class FakeResolver:
        def __init__(self, _providers: object) -> None:
            pass

        def resolve(self, reference: object) -> dict[str, str]:
            assert reference is not None
            return {"username": "operator", "password": "synthetic-secret"}

    monkeypatch.setattr(cli, "NetmikoSessionFactory", FakeFactory)
    monkeypatch.setattr(cli, "ConfigSecretResolver", FakeResolver)
    code = cli.run(
        [
            "--json",
            "--config",
            str(config_path),
            "collect",
            "ssh",
            "--target",
            "192.168.50.20",
            "--platform",
            "aruba_aos",
        ],
        run_id="ssh-run",
    )
    assert code == cli.ExitCode.SUCCESS
    payload = json.loads(capsys.readouterr().out)
    assert payload["facts"] > 0
    assert (payload["partial"], payload["failures"]) == (0, 0)
    assert connections[0][0:2] == ("192.168.50.20", "aruba_aos")
    assert connections[0][3] == "strict"
    assert list((root / "artifacts" / "ssh").glob("*.txt"))


def test_collect_ssh_cli_reports_partial_and_failed_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, _root = database_config(tmp_path)

    class FakeResolver:
        def __init__(self, _providers: object) -> None:
            pass

        def resolve(self, _reference: object) -> dict[str, str]:
            return {"username": "operator", "password": "synthetic-secret"}

    class RawSession:
        async def run(self, _command: str, *, structured: bool) -> object:
            return "raw fallback"

        async def close(self) -> None:
            return None

    class RawFactory:
        async def connect(self, *_args: object, **_kwargs: object) -> RawSession:
            return RawSession()

    monkeypatch.setattr(cli, "ConfigSecretResolver", FakeResolver)
    monkeypatch.setattr(cli, "NetmikoSessionFactory", RawFactory)
    arguments = [
        "--config",
        str(config_path),
        "collect",
        "ssh",
        "--target",
        "192.168.50.20",
        "--platform",
        "cisco_ios",
    ]
    assert cli.run(arguments, run_id="ssh-partial") == cli.ExitCode.SUCCESS
    assert "1 partial" in capsys.readouterr().out

    class FailingFactory:
        async def connect(self, *_args: object, **_kwargs: object) -> object:
            raise cli.CollectorError("synthetic SSH refusal")

    monkeypatch.setattr(cli, "NetmikoSessionFactory", FailingFactory)
    assert cli.run(arguments, run_id="ssh-failed") == cli.ExitCode.COLLECTOR
    assert "1 failed" in capsys.readouterr().out


def test_collect_ssh_cli_rejects_missing_reference_target_and_repository_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, _root = database_config(tmp_path)
    arguments = [
        "--config",
        str(config_path),
        "collect",
        "ssh",
        "--target",
        "192.168.51.20",
        "--platform",
        "hp_comware",
    ]
    assert cli.run(arguments, run_id="ssh-target") == cli.ExitCode.COLLECTOR
    assert "outside approved" in capsys.readouterr().out

    document = yaml.safe_load(config_path.read_text())
    document["collectors"]["ssh"]["credential_ref"] = None
    config_path.write_text(yaml.safe_dump(document))
    assert cli.run(arguments, run_id="ssh-reference") == cli.ExitCode.CONFIGURATION
    assert "credential reference" in capsys.readouterr().out

    document["collectors"]["ssh"]["credential_ref"] = {
        "provider": "secret_helper",
        "key": "SSH_SITE_PROFILE",
    }
    config_path.write_text(yaml.safe_dump(document))
    monkeypatch.setattr(
        cli.Repository, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline"))
    )
    assert cli.run(arguments, run_id="ssh-offline") == cli.ExitCode.COLLECTOR
    assert "offline" in capsys.readouterr().out


def test_status_emits_stable_schema_and_collector_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, _root = database_config(tmp_path)
    report: dict[str, object] = {
        "schema_version": 1,
        "generated_at": "2026-07-15T00:00:00+00:00",
        "ok": True,
        "summary": {"checks": 1, "errors": 0, "warnings": 0},
        "network": {"interface": "eth0", "cidr": "192.0.2.0/24"},
        "paths": [],
        "database": {"integrity": ["ok"]},
        "disk": {"free_percent": 75.0},
        "collectors": [{"collector": "fixture", "item_count": 3, "age_seconds": 5}],
        "checks": [
            {
                "name": "database",
                "category": "database",
                "status": "ok",
                "message": "Database integrity is healthy",
                "details": {},
            }
        ],
    }
    monkeypatch.setattr(cli, "collect_status", lambda _configuration: report)
    assert (
        cli.run(["--json", "--config", str(config_path), "status"], run_id="status-run")
        == cli.ExitCode.SUCCESS
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 1
    assert payload["command"] == "status"
    assert payload["collectors"][0]["collector"] == "fixture"
    assert payload["message"] == "Appliance healthy: 0 errors, 0 warnings, 1 checks."
    monkeypatch.setattr(cli, "collect_doctor", lambda _configuration: report)
    assert (
        cli.run(["--json", "--config", str(config_path), "doctor"], run_id="doctor-run")
        == cli.ExitCode.SUCCESS
    )
    assert json.loads(capsys.readouterr().out)["command"] == "doctor"


def test_status_and_doctor_degraded_human_output_have_stable_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, _root = database_config(tmp_path)
    report: dict[str, object] = {
        "schema_version": 1,
        "generated_at": "2026-07-15T00:00:00+00:00",
        "ok": False,
        "summary": {"checks": 2, "errors": 1, "warnings": 1},
        "checks": [
            {
                "name": "database",
                "category": "database",
                "status": "error",
                "message": "Database is unavailable",
                "details": {},
            },
            {
                "name": "service",
                "category": "services",
                "status": "warning",
                "message": "Service is not installed",
                "details": {},
            },
        ],
    }
    monkeypatch.setattr(cli, "collect_status", lambda _configuration: report)
    assert cli.run(["--config", str(config_path), "status"]) == cli.ExitCode.DIAGNOSTIC
    output = capsys.readouterr().out
    assert "Appliance degraded: 1 errors, 1 warnings, 2 checks." in output
    assert "[ERROR] database: Database is unavailable" in output
    assert "[WARNING] service: Service is not installed" in output

    monkeypatch.setattr(cli, "collect_doctor", lambda _configuration: report)
    assert cli.run(["--config", str(config_path), "doctor"]) == cli.ExitCode.DIAGNOSTIC
    assert "Appliance degraded" in capsys.readouterr().out


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


def test_discover_ad_cli_uses_no_credentials_and_persists_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, root = database_config(tmp_path)
    candidate = DomainControllerCandidate(
        "alpha.example.invalid",
        "dc1.alpha.example.invalid",
        ("192.168.50.10",),
        (389,),
        ("Site-A",),
        ("dns_ldap_srv",),
        {},
        0.8,
    )
    calls: list[tuple[object, object, object]] = []

    class FakeDetector:
        async def detect(
            self, domains: object, *, sites: object, service_evidence: object
        ) -> ADDetectionResult:
            calls.append((domains, sites, service_evidence))
            return ADDetectionResult(("alpha.example.invalid",), (candidate,), ())

    monkeypatch.setattr(cli, "ADDetector", lambda *_args, **_kwargs: FakeDetector())
    monkeypatch.setattr(cli, "DnspythonResolver", lambda *_args: object())
    monkeypatch.setattr(cli, "Ldap3RootDSEProbe", lambda *_args: object())
    monkeypatch.setattr(cli, "repository_service_evidence", lambda *_args: ("stored",))
    code = cli.run(
        [
            "--json",
            "--config",
            str(config_path),
            "discover",
            "ad",
            "--domain",
            "alpha.example.invalid",
            "--site",
            "Site-A",
        ],
        run_id="ad-detect",
    )
    assert code == cli.ExitCode.SUCCESS
    payload = json.loads(capsys.readouterr().out)
    assert payload["candidates"][0]["hostname"] == "dc1.alpha.example.invalid"
    assert payload["limitations"] == 0
    assert calls == [(["alpha.example.invalid"], ["Site-A"], ("stored",))]
    connection = sqlite3.connect(root / "discovery.db")
    assert connection.execute("SELECT status FROM collector_runs").fetchone()[0] == "succeeded"
    assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1
    connection.close()


def test_discover_ad_cli_records_partial_limitations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, root = database_config(tmp_path)

    class FakeDetector:
        async def detect(self, *_args: object, **_kwargs: object) -> ADDetectionResult:
            return ADDetectionResult(
                ("example.invalid",),
                (),
                (DetectionIssue("dns_unreachable", "owner", "DNS query was unreachable"),),
            )

    monkeypatch.setattr(cli, "ADDetector", lambda *_args, **_kwargs: FakeDetector())
    monkeypatch.setattr(cli, "repository_service_evidence", lambda *_args: ())
    assert (
        cli.run(["--config", str(config_path), "discover", "ad"], run_id="ad-partial")
        == cli.ExitCode.SUCCESS
    )
    assert "1 limitations" in capsys.readouterr().out
    connection = sqlite3.connect(root / "discovery.db")
    assert connection.execute("SELECT status FROM collector_runs").fetchone()[0] == "partial"
    assert connection.execute("SELECT retryable FROM collector_errors").fetchone()[0] == 1
    connection.close()


def test_discover_ad_cli_missing_domain_and_safe_failure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config_path, root = database_config(tmp_path)
    document = yaml.safe_load(config_path.read_text())
    document["collectors"]["ad"]["domain"] = None
    config_path.write_text(yaml.safe_dump(document))
    arguments = ["--config", str(config_path), "discover", "ad"]
    assert cli.run(arguments, run_id="ad-no-domain") == cli.ExitCode.CONFIGURATION
    assert "requires" in capsys.readouterr().out

    document["collectors"]["ad"]["domain"] = "example.invalid"
    config_path.write_text(yaml.safe_dump(document))

    class FailingDetector:
        async def detect(self, *_args: object, **_kwargs: object) -> object:
            raise ADDetectionError("synthetic safe refusal")

    monkeypatch.setattr(cli, "ADDetector", lambda *_args, **_kwargs: FailingDetector())
    monkeypatch.setattr(cli, "repository_service_evidence", lambda *_args: ())
    assert cli.run(arguments, run_id="ad-fail") == cli.ExitCode.COLLECTOR
    captured = capsys.readouterr()
    assert "synthetic safe refusal" in captured.out
    assert "ad_detection_failed" in captured.err
    connection = sqlite3.connect(root / "discovery.db")
    assert connection.execute("SELECT status FROM collector_runs").fetchone()[0] == "failed"
    connection.close()

    monkeypatch.setattr(
        cli.Repository, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline"))
    )
    assert cli.run(arguments, run_id="ad-offline") == cli.ExitCode.COLLECTOR
    assert "offline" in capsys.readouterr().out


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


def test_report_cli_generates_validates_and_reports_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config, root = database_config(tmp_path)
    repository = Repository.open(root / "discovery.db", data_root=root)
    repository.upsert_deployment("fixture", "Fixture Site", "2026-07-01T00:00:00+00:00")
    repository.close()
    output = root / "reports"
    generate = [
        "--json",
        "--config",
        str(config),
        "report",
        "generate",
        "--output-dir",
        str(output),
    ]
    assert cli.run(generate, run_id="report-generate") == cli.ExitCode.SUCCESS
    generated = json.loads(capsys.readouterr().out)
    assert generated["upload_ready"] is True
    report = Path(generated["docx"])
    assert report.is_file()
    assert Path(generated["json"]).is_file()
    missing_document = yaml.safe_load(config.read_text())
    missing_document["report"]["author"] = None
    missing_config = tmp_path / "missing-report-metadata.yaml"
    missing_config.write_text(yaml.safe_dump(missing_document))
    assert (
        cli.run(
            ["--config", str(missing_config), "report", "generate"],
            run_id="report-metadata-missing",
        )
        == cli.ExitCode.REPORT
    )
    assert "explicit metadata" in capsys.readouterr().out
    assert (
        cli.run(
            ["--json", "--config", str(config), "report", "validate", str(report)],
            run_id="report-validate",
        )
        == cli.ExitCode.SUCCESS
    )
    validated = json.loads(capsys.readouterr().out)
    assert validated["paragraphs"] > 0
    assert validated["validated_parts"] > 0
    assert validated["external_relationships"] == []
    assert validated["upload_ready"] is True

    bad = tmp_path / "bad.docx"
    bad.write_text("not a package")
    assert (
        cli.run(
            ["--config", str(config), "report", "validate", str(bad)],
            run_id="report-invalid",
        )
        == cli.ExitCode.REPORT
    )
    assert "validation failed" in capsys.readouterr().out.lower()

    empty_parent = tmp_path / "empty"
    empty_parent.mkdir()
    empty_config, _empty_root = database_config(empty_parent)
    assert (
        cli.run(["--config", str(empty_config), "report", "generate"], run_id="report-empty")
        == cli.ExitCode.REPORT
    )
    assert "no deployment" in capsys.readouterr().out


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


def test_database_cli_restore_recover_and_low_disk_pause(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, root = database_config(tmp_path)
    repository = Repository.open(root / "discovery.db", data_root=root)
    run_id = repository.start_run(None, "fixture", "2026-01-01T00:00:00+00:00")
    backup = repository.backup(root / "source.db")
    repository.close()
    prefix = ["--json", "--config", str(config), "db"]
    restored = root / "restored.db"
    assert (
        cli.run(
            [*prefix, "restore", str(backup), "--output", str(restored)],
            run_id="db-restore",
        )
        == cli.ExitCode.SUCCESS
    )
    assert json.loads(capsys.readouterr().out)["path"] == str(restored)
    assert (
        cli.run([*prefix, "recover", "--confirm-stopped"], run_id="db-recover")
        == cli.ExitCode.SUCCESS
    )
    assert json.loads(capsys.readouterr().out)["recovered_runs"] == 1
    repository = Repository.open(root / "discovery.db", data_root=root)
    assert repository.recent_collector_runs()[0]["id"] == run_id
    assert repository.recent_collector_runs()[0]["status"] == "failed"
    repository.close()

    class PausedGuard:
        def check(self, _path: Path, _required: int = 0) -> None:
            raise cli.LowDiskSpace("artifact-heavy work paused")

    monkeypatch.setattr(cli.DiskGuard, "from_config", lambda _configuration: PausedGuard())
    assert cli.run([*prefix, "backup"], run_id="db-low-disk") == cli.ExitCode.STORAGE
    assert "paused" in json.loads(capsys.readouterr().out)["message"]
    assert (
        cli.run(
            ["--json", "--config", str(config), "report", "generate"],
            run_id="report-low-disk",
        )
        == cli.ExitCode.STORAGE
    )
    assert "paused" in json.loads(capsys.readouterr().out)["message"]


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
