"""Offline-safe command-line application shell."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sqlite3
import sys
import uuid
from collections.abc import Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from pathlib import Path
from typing import Any, NoReturn, cast
from urllib.parse import urlsplit

from field_discovery import __version__
from field_discovery.collectors import CollectorContext, CollectorError, CredentialReference
from field_discovery.config import ConfigurationError, load_config
from field_discovery.logging import configure_logging
from field_discovery.nmap_import import NmapImportError, import_nmap_artifacts
from field_discovery.nmap_scan import ScanLaunchError, run_nmap_scan
from field_discovery.reporting import ReportError, generate_reports, validate_docx
from field_discovery.repository import Repository, RepositoryError, RetentionCutoffs
from field_discovery.subnet import SubnetResolutionError, resolve_subnet
from field_discovery.unifi import (
    UniFiCollector,
    UniFiError,
    endpoint_from_config,
    resolve_credentials,
)

DEFAULT_CONFIG = Path("/etc/field-discovery/config.yaml")


class ExitCode(IntEnum):
    """Stable process exit codes forming part of the operator contract."""

    SUCCESS = 0
    USAGE = 2
    CONFIGURATION = 3
    NOT_IMPLEMENTED = 4
    INTERNAL = 70
    RESOLUTION = 5
    DATABASE = 6
    SCAN_REFUSED = 7
    IMPORT = 8
    REPORT = 9
    COLLECTOR = 10


class CliParser(argparse.ArgumentParser):
    """Argument parser whose usage failures use the stable usage code."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(int(ExitCode.USAGE), f"{self.prog}: error: {message}\n")


def _command_parser(subparsers: Any, name: str, help_text: str) -> argparse.ArgumentParser:
    return cast(argparse.ArgumentParser, subparsers.add_parser(name, help=help_text))


def build_parser() -> argparse.ArgumentParser:
    """Build the complete SPEC command tree without performing I/O."""
    parser = CliParser(prog="field-discovery", description="CodexNet field discovery appliance")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="non-secret YAML path")
    parser.add_argument("--json", action="store_true", dest="json_mode", help="emit JSON output")
    commands = parser.add_subparsers(dest="group", required=True)

    config = _command_parser(commands, "config", "configuration operations")
    config_sub = config.add_subparsers(dest="action", required=True)
    _command_parser(config_sub, "validate", "validate non-secret configuration")

    _command_parser(commands, "status", "show appliance status")
    discover = _command_parser(commands, "discover", "safe discovery operations")
    discover_sub = discover.add_subparsers(dest="action", required=True)
    _command_parser(discover_sub, "subnet", "resolve the selected interface and subnet")

    collect = _command_parser(commands, "collect", "collector operations")
    collect_sub = collect.add_subparsers(dest="action", required=True)
    passive = _command_parser(collect_sub, "passive", "passive observer operations")
    passive_sub = passive.add_subparsers(dest="detail", required=True)
    _command_parser(passive_sub, "status", "show passive observer status")
    snmp = _command_parser(collect_sub, "snmp", "run SNMP collection")
    snmp.add_argument("--target", action="append")
    unifi = _command_parser(collect_sub, "unifi", "run UniFi collection")
    unifi.add_argument("--controller", action="append")
    ad = _command_parser(collect_sub, "ad", "run Active Directory collection")
    ad.add_argument("--domain")
    ssh = _command_parser(collect_sub, "ssh", "run network-device SSH collection")
    ssh.add_argument("--target", action="append")

    import_group = _command_parser(commands, "import", "artifact import operations")
    import_sub = import_group.add_subparsers(dest="action", required=True)
    nmap_import = _command_parser(import_sub, "nmap", "import nmap XML")
    nmap_import.add_argument("--path", type=Path)
    nmap_import.add_argument(
        "--stability-seconds",
        type=float,
        default=5.0,
        help="minimum unchanged artifact age before import",
    )

    scan = _command_parser(commands, "scan", "explicit active scan operations")
    scan_sub = scan.add_subparsers(dest="action", required=True)
    nmap_scan = _command_parser(scan_sub, "nmap", "explicitly invoke the protected nmap script")
    nmap_scan.add_argument(
        "--yes", action="store_true", help="confirm the authorised active scan non-interactively"
    )
    nmap_scan.add_argument(
        "--timeout", type=int, help="outer timeout in seconds (default: configured value)"
    )

    report = _command_parser(commands, "report", "report operations")
    report_sub = report.add_subparsers(dest="action", required=True)
    generate = _command_parser(report_sub, "generate", "generate a report")
    generate.add_argument("--format", choices=("docx",), default="docx")
    generate.add_argument("--output-dir", type=Path)
    validate = _command_parser(report_sub, "validate", "validate a DOCX report")
    validate.add_argument("report", type=Path)

    database = _command_parser(commands, "db", "database operations")
    database_sub = database.add_subparsers(dest="action", required=True)
    _command_parser(database_sub, "check", "check database integrity")
    backup = _command_parser(database_sub, "backup", "back up the database")
    backup.add_argument("--output", type=Path, help="new path inside configured data root")
    prune = _command_parser(database_sub, "prune", "prune data according to retention policy")
    prune.add_argument("--apply", action="store_true", help="apply the default dry-run plan")
    _command_parser(commands, "doctor", "run appliance diagnostics")
    return parser


def _command_name(arguments: argparse.Namespace) -> str:
    parts = [arguments.group]
    for name in ("action", "detail"):
        value = getattr(arguments, name, None)
        if value:
            parts.append(value)
    return " ".join(parts)


def _emit(payload: dict[str, Any], *, json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return
    print(str(payload["message"]))


def run(argv: Sequence[str] | None = None, *, run_id: str | None = None) -> int:
    """Run the CLI and return a stable exit status."""
    arguments = build_parser().parse_args(argv)
    actual_run_id = run_id or str(uuid.uuid4())
    logger = configure_logging(json_mode=arguments.json_mode, run_id=actual_run_id)
    command = _command_name(arguments)
    try:
        configuration = load_config(arguments.config)
    except ConfigurationError as exc:
        logger.error("configuration_invalid", extra={"command": command, "reason": str(exc)})
        _emit(
            {"ok": False, "command": command, "message": f"Configuration invalid: {exc}"},
            json_mode=arguments.json_mode,
        )
        return int(ExitCode.CONFIGURATION)
    if command == "config validate":
        logger.info("configuration_valid", extra={"command": command})
        _emit(
            {"ok": True, "command": command, "message": "Configuration is valid."},
            json_mode=arguments.json_mode,
        )
        return int(ExitCode.SUCCESS)
    if command == "status":
        paths = configuration.data["paths"]
        status_repository: Repository | None = None
        try:
            status_repository = Repository.open(
                Path(paths["database"]), data_root=Path(paths["data_root"])
            )
            runs = status_repository.recent_collector_runs()
            message = (
                "No collector runs recorded."
                if not runs
                else f"Collector runs: {len(runs)} shown; latest {runs[0]['collector']} "
                f"{runs[0]['status']}."
            )
            _emit(
                {
                    "ok": True,
                    "command": command,
                    "message": message,
                    "collector_runs": list(runs),
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.SUCCESS)
        except (RepositoryError, sqlite3.Error, OSError) as exc:
            logger.error("status_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"Status failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.DATABASE)
        finally:
            if status_repository is not None:
                status_repository.close()
    if command == "discover subnet":
        try:
            description = resolve_subnet(configuration.data)
        except SubnetResolutionError as exc:
            logger.error("subnet_resolution_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"Subnet resolution failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.RESOLUTION)
        details = description.as_dict()
        message = (
            f"Interface {description.interface}: {description.address} on {description.cidr}; "
            f"gateway {description.gateway or 'none'}; DNS "
            f"{', '.join(description.dns_servers) or 'none'}; active target "
            f"{'permitted' if description.active_target_permitted else 'refused'}"
        )
        logger.info(
            "subnet_resolved",
            extra={
                "command": command,
                "interface": description.interface,
                "cidr": description.cidr,
                "active_target_permitted": description.active_target_permitted,
            },
        )
        _emit(
            {"ok": True, "command": command, "message": message, "subnet": details},
            json_mode=arguments.json_mode,
        )
        return int(ExitCode.SUCCESS)
    if command == "collect unifi":
        endpoints = configuration.data["collectors"]["unifi"]["endpoints"]
        selected = set(arguments.controller or ())
        if selected:
            endpoints = [endpoint for endpoint in endpoints if endpoint["url"] in selected]
        if not endpoints:
            _emit(
                {
                    "ok": False,
                    "command": command,
                    "message": "No matching configured UniFi controller endpoint.",
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.CONFIGURATION)
        paths = configuration.data["paths"]
        unifi_repository: Repository | None = None
        try:
            unifi_repository = Repository.open(
                Path(paths["database"]), data_root=Path(paths["data_root"])
            )
            timestamp = datetime.now(UTC)
            deployment_id = unifi_repository.upsert_deployment(
                "default", "Default deployment", timestamp.isoformat()
            )
            total = 0
            failures = 0
            for value in endpoints:
                endpoint = endpoint_from_config(value)
                reference = CredentialReference.from_mapping(value.get("credential_ref"))
                unifi_run = unifi_repository.start_run(
                    deployment_id,
                    "unifi",
                    timestamp.isoformat(),
                    target_cidr=urlsplit(endpoint.url).hostname,
                )
                try:
                    if reference is None:
                        raise UniFiError("UniFi collection requires a credential reference")
                    collector = UniFiCollector(
                        endpoint,
                        lambda requested: resolve_credentials(
                            requested, configuration.data["secret_providers"]
                        ),
                    )
                    unifi_result = asyncio.run(
                        collector.collect(
                            CollectorContext(
                                urlsplit(endpoint.url).hostname or "controller",
                                reference,
                                asyncio.Event(),
                            )
                        )
                    )
                    total += unifi_result.item_count
                    unifi_repository.finish_run(
                        unifi_run,
                        "succeeded",
                        datetime.now(UTC).isoformat(),
                        unifi_result.item_count,
                    )
                except CollectorError as exc:
                    failures += 1
                    unifi_repository.record_collector_error(
                        unifi_run,
                        category="unifi",
                        detail=unifi_repository.redactor.text(exc),
                        retryable=False,
                        source="unifi",
                        observed_at=datetime.now(UTC).isoformat(),
                    )
                    unifi_repository.finish_run(
                        unifi_run, "failed", datetime.now(UTC).isoformat(), 0
                    )
            ok = failures == 0
            _emit(
                {
                    "ok": ok,
                    "command": command,
                    "message": f"UniFi collection: {total} sites, {failures} failed controllers.",
                    "sites": total,
                    "failures": failures,
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.SUCCESS if ok else ExitCode.COLLECTOR)
        except (RepositoryError, sqlite3.Error, OSError, CollectorError) as exc:
            logger.error("unifi_collection_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"UniFi collection failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.COLLECTOR)
        finally:
            if unifi_repository is not None:
                unifi_repository.close()
    if command == "import nmap":
        paths = configuration.data["paths"]
        repository: Repository | None = None
        run_record: int | None = None
        timestamp = datetime.now(UTC)
        try:
            repository = Repository.open(
                Path(paths["database"]), data_root=Path(paths["data_root"])
            )
            deployment_id = repository.upsert_deployment(
                "default", "Default deployment", timestamp.isoformat()
            )
            run_record = repository.start_run(deployment_id, "nmap_import", timestamp.isoformat())
            summary = import_nmap_artifacts(
                repository,
                arguments.path or Path(paths["nmap_results"]),
                deployment_id=deployment_id,
                collector_run_id=run_record,
                stability_seconds=arguments.stability_seconds,
                now=timestamp,
            )
            for issue in summary.issues:
                repository.connection.execute(
                    "INSERT INTO collector_errors"
                    "(collector_run_id, category, detail, retryable, source, observed_at) "
                    "VALUES (?, ?, ?, ?, 'nmap_import', ?)",
                    (
                        run_record,
                        issue.category,
                        repository.redactor.text(issue.detail),
                        int(issue.retryable),
                        timestamp.isoformat(),
                    ),
                )
            status = "partial" if summary.issues else "succeeded"
            repository.finish_run(run_record, status, datetime.now(UTC).isoformat(), summary.hosts)
            payload = {
                "ok": True,
                "command": command,
                "message": (
                    f"Nmap import: {summary.imported} imported, {summary.skipped} skipped, "
                    f"{summary.deferred} deferred, {len(summary.issues)} errors."
                ),
                "discovered": summary.discovered,
                "imported": summary.imported,
                "skipped": summary.skipped,
                "deferred": summary.deferred,
                "hosts": summary.hosts,
                "errors": len(summary.issues),
            }
            logger.info(
                "nmap_import_completed",
                extra={
                    "command": command,
                    "imported": summary.imported,
                    "skipped": summary.skipped,
                    "deferred": summary.deferred,
                    "errors": len(summary.issues),
                },
            )
            _emit(payload, json_mode=arguments.json_mode)
            return int(ExitCode.SUCCESS)
        except (NmapImportError, RepositoryError, sqlite3.Error, OSError) as exc:
            if repository is not None and run_record is not None:
                with suppress(RepositoryError, sqlite3.Error):
                    repository.finish_run(run_record, "failed", datetime.now(UTC).isoformat(), 0)
            logger.error("nmap_import_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"Nmap import failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.IMPORT)
        finally:
            if repository is not None:
                repository.close()
    if command == "scan nmap":
        if not arguments.yes:
            if arguments.json_mode or not sys.stdin.isatty():
                _emit(
                    {
                        "ok": False,
                        "command": command,
                        "message": "Active scan not confirmed; rerun with --yes.",
                    },
                    json_mode=arguments.json_mode,
                )
                return int(ExitCode.SCAN_REFUSED)
            answer = input("Type SCAN to confirm this authorised active network scan: ")
            if answer != "SCAN":
                _emit(
                    {"ok": False, "command": command, "message": "Active scan cancelled."},
                    json_mode=False,
                )
                return int(ExitCode.SCAN_REFUSED)
        timeout = arguments.timeout or configuration.data["active"]["scan_timeout_seconds"]
        try:
            result = run_nmap_scan(configuration.data, timeout_seconds=timeout)
        except (ScanLaunchError, SubnetResolutionError, RepositoryError, OSError) as exc:
            logger.error("nmap_scan_refused", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"Active scan refused: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.SCAN_REFUSED)
        payload = {
            "ok": result.exit_code == 0,
            "command": command,
            "message": (
                f"Active scan {result.status} for {result.interface} ({result.cidr}); "
                f"exit code {result.exit_code}."
            ),
            "scan": {
                "status": result.status,
                "exit_code": result.exit_code,
                "interface": result.interface,
                "cidr": result.cidr,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "duration_seconds": result.duration_seconds,
                "script_sha256": result.script_sha256,
            },
        }
        logger.info(
            "nmap_scan_finished",
            extra={
                "command": command,
                "status": result.status,
                "exit_code": result.exit_code,
                "interface": result.interface,
                "cidr": result.cidr,
            },
        )
        _emit(payload, json_mode=arguments.json_mode)
        return result.exit_code
    if command == "report validate":
        try:
            validation = validate_docx(arguments.report)
        except ReportError as exc:
            logger.error("report_validation_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"Report validation failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.REPORT)
        _emit(
            {
                "ok": True,
                "command": command,
                "message": "DOCX report validation passed.",
                "paragraphs": validation.paragraph_count,
                "tables": validation.table_count,
                "external_relationships": list(validation.external_relationships),
            },
            json_mode=arguments.json_mode,
        )
        return int(ExitCode.SUCCESS)
    if command == "report generate":
        paths = configuration.data["paths"]
        repository = None
        try:
            repository = Repository.open(
                Path(paths["database"]), data_root=Path(paths["data_root"])
            )
            deployment = repository.connection.execute(
                "SELECT id FROM deployments ORDER BY id LIMIT 1"
            ).fetchone()
            if deployment is None:
                raise ReportError("no deployment is available to report")
            outputs = generate_reports(
                repository,
                int(deployment["id"]),
                arguments.output_dir or Path(paths["data_root"]) / "reports",
                generated_at=datetime.now(UTC),
                confidentiality=str(configuration.data["report"]["confidentiality"]),
            )
            payload = {
                "ok": True,
                "command": command,
                "message": f"DOCX report generated: {outputs.docx_path}",
                "docx": str(outputs.docx_path),
                "json": str(outputs.json_path),
                "docx_sha256": outputs.docx_sha256,
                "json_sha256": outputs.json_sha256,
            }
            logger.info("report_generated", extra={"command": command})
            _emit(payload, json_mode=arguments.json_mode)
            return int(ExitCode.SUCCESS)
        except (ReportError, RepositoryError, sqlite3.Error, OSError) as exc:
            logger.error("report_generation_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"Report generation failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.REPORT)
        finally:
            if repository is not None:
                repository.close()
    if arguments.group == "db":
        paths = configuration.data["paths"]
        try:
            repository = Repository.open(
                Path(paths["database"]), data_root=Path(paths["data_root"])
            )
            try:
                if arguments.action == "check":
                    integrity_result = repository.integrity_check()
                    payload = {
                        "ok": integrity_result.ok,
                        "command": command,
                        "message": (
                            "Database integrity checks passed."
                            if integrity_result.ok
                            else "Database integrity checks failed."
                        ),
                        "integrity": list(integrity_result.integrity),
                        "foreign_key_violations": list(integrity_result.foreign_key_violations),
                    }
                    logger.info(
                        "database_checked",
                        extra={"command": command, "ok": integrity_result.ok},
                    )
                    _emit(payload, json_mode=arguments.json_mode)
                    return int(ExitCode.SUCCESS if integrity_result.ok else ExitCode.DATABASE)
                if arguments.action == "backup":
                    destination = arguments.output or Path(paths["data_root"]) / (
                        f"discovery-backup-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.db"
                    )
                    backup_path = repository.backup(destination)
                    logger.info("database_backed_up", extra={"command": command})
                    _emit(
                        {
                            "ok": True,
                            "command": command,
                            "message": f"Database backup created: {backup_path}",
                            "path": str(backup_path),
                        },
                        json_mode=arguments.json_mode,
                    )
                    return int(ExitCode.SUCCESS)
                retention_days = configuration.data["retention"]["detailed_days"]
                cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
                prune_result = repository.prune(
                    RetentionCutoffs(cutoff, cutoff, cutoff), dry_run=not arguments.apply
                )
                mode = "preview" if prune_result.dry_run else "applied"
                logger.info("database_prune_completed", extra={"command": command, "mode": mode})
                _emit(
                    {
                        "ok": True,
                        "command": command,
                        "message": (
                            f"Database prune {mode}: {sum(prune_result.counts.values())} rows."
                        ),
                        "dry_run": prune_result.dry_run,
                        "counts": prune_result.counts,
                    },
                    json_mode=arguments.json_mode,
                )
                return int(ExitCode.SUCCESS)
            finally:
                repository.close()
        except (RepositoryError, sqlite3.Error, OSError) as exc:
            logger.error(
                "database_operation_failed", extra={"command": command, "reason": str(exc)}
            )
            _emit(
                {"ok": False, "command": command, "message": f"Database operation failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.DATABASE)
    logger.warning("command_unavailable", extra={"command": command})
    _emit(
        {
            "ok": False,
            "command": command,
            "message": f"Command is not implemented yet: {command}",
        },
        json_mode=arguments.json_mode,
    )
    return int(ExitCode.NOT_IMPLEMENTED)


def main() -> NoReturn:
    """Installed console entry point."""
    try:
        code = run()
    except KeyboardInterrupt:
        logging.getLogger("field_discovery").warning("interrupted")
        code = 130
    except Exception:
        logging.getLogger("field_discovery").exception("unexpected_error")
        code = int(ExitCode.INTERNAL)
    raise SystemExit(code)
