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
from field_discovery.ad_collection import (
    ActiveDirectoryCollector,
    Ldap3SessionFactory,
    resolve_ad_credentials,
)
from field_discovery.ad_detection import (
    ADDetectionError,
    ADDetector,
    DnspythonResolver,
    Ldap3RootDSEProbe,
    persist_detection,
    repository_service_evidence,
)
from field_discovery.artifacts import ArtifactStore
from field_discovery.collectors import (
    CollectorContext,
    CollectorError,
    CollectorOrchestrator,
    CollectorRequest,
    CredentialReference,
)
from field_discovery.config import ConfigurationError, load_config
from field_discovery.diagnostics import collect_doctor, collect_status
from field_discovery.logging import configure_logging
from field_discovery.nmap_import import NmapImportError, import_nmap_artifacts
from field_discovery.nmap_scan import ScanLaunchError, run_nmap_scan
from field_discovery.reporting import ReportError, generate_reports, validate_docx
from field_discovery.repository import Repository, RepositoryError, RetentionCutoffs
from field_discovery.snmp import SnmpCollector
from field_discovery.ssh_collection import (
    ConfigSecretResolver,
    NetmikoSessionFactory,
    NetworkDeviceSSHCollector,
)
from field_discovery.storage import (
    BackupPruner,
    DiskGuard,
    LowDiskSpace,
    UnsafeStoragePath,
    prune_artifact_tree,
)
from field_discovery.subnet import SubnetResolutionError, resolve_subnet
from field_discovery.unifi import (
    UniFiError,
    endpoint_from_config,
    resolve_credentials,
)
from field_discovery.unifi_inventory import UniFiInventoryCollector, persist_inventory

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
    DIAGNOSTIC = 11
    STORAGE = 12


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
    ad_discovery = _command_parser(discover_sub, "ad", "detect AD without credentials")
    ad_discovery.add_argument("--domain", action="append", help="explicit approved DNS domain")
    ad_discovery.add_argument("--site", action="append", help="optional AD site SRV scope")

    collect = _command_parser(commands, "collect", "collector operations")
    collect_sub = collect.add_subparsers(dest="action", required=True)
    passive = _command_parser(collect_sub, "passive", "passive observer operations")
    passive_sub = passive.add_subparsers(dest="detail", required=True)
    _command_parser(passive_sub, "status", "show passive observer status")
    snmp = _command_parser(collect_sub, "snmp", "run SNMP collection")
    snmp.add_argument("--target", action="append", required=True)
    unifi = _command_parser(collect_sub, "unifi", "run UniFi collection")
    unifi.add_argument("--controller", action="append")
    ad = _command_parser(collect_sub, "ad", "run Active Directory collection")
    ad.add_argument("--domain")
    ad.add_argument("--target", required=True, help="explicit approved domain-controller IPv4")
    ad.add_argument("--server-name", help="certificate/SPN hostname for the approved target")
    ssh = _command_parser(collect_sub, "ssh", "run network-device SSH collection")
    ssh.add_argument("--target", action="append", required=True)
    ssh.add_argument(
        "--platform",
        choices=("cisco_ios", "hp_comware", "aruba_aos"),
        required=True,
        help="explicit conservative platform selection for the approved targets",
    )

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
    restore = _command_parser(database_sub, "restore", "restore a verified backup to a new file")
    restore.add_argument("backup", type=Path, help="backup inside configured data root")
    restore.add_argument("--output", type=Path, required=True, help="new database path")
    prune = _command_parser(database_sub, "prune", "prune data according to retention policy")
    prune.add_argument("--apply", action="store_true", help="apply the default dry-run plan")
    recover = _command_parser(database_sub, "recover", "mark boot-interrupted runs failed")
    recover.add_argument(
        "--confirm-stopped",
        action="store_true",
        required=True,
        help="confirm every CodexNet writer is stopped",
    )
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


def _emit_diagnostics(report: dict[str, object], *, command: str, json_mode: bool) -> None:
    summary = cast(dict[str, object], report["summary"])
    state = "healthy" if report["ok"] else "degraded"
    message = (
        f"Appliance {state}: {summary['errors']} errors, {summary['warnings']} warnings, "
        f"{summary['checks']} checks."
    )
    if json_mode:
        print(
            json.dumps(
                {**report, "command": command, "message": message},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return
    print(message)
    for item in cast(list[dict[str, object]], report["checks"]):
        print(f"[{str(item['status']).upper()}] {item['name']}: {item['message']}")


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
        report = collect_status(configuration.data)
        _emit_diagnostics(report, command=command, json_mode=arguments.json_mode)
        return int(ExitCode.SUCCESS if report["ok"] else ExitCode.DIAGNOSTIC)
    if command == "doctor":
        report = collect_doctor(configuration.data)
        _emit_diagnostics(report, command=command, json_mode=arguments.json_mode)
        return int(ExitCode.SUCCESS if report["ok"] else ExitCode.DIAGNOSTIC)
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
    if command == "discover ad":
        configured_domain = configuration.data["collectors"]["ad"]["domain"]
        domains = arguments.domain or ([configured_domain] if configured_domain else [])
        if not domains:
            _emit(
                {
                    "ok": False,
                    "command": command,
                    "message": "AD detection requires an explicitly configured or supplied domain.",
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.CONFIGURATION)
        paths = configuration.data["paths"]
        ad_repository: Repository | None = None
        ad_run: int | None = None
        try:
            ad_repository = Repository.open(
                Path(paths["database"]), data_root=Path(paths["data_root"])
            )
            timestamp = datetime.now(UTC)
            deployment_id = ad_repository.upsert_deployment(
                "default", "Default deployment", timestamp.isoformat()
            )
            ad_run = ad_repository.start_run(
                deployment_id,
                "ad_detection",
                timestamp.isoformat(),
                interface_name=configuration.data["interface"]["name"],
                target_cidr=",".join(domains),
            )
            scheduler = configuration.data["scheduler"]
            detector = ADDetector(
                DnspythonResolver(scheduler["timeout_seconds"]),
                Ldap3RootDSEProbe(scheduler["timeout_seconds"]),
                configuration.data["active"]["approved_ranges"],
                concurrency=scheduler["concurrency"],
            )
            evidence = repository_service_evidence(ad_repository, deployment_id, domains)
            ad_result = asyncio.run(
                detector.detect(domains, sites=arguments.site or (), service_evidence=evidence)
            )
            persist_detection(ad_repository, deployment_id, ad_result, observed_at=timestamp)
            for ad_issue in ad_result.issues:
                ad_repository.record_collector_error(
                    ad_run,
                    category=ad_issue.category,
                    detail=f"{ad_issue.subject}: {ad_issue.detail}",
                    retryable=ad_issue.category.endswith("unreachable"),
                    source="ad_detection",
                    observed_at=timestamp.isoformat(),
                )
            status = "partial" if ad_result.issues else "succeeded"
            ad_repository.finish_run(
                ad_run, status, datetime.now(UTC).isoformat(), len(ad_result.candidates)
            )
            candidates = [
                {
                    "domain": item.domain,
                    "hostname": item.hostname,
                    "addresses": list(item.addresses),
                    "ports": list(item.ports),
                    "sites": list(item.sites),
                    "sources": list(item.sources),
                    "confidence": item.confidence,
                }
                for item in ad_result.candidates
            ]
            _emit(
                {
                    "ok": True,
                    "command": command,
                    "message": (
                        f"AD detection: {len(candidates)} candidates, "
                        f"{len(ad_result.issues)} limitations."
                    ),
                    "domains": list(ad_result.domains),
                    "candidates": candidates,
                    "limitations": len(ad_result.issues),
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.SUCCESS)
        except (ADDetectionError, RepositoryError, sqlite3.Error, OSError) as exc:
            if ad_repository is not None and ad_run is not None:
                with suppress(RepositoryError, sqlite3.Error):
                    ad_repository.finish_run(ad_run, "failed", datetime.now(UTC).isoformat(), 0)
            logger.error("ad_detection_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"AD detection failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.COLLECTOR)
        finally:
            if ad_repository is not None:
                ad_repository.close()
    if command == "collect snmp":
        paths = configuration.data["paths"]
        settings = configuration.data["collectors"]["snmp"]
        reference = CredentialReference.from_mapping(settings["credential_ref"])
        if reference is None:
            _emit(
                {
                    "ok": False,
                    "command": command,
                    "message": "SNMP collection requires a configured credential reference.",
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.CONFIGURATION)
        notice: str | None = None
        if settings["protocol"] == "v2c":
            notice = "Security notice: SNMPv2c is unencrypted and was explicitly enabled."
            logger.warning("snmp_v2c_explicitly_enabled", extra={"command": command})
        snmp_repository: Repository | None = None
        try:
            snmp_repository = Repository.open(
                Path(paths["database"]), data_root=Path(paths["data_root"])
            )
            timestamp = datetime.now(UTC)
            deployment_id = snmp_repository.upsert_deployment(
                "default", "Default deployment", timestamp.isoformat()
            )
            scheduler = configuration.data["scheduler"]
            snmp_collector = SnmpCollector(
                repository=snmp_repository,
                deployment_id=deployment_id,
                protocol=settings["protocol"],
                allow_insecure_v2c=settings["allow_insecure_v2c"],
                providers=configuration.data["secret_providers"],
                timeout_seconds=scheduler["timeout_seconds"],
            )
            orchestrator = CollectorOrchestrator(
                repository=snmp_repository,
                deployment_id=deployment_id,
                approved_ranges=configuration.data["active"]["approved_ranges"],
                collectors={"snmp": snmp_collector},
                concurrency=scheduler["concurrency"],
                timeout_seconds=scheduler["timeout_seconds"],
                retries=scheduler["retries"],
                interface_name=configuration.data["interface"]["name"],
            )
            summaries = asyncio.run(
                orchestrator.run(
                    [
                        CollectorRequest("snmp", target, reference)
                        for target in cast(list[str], arguments.target)
                    ]
                )
            )
            failures = sum(summary.status not in {"succeeded", "partial"} for summary in summaries)
            partial = sum(summary.status == "partial" for summary in summaries)
            total = sum(summary.item_count for summary in summaries)
            ok = failures == 0
            message = (
                f"SNMP collection: {total} facts, {partial} partial, {failures} failed targets."
            )
            if notice is not None:
                message = f"{notice} {message}"
            _emit(
                {
                    "ok": ok,
                    "command": command,
                    "message": message,
                    "facts": total,
                    "partial": partial,
                    "failures": failures,
                    "protocol": settings["protocol"],
                    "security_notice": notice,
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.SUCCESS if ok else ExitCode.COLLECTOR)
        except (CollectorError, RepositoryError, sqlite3.Error, OSError) as exc:
            logger.error("snmp_collection_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"SNMP collection failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.COLLECTOR)
        finally:
            if snmp_repository is not None:
                snmp_repository.close()
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
                    collector = UniFiInventoryCollector(
                        endpoint,
                        lambda requested: resolve_credentials(
                            requested, configuration.data["secret_providers"]
                        ),
                        lambda inventory: persist_inventory(
                            unifi_repository, deployment_id, inventory
                        ),
                        timestamp,
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
                    for issue in unifi_result.issues:
                        unifi_repository.record_collector_error(
                            unifi_run,
                            category=issue.category,
                            detail=issue.detail,
                            retryable=issue.retryable,
                            source="unifi",
                            observed_at=datetime.now(UTC).isoformat(),
                        )
                    unifi_repository.finish_run(
                        unifi_run,
                        "partial" if unifi_result.issues else "succeeded",
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
                    "message": (
                        f"UniFi collection: {total} normalized entities, "
                        f"{failures} failed controllers."
                    ),
                    "entities": total,
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
    if command == "collect ad":
        settings = configuration.data["collectors"]["ad"]
        reference = CredentialReference.from_mapping(settings["credential_ref"])
        domain = arguments.domain or settings["domain"]
        server_name = arguments.server_name or settings["server_name"]
        base_dn = settings["base_dn"]
        if reference is None:
            _emit(
                {
                    "ok": False,
                    "command": command,
                    "message": "AD collection requires a configured credential reference.",
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.CONFIGURATION)
        if not domain or not base_dn or not server_name:
            _emit(
                {
                    "ok": False,
                    "command": command,
                    "message": "AD collection requires domain, base DN, and server name.",
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.CONFIGURATION)
        paths = configuration.data["paths"]
        ad_collection_repository: Repository | None = None
        try:
            ad_collection_repository = Repository.open(
                Path(paths["database"]), data_root=Path(paths["data_root"])
            )
            timestamp = datetime.now(UTC)
            deployment_id = ad_collection_repository.upsert_deployment(
                "default", "Default deployment", timestamp.isoformat()
            )
            scheduler = configuration.data["scheduler"]
            ad_collector = ActiveDirectoryCollector(
                ad_collection_repository,
                deployment_id,
                Ldap3SessionFactory(),
                lambda requested, transport: resolve_ad_credentials(
                    requested, configuration.data["secret_providers"], transport
                ),
                domain=domain,
                base_dn=base_dn,
                transport=settings["transport"],
                allow_plaintext_ldap=settings["allow_plaintext_ldap"],
                server_name=server_name,
                page_size=settings["page_size"],
                max_entries=settings["max_entries"],
                documentation_groups=settings["documentation_groups"],
                timeout=scheduler["timeout_seconds"],
            )
            orchestrator = CollectorOrchestrator(
                repository=ad_collection_repository,
                deployment_id=deployment_id,
                approved_ranges=configuration.data["active"]["approved_ranges"],
                collectors={"ad": ad_collector},
                concurrency=1,
                timeout_seconds=scheduler["timeout_seconds"],
                retries=scheduler["retries"],
                interface_name=configuration.data["interface"]["name"],
            )
            ad_summary = asyncio.run(
                orchestrator.run([CollectorRequest("ad", arguments.target, reference)])
            )[0]
            ok = ad_summary.status in {"succeeded", "partial"}
            security_notice = (
                "Plaintext LDAP was explicitly enabled; credentials and directory traffic "
                "are not transport encrypted."
                if settings["transport"] == "ldap"
                else None
            )
            if security_notice:
                logger.warning("ad_plaintext_ldap_explicitly_enabled", extra={"command": command})
            _emit(
                {
                    "ok": ok,
                    "command": command,
                    "message": (
                        f"AD collection {ad_summary.status}: {ad_summary.item_count} records, "
                        f"{ad_summary.error_count} limitations."
                    ),
                    "status": ad_summary.status,
                    "records": ad_summary.item_count,
                    "limitations": ad_summary.error_count,
                    "transport": settings["transport"],
                    "security_notice": security_notice,
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.SUCCESS if ok else ExitCode.COLLECTOR)
        except (CollectorError, RepositoryError, sqlite3.Error, OSError) as exc:
            logger.error("ad_collection_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"AD collection failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.COLLECTOR)
        finally:
            if ad_collection_repository is not None:
                ad_collection_repository.close()
    if command == "collect ssh":
        paths = configuration.data["paths"]
        settings = configuration.data["collectors"]["ssh"]
        reference = CredentialReference.from_mapping(settings["credential_ref"])
        if reference is None:
            _emit(
                {
                    "ok": False,
                    "command": command,
                    "message": "SSH collection requires a configured credential reference.",
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.CONFIGURATION)
        ssh_repository: Repository | None = None
        try:
            data_root = Path(paths["data_root"])
            ssh_repository = Repository.open(Path(paths["database"]), data_root=data_root)
            timestamp = datetime.now(UTC)
            deployment_id = ssh_repository.upsert_deployment(
                "default", "Default deployment", timestamp.isoformat()
            )
            ssh_collector = NetworkDeviceSSHCollector(
                repository=ssh_repository,
                deployment_id=deployment_id,
                artifact_store=ArtifactStore(
                    data_root / "artifacts" / "ssh",
                    redactor=ssh_repository.redactor,
                    space_guard=DiskGuard.from_config(configuration.data).check,
                ),
                session_factory=NetmikoSessionFactory(),
                secret_resolver=ConfigSecretResolver(configuration.data["secret_providers"]),
                platform=arguments.platform,
                host_key_policy=settings["host_key_policy"],
                retention=timedelta(days=configuration.data["retention"]["detailed_days"]),
            )
            scheduler = configuration.data["scheduler"]
            orchestrator = CollectorOrchestrator(
                repository=ssh_repository,
                deployment_id=deployment_id,
                approved_ranges=configuration.data["active"]["approved_ranges"],
                collectors={"ssh": ssh_collector},
                concurrency=1,
                timeout_seconds=scheduler["timeout_seconds"],
                retries=scheduler["retries"],
                interface_name=configuration.data["interface"]["name"],
            )
            summaries = asyncio.run(
                orchestrator.run(
                    [
                        CollectorRequest("ssh", target, reference)
                        for target in cast(list[str], arguments.target)
                    ]
                )
            )
            failed = sum(summary.status not in {"succeeded", "partial"} for summary in summaries)
            partial = sum(summary.status == "partial" for summary in summaries)
            total = sum(summary.item_count for summary in summaries)
            ok = failed == 0
            _emit(
                {
                    "ok": ok,
                    "command": command,
                    "message": (
                        f"SSH collection: {total} facts, {partial} partial, "
                        f"{failed} failed targets."
                    ),
                    "facts": total,
                    "partial": partial,
                    "failures": failed,
                },
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.SUCCESS if ok else ExitCode.COLLECTOR)
        except (CollectorError, RepositoryError, sqlite3.Error, OSError) as exc:
            logger.error("ssh_collection_failed", extra={"command": command, "reason": str(exc)})
            _emit(
                {"ok": False, "command": command, "message": f"SSH collection failed: {exc}"},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.COLLECTOR)
        finally:
            if ssh_repository is not None:
                ssh_repository.close()
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
            for nmap_issue in summary.issues:
                repository.connection.execute(
                    "INSERT INTO collector_errors"
                    "(collector_run_id, category, detail, retryable, source, observed_at) "
                    "VALUES (?, ?, ?, ?, 'nmap_import', ?)",
                    (
                        run_record,
                        nmap_issue.category,
                        repository.redactor.text(nmap_issue.detail),
                        int(nmap_issue.retryable),
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
                "validated_parts": len(validation.entries),
                "external_relationships": list(validation.external_relationships),
                "upload_ready": True,
            },
            json_mode=arguments.json_mode,
        )
        return int(ExitCode.SUCCESS)
    if command == "report generate":
        paths = configuration.data["paths"]
        repository = None
        try:
            DiskGuard.from_config(configuration.data).check(Path(paths["data_root"]))
            repository = Repository.open(
                Path(paths["database"]), data_root=Path(paths["data_root"])
            )
            deployment = repository.connection.execute(
                "SELECT id FROM deployments ORDER BY id LIMIT 1"
            ).fetchone()
            if deployment is None:
                raise ReportError("no deployment is available to report")
            report_settings = configuration.data["report"]
            missing_metadata = [
                key
                for key in ("customer_name", "site_name", "author")
                if report_settings[key] is None
            ]
            if missing_metadata:
                raise ReportError(
                    "report generation requires explicit metadata: " + ", ".join(missing_metadata)
                )
            outputs = generate_reports(
                repository,
                int(deployment["id"]),
                arguments.output_dir or Path(paths["data_root"]) / "reports",
                generated_at=datetime.now(UTC),
                customer_name=str(report_settings["customer_name"]),
                site_name=str(report_settings["site_name"]),
                author=str(report_settings["author"]),
                company_name=str(report_settings["company_name"]),
                confidentiality=str(report_settings["confidentiality"]),
                document_version=str(report_settings["document_version"]),
                template_path=(
                    Path(str(report_settings["template"]))
                    if report_settings["template"] is not None
                    else None
                ),
            )
            payload = {
                "ok": True,
                "command": command,
                "message": (
                    f"DOCX report generated and validated for manual upload: {outputs.docx_path}"
                ),
                "docx": str(outputs.docx_path),
                "json": str(outputs.json_path),
                "docx_sha256": outputs.docx_sha256,
                "json_sha256": outputs.json_sha256,
                "upload_ready": True,
            }
            logger.info("report_generated", extra={"command": command})
            _emit(payload, json_mode=arguments.json_mode)
            return int(ExitCode.SUCCESS)
        except LowDiskSpace as exc:
            logger.warning("report_generation_paused", extra={"command": command})
            _emit(
                {"ok": False, "command": command, "message": str(exc)},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.STORAGE)
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
        data_root = Path(paths["data_root"])
        try:
            if arguments.action == "restore":
                DiskGuard.from_config(configuration.data).check(
                    data_root, arguments.backup.stat().st_size
                )
                restored = Repository.restore_backup(
                    arguments.backup, arguments.output, data_root=data_root
                )
                _emit(
                    {
                        "ok": True,
                        "command": command,
                        "message": f"Verified database restored to new path: {restored}",
                        "path": str(restored),
                    },
                    json_mode=arguments.json_mode,
                )
                return int(ExitCode.SUCCESS)
            repository = Repository.open(Path(paths["database"]), data_root=data_root)
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
                    DiskGuard.from_config(configuration.data).check(
                        data_root, repository.database_path.stat().st_size
                    )
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
                if arguments.action == "recover":
                    recovered = repository.recover_interrupted_runs(datetime.now(UTC).isoformat())
                    _emit(
                        {
                            "ok": True,
                            "command": command,
                            "message": f"Recovered {recovered} interrupted collector runs.",
                            "recovered_runs": recovered,
                        },
                        json_mode=arguments.json_mode,
                    )
                    return int(ExitCode.SUCCESS)
                retention_days = configuration.data["retention"]["detailed_days"]
                retention = configuration.data["retention"]
                now = datetime.now(UTC)
                backup_pruner = BackupPruner(data_root)
                backup_plan = backup_pruner.plan(
                    before=now - timedelta(days=retention["backup_days"])
                )
                artifact_count = prune_artifact_tree(data_root / "artifacts", now=now, dry_run=True)
                prune_result = repository.prune(
                    RetentionCutoffs(
                        (now - timedelta(days=retention_days)).isoformat(),
                        (now - timedelta(days=retention["artifact_days"])).isoformat(),
                        (now - timedelta(days=retention["report_days"])).isoformat(),
                    ),
                    dry_run=not arguments.apply,
                )
                if arguments.apply:
                    backup_pruner.apply(backup_plan)
                    prune_artifact_tree(data_root / "artifacts", now=now, dry_run=False)
                mode = "preview" if prune_result.dry_run else "applied"
                counts = {
                    **prune_result.counts,
                    "artifact_files": artifact_count,
                    "backup_files": len(backup_plan),
                }
                logger.info("database_prune_completed", extra={"command": command, "mode": mode})
                _emit(
                    {
                        "ok": True,
                        "command": command,
                        "message": (
                            f"Database prune {mode}: {sum(counts.values())} expired items."
                        ),
                        "dry_run": prune_result.dry_run,
                        "counts": counts,
                    },
                    json_mode=arguments.json_mode,
                )
                return int(ExitCode.SUCCESS)
            finally:
                repository.close()
        except LowDiskSpace as exc:
            logger.warning("database_operation_paused", extra={"command": command})
            _emit(
                {"ok": False, "command": command, "message": str(exc)},
                json_mode=arguments.json_mode,
            )
            return int(ExitCode.STORAGE)
        except (RepositoryError, UnsafeStoragePath, sqlite3.Error, OSError) as exc:
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
