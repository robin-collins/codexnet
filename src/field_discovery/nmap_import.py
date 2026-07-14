"""Read-only, idempotent import of completed nmap XML artifact trees."""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from field_discovery.correlation import (
    DeviceObservation,
    FactEvidence,
    IdentifierKind,
    IdentityEvidence,
    NormalizationError,
    correlate,
)
from field_discovery.nmap_xml import NmapHost, NmapScan, NmapXmlError, parse_nmap_xml
from field_discovery.repository import Repository, RepositoryError

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_SOURCE = "nmap"
_fstat = os.fstat


class NmapImportError(RuntimeError):
    """The import root or import operation is invalid or unavailable."""


@dataclass(frozen=True)
class NmapImportIssue:
    """One isolated artifact discovery, read, parse, or normalization issue."""

    relative_path: str
    category: str
    detail: str
    retryable: bool


@dataclass(frozen=True)
class NmapImportSummary:
    """Deterministic operator-facing result for one recursive import pass."""

    discovered: int
    imported: int
    skipped: int
    deferred: int
    hosts: int
    issues: tuple[NmapImportIssue, ...]


@dataclass(frozen=True)
class _Candidate:
    path: Path
    relative_path: str


def _safe_detail(error: BaseException) -> str:
    if isinstance(error, PermissionError):
        return "permission denied"
    if isinstance(error, NmapXmlError):
        text = str(error)
        return text if len(text) <= 512 else f"{text[:509]}..."
    return error.__class__.__name__


def _incomplete_xml(error: NmapXmlError) -> bool:
    detail = str(error).casefold()
    return "malformed nmap xml" in detail and any(
        marker in detail for marker in ("no element found", "unclosed token")
    )


def _walk_xml(root: Path) -> tuple[list[_Candidate], list[NmapImportIssue]]:
    candidates: list[_Candidate] = []
    issues: list[NmapImportIssue] = []

    def walk(directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            relative = "." if directory == root else directory.relative_to(root).as_posix()
            issues.append(NmapImportIssue(relative, "discovery", _safe_detail(exc), True))
            return
        for entry in entries:
            path = Path(entry.path)
            try:
                if entry.is_dir(follow_symlinks=False):
                    walk(path)
                elif entry.is_file(follow_symlinks=False) and entry.name.casefold().endswith(
                    ".xml"
                ):
                    candidates.append(_Candidate(path, path.relative_to(root).as_posix()))
            except OSError as exc:
                issues.append(
                    NmapImportIssue(
                        path.relative_to(root).as_posix(),
                        "discovery",
                        _safe_detail(exc),
                        True,
                    )
                )

    walk(root)
    return candidates, issues


def _discover(source: Path) -> tuple[Path, list[_Candidate], list[NmapImportIssue]]:
    if not source.is_absolute():
        raise NmapImportError("nmap import path must be absolute")
    try:
        info = source.lstat()
    except OSError as exc:
        raise NmapImportError("nmap import path is unavailable") from exc
    if stat.S_ISLNK(info.st_mode):
        raise NmapImportError("nmap import path must not be a symlink")
    if stat.S_ISREG(info.st_mode):
        if not source.name.casefold().endswith(".xml"):
            raise NmapImportError("nmap import file must have an .xml suffix")
        return source.parent, [_Candidate(source, source.name)], []
    if not stat.S_ISDIR(info.st_mode):
        raise NmapImportError("nmap import path must be a regular file or directory")
    candidates, issues = _walk_xml(source)
    return source, candidates, issues


def _open_readonly(path: Path) -> BinaryIO:
    descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
    try:
        info = _fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise NmapImportError("artifact is not a regular file")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _scan_time(scan: NmapScan, info: os.stat_result) -> datetime:
    return scan.finished_at or scan.started_at or datetime.fromtimestamp(info.st_mtime, tz=UTC)


def _host_observation(
    host: NmapHost, *, digest: str, index: int, observed_at: datetime
) -> DeviceObservation:
    identifiers: list[IdentityEvidence] = []
    facts: list[FactEvidence] = []
    for address in host.addresses:
        if address.address_type == "mac":
            identifiers.append(
                IdentityEvidence(IdentifierKind.MAC, address.address, _SOURCE, observed_at)
            )
            if address.vendor:
                facts.append(FactEvidence("vendor", address.vendor, _SOURCE, observed_at, 0.9))
        elif address.address_type == "ipv4":
            identifiers.append(
                IdentityEvidence(IdentifierKind.IPV4, address.address, _SOURCE, observed_at, 0.8)
            )
    identifiers.extend(
        IdentityEvidence(IdentifierKind.HOSTNAME, item.name, _SOURCE, observed_at, 0.7)
        for item in host.hostnames
    )
    if host.state:
        facts.append(FactEvidence("host_state", host.state, _SOURCE, observed_at))
    for match in host.os_matches:
        facts.append(
            FactEvidence("os_guess", match.name, _SOURCE, observed_at, (match.accuracy or 0) / 100)
        )
    for script in host.scripts:
        facts.append(
            FactEvidence(
                f"nse:{script.script_id}", script.output or "(no output)", _SOURCE, observed_at
            )
        )
    return DeviceObservation(
        f"nmap:{digest}:{index}",
        _SOURCE,
        observed_at,
        tuple(identifiers),
        (),
        tuple(facts),
    )


def _json(repository: Repository, value: object) -> str:
    return json.dumps(
        repository.redactor.value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _text(repository: Repository, value: str | None) -> str | None:
    return None if value is None else repository.redactor.text(value)


def _persist(
    repository: Repository,
    *,
    deployment_id: int,
    collector_run_id: int | None,
    relative_path: str,
    digest: str,
    size: int,
    file_time: str,
    imported_at: str,
    scan: NmapScan,
    observations: tuple[DeviceObservation, ...],
) -> bool:
    """Persist an artifact and all normalized inventory in one transaction."""
    correlation = correlate(observations)
    path_value = repository.redactor.text(relative_path)
    if path_value != relative_path:
        raise RepositoryError("artifact path contains sensitive data")
    with repository.transaction():
        duplicate = repository.connection.execute(
            "SELECT 1 FROM artifacts WHERE relative_path = ? AND sha256_digest = ?",
            (relative_path, digest),
        ).fetchone()
        if duplicate is not None:
            return False
        device_ids: dict[str, int] = {}
        for device in correlation.devices:
            created_at = (
                min(item.observed_at for item in device.identifiers + device.facts).isoformat()
                if device.identifiers or device.facts
                else imported_at
            )
            repository.connection.execute(
                "INSERT INTO devices(deployment_id, canonical_key, created_at) VALUES (?, ?, ?) "
                "ON CONFLICT(deployment_id, canonical_key) DO NOTHING",
                (deployment_id, device.canonical_key, created_at),
            )
            device_id = int(
                repository.connection.execute(
                    "SELECT id FROM devices WHERE deployment_id = ? AND canonical_key = ?",
                    (deployment_id, device.canonical_key),
                ).fetchone()[0]
            )
            device_ids[device.canonical_key] = device_id
            for identity in device.identifiers:
                alias_value = repository.redactor.text(identity.value)
                repository.connection.execute(
                    "INSERT OR IGNORE INTO device_aliases"
                    "(device_id, alias_kind, alias_value, confidence, source, observed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        device_id,
                        identity.kind.value,
                        alias_value,
                        identity.confidence,
                        _SOURCE,
                        identity.observed_at.isoformat(),
                    ),
                )
                if identity.kind in {IdentifierKind.IPV4, IdentifierKind.MAC}:
                    repository.connection.execute(
                        "INSERT OR IGNORE INTO address_assignments"
                        "(device_id, address_kind, address, first_seen_at, last_seen_at, source, "
                        "observed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            device_id,
                            identity.kind.value,
                            alias_value,
                            identity.observed_at.isoformat(),
                            identity.observed_at.isoformat(),
                            _SOURCE,
                            identity.observed_at.isoformat(),
                        ),
                    )
            for fact in device.facts:
                repository.connection.execute(
                    "INSERT OR IGNORE INTO observations"
                    "(deployment_id, subject_type, subject_id, fact_type, fact_value_json, "
                    "confidence, inferred, source, observed_at) VALUES (?, 'device', ?, ?, ?, "
                    "?, 0, ?, ?)",
                    (
                        deployment_id,
                        device_id,
                        fact.field,
                        _json(repository, fact.value),
                        fact.confidence,
                        _SOURCE,
                        fact.observed_at.isoformat(),
                    ),
                )
        observation_to_device = {
            observation_id: device_ids[device.canonical_key]
            for device in correlation.devices
            for observation_id in device.observation_ids
        }
        for index, host in enumerate(scan.hosts):
            device_id = observation_to_device[f"nmap:{digest}:{index}"]
            host_time = observations[index].observed_at.isoformat()
            for port in host.ports:
                repository.connection.execute(
                    "INSERT OR IGNORE INTO services"
                    "(device_id, transport, port, service_name, product, version, state, source, "
                    "observed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        device_id,
                        port.protocol,
                        port.port,
                        _text(repository, port.service.name) if port.service else None,
                        _text(repository, port.service.product) if port.service else None,
                        _text(repository, port.service.version) if port.service else None,
                        _text(repository, port.state),
                        _SOURCE,
                        host_time,
                    ),
                )
                service_id = int(
                    repository.connection.execute(
                        "SELECT id FROM services WHERE device_id = ? AND transport = ? AND "
                        "port = ? AND source = ? AND observed_at = ?",
                        (device_id, port.protocol, port.port, _SOURCE, host_time),
                    ).fetchone()[0]
                )
                for script in port.scripts:
                    repository.connection.execute(
                        "INSERT OR IGNORE INTO observations"
                        "(deployment_id, subject_type, subject_id, fact_type, fact_value_json, "
                        "confidence, inferred, source, observed_at) VALUES (?, 'service', ?, "
                        "?, ?, 1.0, 0, ?, ?)",
                        (
                            deployment_id,
                            service_id,
                            f"nse:{script.script_id}",
                            _json(repository, script.output or "(no output)"),
                            _SOURCE,
                            host_time,
                        ),
                    )
        repository.connection.execute(
            "INSERT INTO artifacts"
            "(deployment_id, collector_run_id, relative_path, sha256_digest, media_type, "
            "size_bytes, collected_at, imported_at, source, observed_at) "
            "VALUES (?, ?, ?, ?, 'application/xml', ?, ?, ?, ?, ?)",
            (
                deployment_id,
                collector_run_id,
                relative_path,
                digest,
                size,
                file_time,
                imported_at,
                _SOURCE,
                imported_at,
            ),
        )
    return True


def import_nmap_artifacts(
    repository: Repository,
    source: Path,
    *,
    deployment_id: int,
    collector_run_id: int | None = None,
    stability_seconds: float = 5.0,
    now: datetime | None = None,
) -> NmapImportSummary:
    """Recursively import stable, completed XML while isolating artifact failures."""
    if not math.isfinite(stability_seconds) or stability_seconds < 0:
        raise NmapImportError("stability_seconds must be a finite non-negative number")
    current_time = now or datetime.now(UTC)
    _root, candidates, issues = _discover(source)
    imported = skipped = deferred = hosts = 0
    for candidate in candidates:
        try:
            with _open_readonly(candidate.path) as stream:
                before = _fstat(stream.fileno())
                if current_time.timestamp() - before.st_mtime < stability_seconds:
                    deferred += 1
                    continue
                digest_builder = hashlib.sha256()
                while chunk := stream.read(64 * 1024):
                    digest_builder.update(chunk)
                digest = digest_builder.hexdigest()
                existing = repository.connection.execute(
                    "SELECT 1 FROM artifacts WHERE relative_path = ? AND sha256_digest = ?",
                    (candidate.relative_path, digest),
                ).fetchone()
                if existing is not None:
                    skipped += 1
                    continue
                stream.seek(0)
                try:
                    scan = parse_nmap_xml(stream)
                except NmapXmlError as exc:
                    if _incomplete_xml(exc):
                        deferred += 1
                        continue
                    raise
                stream.seek(0)
                verified_digest = hashlib.sha256()
                while chunk := stream.read(64 * 1024):
                    verified_digest.update(chunk)
                after = _fstat(stream.fileno())
                if verified_digest.hexdigest() != digest or (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                    deferred += 1
                    continue
                if scan.finished_at is None and scan.exit_status is None:
                    deferred += 1
                    continue
                observed_at = _scan_time(scan, before)
                observations = tuple(
                    _host_observation(host, digest=digest, index=index, observed_at=observed_at)
                    for index, host in enumerate(scan.hosts)
                )
                imported_at = current_time.isoformat()
                created = _persist(
                    repository,
                    deployment_id=deployment_id,
                    collector_run_id=collector_run_id,
                    relative_path=candidate.relative_path,
                    digest=digest,
                    size=before.st_size,
                    file_time=datetime.fromtimestamp(before.st_mtime, tz=UTC).isoformat(),
                    imported_at=imported_at,
                    scan=scan,
                    observations=observations,
                )
                if created:
                    imported += 1
                    hosts += len(scan.hosts)
                else:
                    skipped += 1
        except (OSError, NmapXmlError, NormalizationError, RepositoryError, sqlite3.Error) as exc:
            issues.append(
                NmapImportIssue(
                    candidate.relative_path,
                    "permission" if isinstance(exc, PermissionError) else "artifact",
                    _safe_detail(exc),
                    isinstance(exc, OSError | NmapXmlError),
                )
            )
    return NmapImportSummary(
        len(candidates),
        imported,
        skipped,
        deferred,
        hosts,
        tuple(sorted(issues, key=lambda item: (item.relative_path, item.category))),
    )
