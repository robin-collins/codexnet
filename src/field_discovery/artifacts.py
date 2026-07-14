"""Bounded, redacted, restrictive storage for diagnostic text artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
import uuid
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from field_discovery.redaction import REDACTED, Redactor

DEFAULT_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_AUDIT_FILE_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_SAFE_CATEGORY = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_METADATA_SUFFIX = ".metadata.json"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class ArtifactError(ValueError):
    """Base error for an artifact rejected before publication."""


class UnsafeArtifactPath(ArtifactError):
    """An artifact path is ambiguous, traversing, or link based."""


class ArtifactTooLarge(ArtifactError):
    """An artifact exceeds its configured byte limit."""


@dataclass(frozen=True)
class ArtifactMetadata:
    """Durable, non-secret metadata for one sanitized artifact."""

    schema_version: int
    filename: str
    category: str
    media_type: str
    size_bytes: int
    sha256: str
    created_at: str
    expires_at: str


@dataclass(frozen=True)
class AuditFinding:
    """A file that is unsafe or would be changed by central redaction."""

    path: str
    reason: str


def validate_filename(filename: str) -> str:
    """Accept one portable basename; never accept a path or hidden name."""
    if not isinstance(filename, str) or not _SAFE_NAME.fullmatch(filename):
        raise UnsafeArtifactPath("artifact filename must be a safe portable basename")
    return filename


def safe_filename(label: str, *, suffix: str = "", redactor: Redactor | None = None) -> str:
    """Create a bounded portable filename from a display label."""
    if suffix and (not suffix.startswith(".") or not re.fullmatch(r"\.[A-Za-z0-9]{1,12}", suffix)):
        raise UnsafeArtifactPath("artifact suffix must be a simple extension")
    cleaned = (redactor or Redactor()).text(label)
    if REDACTED in cleaned:
        cleaned = "artifact"
    ascii_label = unicodedata.normalize("NFKD", cleaned).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", ascii_label).strip("._-")
    slug = re.sub(r"[-_.]{2,}", "-", slug) or "artifact"
    maximum = 100 - len(suffix)
    return validate_filename(f"{slug[:maximum].rstrip('._-') or 'artifact'}{suffix}")


class ArtifactStore:
    """Publish sanitized text artifacts beneath one link-safe directory."""

    def __init__(
        self,
        root: Path,
        *,
        redactor: Redactor | None = None,
        max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.root = root
        self.redactor = redactor or Redactor()
        self.max_bytes = max_bytes
        self._ensure_root()

    def _ensure_root(self) -> None:
        try:
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = self.root.lstat()
        except OSError as exc:
            raise UnsafeArtifactPath("artifact root cannot be prepared") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise UnsafeArtifactPath("artifact root must be a real directory")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise UnsafeArtifactPath(
                "artifact root permissions must not allow group or other access"
            )

    def _open_root(self) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY
        flags |= _NOFOLLOW
        try:
            return os.open(self.root, flags)
        except OSError as exc:
            raise UnsafeArtifactPath("artifact root is not link-safe") from exc

    def write_text(
        self,
        filename: str,
        content: str,
        *,
        category: str,
        retention: timedelta,
        media_type: str = "text/plain",
        now: datetime | None = None,
    ) -> ArtifactMetadata:
        """Redact and atomically publish bounded UTF-8 content and metadata."""
        if not isinstance(content, str):
            raise TypeError("artifact content must be text")
        return self._write(
            filename,
            self.redactor.text(content).encode("utf-8"),
            category=category,
            retention=retention,
            media_type=media_type,
            now=now,
        )

    def write_json(
        self,
        filename: str,
        value: Any,
        *,
        category: str,
        retention: timedelta,
        now: datetime | None = None,
    ) -> ArtifactMetadata:
        """Structurally redact and publish deterministic JSON."""
        content = json.dumps(
            self.redactor.value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return self._write(
            filename,
            content.encode("utf-8"),
            category=category,
            retention=retention,
            media_type="application/json",
            now=now,
        )

    def _write(
        self,
        filename: str,
        payload: bytes,
        *,
        category: str,
        retention: timedelta,
        media_type: str,
        now: datetime | None,
    ) -> ArtifactMetadata:
        filename = validate_filename(filename)
        if filename.endswith(_METADATA_SUFFIX):
            raise UnsafeArtifactPath("reserved metadata suffix")
        if not _SAFE_CATEGORY.fullmatch(category):
            raise ArtifactError("artifact category is invalid")
        if retention <= timedelta(0):
            raise ArtifactError("artifact retention must be positive")
        if len(payload) > self.max_bytes:
            raise ArtifactTooLarge(f"artifact exceeds configured {self.max_bytes} byte limit")
        created = (now or datetime.now(UTC)).astimezone(UTC)
        metadata = ArtifactMetadata(
            schema_version=1,
            filename=filename,
            category=category,
            media_type=media_type,
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            created_at=created.isoformat(),
            expires_at=(created + retention).isoformat(),
        )
        metadata_payload = json.dumps(
            asdict(metadata), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        directory_fd = self._open_root()
        metadata_name = filename + _METADATA_SUFFIX
        try:
            self._publish(directory_fd, metadata_name, metadata_payload)
            try:
                self._publish(directory_fd, filename, payload)
            except Exception:
                os.unlink(metadata_name, dir_fd=directory_fd)
                raise
        finally:
            os.close(directory_fd)
        return metadata

    @staticmethod
    def _publish(directory_fd: int, filename: str, payload: bytes) -> None:
        temporary = f".staging-{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= _NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(
                temporary,
                filename,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        finally:
            os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=directory_fd)

    def expired(self, *, now: datetime | None = None) -> list[ArtifactMetadata]:
        """List expired artifacts without deleting anything."""
        cutoff = (now or datetime.now(UTC)).astimezone(UTC)
        directory_fd = self._open_root()
        try:
            names = sorted(
                entry.name
                for entry in os.scandir(self.root)
                if entry.name.endswith(_METADATA_SUFFIX)
            )
            metadata = [self._read_metadata(directory_fd, name) for name in names]
            return [item for item in metadata if datetime.fromisoformat(item.expires_at) <= cutoff]
        finally:
            os.close(directory_fd)

    def prune_expired(
        self, *, now: datetime | None = None, dry_run: bool = True
    ) -> list[ArtifactMetadata]:
        """Retention hook; dry-run by default and link-safe when deleting."""
        expired = self.expired(now=now)
        if dry_run:
            return expired
        directory_fd = self._open_root()
        try:
            for metadata in expired:
                for name in (metadata.filename, metadata.filename + _METADATA_SUFFIX):
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode):
                        raise UnsafeArtifactPath("retention refuses non-regular artifact entries")
                os.unlink(metadata.filename, dir_fd=directory_fd)
                os.unlink(metadata.filename + _METADATA_SUFFIX, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
        return expired

    @staticmethod
    def _read_metadata(directory_fd: int, name: str) -> ArtifactMetadata:
        validate_filename(name)
        flags = os.O_RDONLY
        flags |= _NOFOLLOW
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_METADATA_BYTES:
                raise UnsafeArtifactPath("artifact metadata must be a bounded regular file")
            raw = os.read(descriptor, MAX_METADATA_BYTES + 1)
        finally:
            os.close(descriptor)
        try:
            value = json.loads(raw)
            metadata = ArtifactMetadata(**value)
            validate_filename(metadata.filename)
            datetime.fromisoformat(metadata.expires_at)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise UnsafeArtifactPath("artifact metadata is invalid") from exc
        if name != metadata.filename + _METADATA_SUFFIX:
            raise UnsafeArtifactPath("artifact metadata filename mismatch")
        return metadata


def audit_outputs(
    roots: list[Path], *, redactor: Redactor, max_file_bytes: int = MAX_AUDIT_FILE_BYTES
) -> list[AuditFinding]:
    """Scan text logs, exports, and artifacts for link hazards or redaction misses."""
    findings: list[AuditFinding] = []
    for root in roots:
        if root.is_symlink():
            findings.append(AuditFinding(str(root), "symlink"))
            continue
        candidates = [root] if root.is_file() else sorted(root.rglob("*"))
        for candidate in candidates:
            if candidate.is_symlink():
                findings.append(AuditFinding(str(candidate), "symlink"))
                continue
            if not candidate.is_file():
                continue
            size = candidate.stat().st_size
            if size > max_file_bytes:
                findings.append(AuditFinding(str(candidate), "oversized"))
                continue
            text = candidate.read_bytes().decode("utf-8", errors="replace")
            if redactor.text(text) != text:
                findings.append(AuditFinding(str(candidate), "sensitive-pattern"))
    return findings
