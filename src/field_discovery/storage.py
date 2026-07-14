"""Disk reserve enforcement for artifact-heavy local operations."""

from __future__ import annotations

import os
import re
import shutil
import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from field_discovery.artifacts import ArtifactStore, UnsafeArtifactPath


class LowDiskSpace(RuntimeError):
    """Artifact-heavy work was paused before consuming the configured reserve."""


class UnsafeStoragePath(RuntimeError):
    """A retention path was linked, changed, or outside its exact owned shape."""


@dataclass(frozen=True)
class DiskStatus:
    """Capacity remaining after one proposed local write."""

    checked_path: str
    total_bytes: int
    free_bytes: int
    required_bytes: int
    remaining_bytes: int
    remaining_percent: float
    minimum_free_bytes: int
    minimum_free_percent: int
    allowed: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


UsageProbe = Callable[[Path], Any]


@dataclass(frozen=True)
class DiskGuard:
    """Pause heavy writes when either byte or percentage reserve would be crossed."""

    minimum_free_bytes: int
    minimum_free_percent: int
    usage_probe: UsageProbe = shutil.disk_usage

    @classmethod
    def from_config(cls, configuration: dict[str, Any]) -> DiskGuard:
        settings = configuration["storage"]
        return cls(
            minimum_free_bytes=int(settings["minimum_free_bytes"]),
            minimum_free_percent=int(settings["minimum_free_percent"]),
        )

    def inspect(self, path: Path, required_bytes: int = 0) -> DiskStatus:
        if required_bytes < 0:
            raise ValueError("required_bytes must not be negative")
        candidate = path
        while not candidate.exists() and candidate != candidate.parent:
            candidate = candidate.parent
        usage = self.usage_probe(candidate)
        total = int(usage.total)
        free = int(usage.free)
        remaining = max(0, free - required_bytes)
        percentage = round(remaining * 100 / total, 2) if total else 0.0
        allowed = remaining >= self.minimum_free_bytes and percentage >= self.minimum_free_percent
        return DiskStatus(
            checked_path=str(candidate),
            total_bytes=total,
            free_bytes=free,
            required_bytes=required_bytes,
            remaining_bytes=remaining,
            remaining_percent=percentage,
            minimum_free_bytes=self.minimum_free_bytes,
            minimum_free_percent=self.minimum_free_percent,
            allowed=allowed,
        )

    def check(self, path: Path, required_bytes: int = 0) -> DiskStatus:
        status = self.inspect(path, required_bytes)
        if not status.allowed:
            raise LowDiskSpace(
                "artifact-heavy work paused: available disk reserve is below the configured "
                f"{status.minimum_free_bytes} byte/{status.minimum_free_percent}% threshold"
            )
        return status


_BACKUP_NAME = re.compile(r"^discovery-backup-\d{8}T\d{6}Z\.db$")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True)
class OwnedFile:
    """Identity snapshot used to make preview/apply deletion parity verifiable."""

    name: str
    device: int
    inode: int
    size: int
    modified_ns: int


class BackupPruner:
    """Plan and delete only exact scheduler-created backups in one real data root."""

    def __init__(self, data_root: Path) -> None:
        self.data_root = data_root

    def _open_root(self) -> int:
        try:
            info = self.data_root.lstat()
        except OSError as exc:
            raise UnsafeStoragePath("backup root is unavailable") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise UnsafeStoragePath("backup root must be a real directory")
        try:
            return os.open(self.data_root, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW)
        except OSError as exc:
            raise UnsafeStoragePath("backup root is not link-safe") from exc

    def plan(self, *, before: datetime) -> tuple[OwnedFile, ...]:
        descriptor = self._open_root()
        try:
            results: list[OwnedFile] = []
            for entry in os.scandir(self.data_root):
                if not _BACKUP_NAME.fullmatch(entry.name):
                    continue
                info = os.stat(entry.name, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise UnsafeStoragePath("backup retention refuses non-regular entries")
                modified = datetime.fromtimestamp(info.st_mtime, tz=before.tzinfo)
                if modified < before:
                    results.append(
                        OwnedFile(
                            entry.name,
                            info.st_dev,
                            info.st_ino,
                            info.st_size,
                            info.st_mtime_ns,
                        )
                    )
            return tuple(sorted(results, key=lambda item: item.name))
        finally:
            os.close(descriptor)

    def apply(self, plan: tuple[OwnedFile, ...]) -> tuple[OwnedFile, ...]:
        descriptor = self._open_root()
        try:
            for item in plan:
                if not _BACKUP_NAME.fullmatch(item.name):
                    raise UnsafeStoragePath("backup retention plan contains an invalid name")
                info = os.stat(item.name, dir_fd=descriptor, follow_symlinks=False)
                identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                if not stat.S_ISREG(info.st_mode) or identity != (
                    item.device,
                    item.inode,
                    item.size,
                    item.modified_ns,
                ):
                    raise UnsafeStoragePath("backup changed after retention preview")
            for item in plan:
                os.unlink(item.name, dir_fd=descriptor)
        finally:
            os.close(descriptor)
        return plan


def prune_artifact_tree(root: Path, *, now: datetime, dry_run: bool) -> int:
    """Prune expiry-metadata artifacts only from real immediate owned directories."""
    if not root.exists():
        return 0
    info = root.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise UnsafeStoragePath("artifact retention root must be a real directory")
    count = 0
    for entry in sorted(os.scandir(root), key=lambda item: item.name):
        entry_info = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(entry_info.st_mode) or not stat.S_ISDIR(entry_info.st_mode):
            raise UnsafeStoragePath("artifact retention refuses unexpected entries")
        try:
            store = ArtifactStore(Path(entry.path))
            count += len(store.prune_expired(now=now, dry_run=dry_run))
        except UnsafeArtifactPath as exc:
            raise UnsafeStoragePath("artifact retention path is unsafe") from exc
    return count
