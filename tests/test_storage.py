"""T603 disk reserve and confined filesystem retention tests."""

from __future__ import annotations

import os
from collections import namedtuple
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from field_discovery.artifacts import ArtifactStore
from field_discovery.storage import (
    BackupPruner,
    DiskGuard,
    LowDiskSpace,
    OwnedFile,
    UnsafeStoragePath,
    prune_artifact_tree,
)

Usage = namedtuple("Usage", "total used free")
NOW = datetime(2026, 7, 15, tzinfo=UTC)


def test_disk_guard_enforces_byte_percent_and_pending_reserves(tmp_path: Path) -> None:
    checked: list[Path] = []

    def usage(path: Path) -> Usage:
        checked.append(path)
        return Usage(1000, 800, 200)

    guard = DiskGuard(100, 10, usage)
    status = guard.check(tmp_path / "missing" / "output", 100)
    assert status.allowed and status.remaining_bytes == 100 and status.remaining_percent == 10
    assert status.as_dict()["minimum_free_bytes"] == 100
    assert checked == [tmp_path]
    with pytest.raises(LowDiskSpace, match="paused"):
        guard.check(tmp_path, 101)
    with pytest.raises(ValueError, match="must not be negative"):
        guard.inspect(tmp_path, -1)

    percent = DiskGuard(1, 11, usage).inspect(tmp_path, 100)
    assert not percent.allowed
    empty = DiskGuard(1, 1, lambda _path: Usage(0, 0, 0)).inspect(tmp_path)
    assert empty.remaining_percent == 0 and not empty.allowed


def test_disk_guard_loads_validated_shape() -> None:
    guard = DiskGuard.from_config(
        {"storage": {"minimum_free_bytes": 123, "minimum_free_percent": 7}}
    )
    assert (guard.minimum_free_bytes, guard.minimum_free_percent) == (123, 7)


def _backup(root: Path, name: str, *, age: timedelta) -> Path:
    path = root / name
    path.write_text("fixture")
    timestamp = (NOW - age).timestamp()
    os.utime(path, (timestamp, timestamp))
    return path


def test_backup_prune_preview_apply_parity_and_exact_scope(tmp_path: Path) -> None:
    old = _backup(tmp_path, "discovery-backup-20260701T000000Z.db", age=timedelta(days=14))
    current = _backup(tmp_path, "discovery-backup-20260715T000000Z.db", age=timedelta())
    unrelated = _backup(tmp_path, "customer.db", age=timedelta(days=30))
    pruner = BackupPruner(tmp_path)
    plan = pruner.plan(before=NOW - timedelta(days=7))
    assert [item.name for item in plan] == [old.name]
    assert old.exists()
    assert pruner.apply(plan) == plan
    assert not old.exists() and current.exists() and unrelated.exists()


def test_backup_prune_rejects_links_changed_plans_and_bad_roots(tmp_path: Path) -> None:
    old = _backup(tmp_path, "discovery-backup-20260701T000000Z.db", age=timedelta(days=14))
    pruner = BackupPruner(tmp_path)
    plan = pruner.plan(before=NOW)
    old.write_text("changed")
    with pytest.raises(UnsafeStoragePath, match="changed"):
        pruner.apply(plan)
    with pytest.raises(UnsafeStoragePath, match="invalid name"):
        pruner.apply((OwnedFile("other.db", 0, 0, 0, 0),))

    old.unlink()
    old.symlink_to(tmp_path / "victim")
    with pytest.raises(UnsafeStoragePath, match="non-regular"):
        pruner.plan(before=NOW)

    missing = tmp_path / "missing"
    with pytest.raises(UnsafeStoragePath, match="unavailable"):
        BackupPruner(missing).plan(before=NOW)
    file_root = tmp_path / "file-root"
    file_root.write_text("fixture")
    with pytest.raises(UnsafeStoragePath, match="real directory"):
        BackupPruner(file_root).plan(before=NOW)
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(UnsafeStoragePath, match="real directory"):
        BackupPruner(linked_root).plan(before=NOW)


def test_backup_prune_classifies_root_open_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "field_discovery.storage.os.open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("fixture")),
    )
    with pytest.raises(UnsafeStoragePath, match="link-safe"):
        BackupPruner(tmp_path).plan(before=NOW)


def test_artifact_tree_prune_is_link_safe_and_matches_preview(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    category = root / "ssh"
    category.mkdir(parents=True, mode=0o700)
    store = ArtifactStore(category)
    store.write_text("old.txt", "old", category="ssh", retention=timedelta(days=1), now=NOW)
    store.write_text("current.txt", "new", category="ssh", retention=timedelta(days=10), now=NOW)
    cutoff = NOW + timedelta(days=2)
    assert prune_artifact_tree(root, now=cutoff, dry_run=True) == 1
    assert (category / "old.txt").exists()
    assert prune_artifact_tree(root, now=cutoff, dry_run=False) == 1
    assert not (category / "old.txt").exists() and (category / "current.txt").exists()
    assert prune_artifact_tree(tmp_path / "absent", now=cutoff, dry_run=True) == 0

    linked = root / "linked"
    linked.symlink_to(category, target_is_directory=True)
    with pytest.raises(UnsafeStoragePath, match="unexpected"):
        prune_artifact_tree(root, now=cutoff, dry_run=True)
    linked.unlink()
    root_file = tmp_path / "artifact-file"
    root_file.write_text("fixture")
    with pytest.raises(UnsafeStoragePath, match="real directory"):
        prune_artifact_tree(root_file, now=cutoff, dry_run=True)

    weak_root = tmp_path / "weak-artifacts"
    weak_category = weak_root / "ssh"
    weak_category.mkdir(parents=True, mode=0o755)
    with pytest.raises(UnsafeStoragePath, match="unsafe"):
        prune_artifact_tree(weak_root, now=cutoff, dry_run=True)
