from __future__ import annotations

import base64
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

import pytest

from field_discovery.artifacts import (
    ArtifactError,
    ArtifactStore,
    ArtifactTooLarge,
    UnsafeArtifactPath,
    audit_outputs,
    safe_filename,
    validate_filename,
)
from field_discovery.redaction import REDACTED, Redactor


def _store(tmp_path: Path, *, secret: str = "synthetic-secret", limit: int = 4096) -> ArtifactStore:
    return ArtifactStore(tmp_path / "artifacts", redactor=Redactor([secret]), max_bytes=limit)


def test_text_artifact_is_restrictive_redacted_and_has_metadata(tmp_path: Path) -> None:
    secret = "synthetic-secret"
    store = _store(tmp_path, secret=secret)
    content = "\n".join(
        [
            f"password={secret}",
            "token=synthetic-token",
            "Cookie: session=synthetic-cookie",
            "Authorization: Bearer synthetic-auth",
            "snmp_community=synthetic-community",
            "https://operator:synthetic-url@example.invalid/api",
            base64.b64encode(secret.encode()).decode(),
            quote(secret, safe=""),
            secret.encode().hex(),
        ]
    )
    now = datetime(2026, 7, 15, tzinfo=UTC)
    metadata = store.write_text(
        "session.txt", content, category="ssh", retention=timedelta(hours=2), now=now
    )

    artifact = tmp_path / "artifacts" / "session.txt"
    rendered = artifact.read_text()
    for forbidden in (
        secret,
        "synthetic-token",
        "synthetic-cookie",
        "synthetic-auth",
        "synthetic-community",
        "synthetic-url",
    ):
        assert forbidden not in rendered
    assert REDACTED in rendered
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    assert stat.S_IMODE(artifact.parent.stat().st_mode) == 0o700
    assert metadata.size_bytes == len(rendered.encode())
    assert metadata.expires_at == "2026-07-15T02:00:00+00:00"
    sidecar = json.loads((artifact.with_name("session.txt.metadata.json")).read_text())
    assert sidecar["sha256"] == metadata.sha256
    assert sidecar["category"] == "ssh"


def test_json_artifact_is_structurally_redacted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.write_json(
        "export.json",
        {
            "password": "synthetic-password",
            "headers": {"Authorization": "Bearer synthetic-auth"},
            "safe": "visible",
        },
        category="export",
        retention=timedelta(days=1),
    )
    result = json.loads((store.root / "export.json").read_text())
    assert result == {
        "headers": {"Authorization": REDACTED},
        "password": REDACTED,
        "safe": "visible",
    }


@pytest.mark.parametrize(
    "name",
    ["../escape", "sub/file", "/absolute", ".hidden", "two words", "x" * 101, "a\\b"],
)
def test_filename_validation_rejects_traversal_and_nonportable_names(name: str) -> None:
    with pytest.raises(UnsafeArtifactPath):
        validate_filename(name)


def test_safe_filename_is_bounded_and_does_not_embed_registered_secret() -> None:
    redactor = Redactor(["Synthetic Customer Secret"])
    assert safe_filename("../../Synthetic Customer Secret", suffix=".json", redactor=redactor) == (
        "artifact.json"
    )
    assert safe_filename("  Example customer / Site A  ", suffix=".txt") == (
        "Example-customer-Site-A.txt"
    )
    with pytest.raises(UnsafeArtifactPath):
        safe_filename("example", suffix=".tar.gz")


def test_store_rejects_symlink_root_destination_and_oversize(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root_link = tmp_path / "root-link"
    root_link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafeArtifactPath):
        ArtifactStore(root_link)

    store = _store(tmp_path, limit=4)
    target = store.root / "linked.txt"
    target.symlink_to(tmp_path / "victim")
    with pytest.raises(FileExistsError):
        store.write_text("linked.txt", "safe", category="test", retention=timedelta(hours=1))
    assert target.is_symlink()
    assert not (store.root / "linked.txt.metadata.json").exists()
    with pytest.raises(ArtifactTooLarge, match="configured 4 byte limit"):
        store.write_text("large.txt", "12345", category="test", retention=timedelta(hours=1))
    assert not (store.root / "large.txt").exists()


def test_store_rejects_weak_existing_root_and_invalid_metadata_inputs(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="positive"):
        ArtifactStore(tmp_path / "invalid-limit", max_bytes=0)
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory")
    with pytest.raises(UnsafeArtifactPath, match="cannot be prepared"):
        ArtifactStore(blocked / "child")
    root = tmp_path / "weak"
    root.mkdir(mode=0o755)
    with pytest.raises(UnsafeArtifactPath, match="permissions"):
        ArtifactStore(root)
    store = _store(tmp_path)
    with pytest.raises(UnsafeArtifactPath, match="reserved"):
        store.write_text("bad.metadata.json", "safe", category="test", retention=timedelta(hours=1))
    with pytest.raises(ArtifactError, match="category"):
        store.write_text("bad.txt", "safe", category="Bad Category", retention=timedelta(hours=1))
    with pytest.raises(ArtifactError, match="retention"):
        store.write_text("bad.txt", "safe", category="test", retention=timedelta(0))
    with pytest.raises(TypeError):
        store.write_text(  # type: ignore[arg-type]
            "bad.txt", b"unsafe", category="test", retention=timedelta(hours=1)
        )


def test_existing_artifact_is_never_replaced(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.write_text("once.txt", "first", category="test", retention=timedelta(hours=1))
    with pytest.raises(FileExistsError):
        store.write_text("once.txt", "second", category="test", retention=timedelta(hours=1))
    assert (store.root / "once.txt").read_text() == "first"


def test_retention_hook_defaults_to_dry_run_and_refuses_symlinks(tmp_path: Path) -> None:
    store = _store(tmp_path)
    now = datetime(2026, 7, 15, tzinfo=UTC)
    store.write_text("expired.txt", "old", category="test", retention=timedelta(hours=1), now=now)
    store.write_text("current.txt", "new", category="test", retention=timedelta(days=2), now=now)
    cutoff = now + timedelta(days=1)
    assert [item.filename for item in store.prune_expired(now=cutoff)] == ["expired.txt"]
    assert (store.root / "expired.txt").exists()
    assert [item.filename for item in store.prune_expired(now=cutoff, dry_run=False)] == [
        "expired.txt"
    ]
    assert not (store.root / "expired.txt").exists()
    assert (store.root / "current.txt").exists()

    target = store.root / "current.txt"
    target.unlink()
    target.symlink_to(tmp_path / "victim")
    with pytest.raises(UnsafeArtifactPath, match="non-regular"):
        store.prune_expired(now=now + timedelta(days=3), dry_run=False)
    assert target.is_symlink()


def test_invalid_or_linked_metadata_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    metadata = store.root / "broken.txt.metadata.json"
    metadata.write_text("{}")
    os.chmod(metadata, 0o600)
    with pytest.raises(UnsafeArtifactPath, match="invalid"):
        store.expired(now=datetime.now(UTC))
    metadata.unlink()
    metadata.symlink_to(tmp_path / "missing")
    with pytest.raises(OSError):
        store.expired(now=datetime.now(UTC))


def test_oversized_and_mismatched_metadata_are_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    oversized = store.root / "large.txt.metadata.json"
    oversized.write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(UnsafeArtifactPath, match="bounded regular"):
        store.expired()
    oversized.unlink()

    mismatch = {
        "schema_version": 1,
        "filename": "other.txt",
        "category": "test",
        "media_type": "text/plain",
        "size_bytes": 0,
        "sha256": "0" * 64,
        "created_at": "2026-07-15T00:00:00+00:00",
        "expires_at": "2026-07-16T00:00:00+00:00",
    }
    (store.root / "wrong.txt.metadata.json").write_text(json.dumps(mismatch))
    with pytest.raises(UnsafeArtifactPath, match="mismatch"):
        store.expired()


def test_store_detects_root_replacement_before_publish(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = store.root
    root.rmdir()
    root.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(UnsafeArtifactPath, match="link-safe"):
        store.write_text("safe.txt", "safe", category="test", retention=timedelta(hours=1))


def test_audit_scans_logs_database_exports_and_artifacts(tmp_path: Path) -> None:
    secret = "synthetic-seeded-secret"
    redactor = Redactor([secret])
    logs = tmp_path / "logs"
    exports = tmp_path / "exports"
    artifacts = tmp_path / "artifacts"
    for directory in (logs, exports, artifacts):
        directory.mkdir()
    (logs / "clean.log").write_text(f"password={REDACTED}")
    (exports / "database.json").write_text(json.dumps({"safe": "visible"}))
    (artifacts / "clean.txt").write_text("safe")
    assert audit_outputs([logs, exports, artifacts], redactor=redactor) == []

    (logs / "leak.log").write_text(f"token={secret}")
    (exports / "leak.json").write_text(
        json.dumps({"connection": "https://user:uri-secret@example.invalid"})
    )
    (artifacts / "leak.txt").write_text(base64.b64encode(secret.encode()).decode())
    findings = audit_outputs([logs, exports, artifacts], redactor=redactor)
    assert {Path(item.path).name for item in findings} == {"leak.log", "leak.json", "leak.txt"}
    assert {item.reason for item in findings} == {"sensitive-pattern"}


def test_audit_flags_symlinks_and_oversized_files(tmp_path: Path) -> None:
    root = tmp_path / "outputs"
    root.mkdir()
    (root / "large.txt").write_text("12345")
    (root / "link.txt").symlink_to(root / "large.txt")
    (root / "nested").mkdir()
    root_link = tmp_path / "root-link"
    root_link.symlink_to(root, target_is_directory=True)
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("safe")
    findings = audit_outputs([root, root_link, clean_file], redactor=Redactor(), max_file_bytes=4)
    assert {(Path(item.path).name, item.reason) for item in findings} == {
        ("large.txt", "oversized"),
        ("link.txt", "symlink"),
        ("root-link", "symlink"),
    }
