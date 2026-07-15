"""Operator runbook completeness, safety, links, and staged packaging tests."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
RUNBOOKS = (
    ROOT / "docs" / "installation.md",
    ROOT / "docs" / "operator-guide.md",
)
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")


@pytest.mark.parametrize("document", (ROOT / "README.md", *RUNBOOKS))
def test_operator_documentation_local_links_resolve(document: Path) -> None:
    for target in MARKDOWN_LINK.findall(document.read_text()):
        destination = target.split("#", maxsplit=1)[0]
        if not destination or "://" in destination:
            continue
        assert (document.parent / destination).resolve().is_file(), target


def test_operator_runbooks_cover_required_workflows_and_avoid_unsafe_advice() -> None:
    combined = "\n".join(path.read_text() for path in RUNBOOKS)
    required = (
        "requirements-dev.lock",
        "config validate",
        "discover subnet",
        "collect snmp",
        "collect unifi",
        "collect ad",
        "collect ssh",
        "scan nmap",
        "report generate",
        "report validate",
        "IT Glue",
        "Datto RMM",
        "Autotask",
        "db backup",
        "db restore",
        "db prune",
        "doctor",
        "remove-codexnet-services.sh",
        "retention",
        "Scanopy",
    )
    assert all(value in combined for value in required)
    forbidden = (
        "chmod 777",
        "StrictHostKeyChecking=no",
        "--password",
        "--community",
        "curl |",
        "wget |",
        "sudo field-discovery --config",
        "sudo field-discovery scan",
    )
    assert all(value not in combined for value in forbidden)


def _run_installer(script: str, destination: Path) -> None:
    subprocess.run(
        [str(ROOT / "packaging" / "install" / script), str(ROOT)],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "DESTDIR": str(destination)},
    )


def test_complete_staged_service_install_and_remove_preserves_protected_state(
    tmp_path: Path,
) -> None:
    _run_installer("install-passive-service.sh", tmp_path)
    _run_installer("install-scheduler-service.sh", tmp_path)
    _run_installer("install-nmap-import-service.sh", tmp_path)
    _run_installer("install-maintenance-services.sh", tmp_path)

    unit_root = tmp_path / "usr" / "lib" / "systemd" / "system"
    installed = {path.name for path in unit_root.iterdir()}
    assert installed == {
        "field-discovery-backup.service",
        "field-discovery-backup.timer",
        "field-discovery-nmap-import.service",
        "field-discovery-nmap-import.timer",
        "field-discovery-passive.service",
        "field-discovery-scheduler.service",
        "field-discovery-recovery.service",
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o644 for path in unit_root.iterdir())

    protected = {
        tmp_path / "usr" / "local" / "sbin" / "network-discovery-scan.sh": b"scan\n",
        tmp_path / "etc" / "crontab": b"protected schedule\n",
        tmp_path / "var" / "log" / "network-discovery" / "result.xml": b"<nmaprun/>\n",
        tmp_path / "var" / "lib" / "scanopy" / "sentinel": b"scanopy\n",
    }
    for path, payload in protected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    _run_installer("remove-codexnet-services.sh", tmp_path)
    assert not any(unit_root.glob("field-discovery-*"))
    assert all(path.read_bytes() == payload for path, payload in protected.items())
