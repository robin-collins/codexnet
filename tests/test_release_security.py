"""Release-level security controls that span otherwise independent components."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

import pytest

from field_discovery.cli import build_parser
from packaging.requirements import Requirement

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    "candidate",
    (
        "customer.docx",
        "customer.pdf",
        "capture.pcap",
        "capture.pcapng",
        "capture.cap",
        "discovery.sqlite",
        "discovery.sqlite-wal",
        "discovery.bak",
        "discovery.backup",
    ),
)
def test_generated_sensitive_formats_are_ignored_everywhere(candidate: str) -> None:
    completed = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", candidate],
        cwd=ROOT,
        check=False,
    )
    assert completed.returncode == 0


def _all_options(parser: argparse.ArgumentParser) -> set[str]:
    values = {option for action in parser._actions for option in action.option_strings}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                values.update(_all_options(child))
    return values


def test_cli_has_no_secret_bearing_options() -> None:
    options = _all_options(build_parser())
    prohibited = re.compile(r"(?i)(password|passwd|community|token|api.?key|private.?key|secret)")
    assert not {option for option in options if prohibited.search(option)}


def test_dependency_lock_is_exact_and_has_no_offensive_packages() -> None:
    lines = [
        line.strip()
        for line in (ROOT / "requirements-dev.lock").read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#") and not line.startswith("-e ")
    ]
    assert lines
    requirements = [Requirement(line) for line in lines]
    assert all(
        len(requirement.specifier) == 1
        and next(iter(requirement.specifier)).operator == "=="
        and "*" not in next(iter(requirement.specifier)).version
        for requirement in requirements
    )
    normalized = "\n".join(lines).casefold()
    assert not any(
        name in normalized
        for name in ("impacket", "bloodhound", "secretsdump", "crackmapexec", "netexec")
    )


@pytest.mark.parametrize(
    "unit",
    sorted((ROOT / "packaging" / "systemd").glob("*.service")),
    ids=lambda path: path.name,
)
def test_services_are_unprivileged_confined_and_capability_minimal(unit: Path) -> None:
    text = unit.read_text()
    assert "User=field-discovery" in text
    assert "Group=field-discovery" in text
    assert "UMask=0077" in text
    assert "NoNewPrivileges=true" in text
    assert "ProtectSystem=strict" in text
    read_only_paths = {
        path
        for line in text.splitlines()
        if line.startswith("ReadOnlyPaths=")
        for path in line.removeprefix("ReadOnlyPaths=").split()
    }
    assert "/etc/field-discovery" in read_only_paths
    assert "ReadWritePaths=/var/lib/field-discovery" in text
    if unit.name == "field-discovery-passive.service":
        assert "CapabilityBoundingSet=CAP_NET_RAW" in text
        assert "AmbientCapabilities=CAP_NET_RAW" in text
    else:
        assert re.search(r"(?m)^CapabilityBoundingSet=$", text)
        assert re.search(r"(?m)^AmbientCapabilities=$", text)
