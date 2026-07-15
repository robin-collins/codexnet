"""Published technician handbook structure and CI/CD safety checks."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def _nav_paths(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [path for item in value for path in _nav_paths(item)]
    if isinstance(value, dict):
        return [path for item in value.values() for path in _nav_paths(item)]
    return []


def test_mkdocs_navigation_is_complete_and_confined() -> None:
    configuration = yaml.safe_load((ROOT / "mkdocs.yml").read_text())
    assert configuration["strict"] is True
    assert configuration["docs_dir"] == "handbook"
    assert configuration["site_dir"] == "site"
    assert configuration["theme"]["name"] == "material"
    assert configuration["theme"]["font"] is False

    paths = _nav_paths(configuration["nav"])
    assert len(paths) == len(set(paths)) == 14
    assert all(not Path(path).is_absolute() and ".." not in Path(path).parts for path in paths)
    assert all((ROOT / "handbook" / path).is_file() for path in paths)


def test_pages_workflow_builds_strictly_and_uses_immutable_actions() -> None:
    workflow = (ROOT / ".github/workflows/docs.yml").read_text()
    assert "mkdocs build --strict" in workflow
    assert "pages: write" in workflow and "id-token: write" in workflow
    assert "github-pages" in workflow

    action_references = re.findall(r"uses:\s+[^@\s]+@([^\s#]+)", workflow)
    assert len(action_references) == 5
    assert all(re.fullmatch(r"[0-9a-f]{40}", reference) for reference in action_references)


def test_documentation_dependency_is_exact_and_runtime_separate() -> None:
    requirements = [
        line
        for line in (ROOT / "requirements-docs.txt").read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert requirements == ["mkdocs-material==9.7.6"]
    lock = [
        line
        for line in (ROOT / "requirements-docs.lock").read_text().splitlines()
        if line and not line.startswith("#")
    ]
    assert "mkdocs-material==9.7.6" in lock
    assert "mkdocs==1.6.1" in lock
    assert all("==" in requirement for requirement in lock)
    assert "mkdocs" not in (ROOT / "requirements-dev.lock").read_text().casefold()


def test_published_handbook_contains_no_appliance_runtime_identity() -> None:
    published = "\n".join(path.read_text() for path in (ROOT / "handbook").rglob("*.md"))
    assert "10.10.10.4" not in published
    assert "ccb379db-6a47-4c98-90aa-7456b397ad74" not in published
    assert "/home/osit" not in published
