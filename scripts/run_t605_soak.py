#!/usr/bin/env python3
"""Run the T605 synthetic accelerated soak and emit one JSON result."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from field_discovery.diagnostics import LocalDiagnosticProbe
from field_discovery.soak import run_accelerated_soak

ROOT = Path(__file__).parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--cycles-per-day", type=int, default=24)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument(
        "--skip-protected-probe",
        action="store_true",
        help="skip read-only local Scanopy/nmap comparison (tests only)",
    )
    arguments = parser.parse_args()
    temporary = None
    output_root = arguments.output_root
    if output_root is None:
        temporary = tempfile.TemporaryDirectory(prefix="codexnet-t605-")
        output_root = Path(temporary.name)
    probe = None if arguments.skip_protected_probe else LocalDiagnosticProbe().protected_state
    result = run_accelerated_soak(
        output_root,
        days=arguments.days,
        cycles_per_day=arguments.cycles_per_day,
        nmap_fixture=ROOT / "tests/fixtures/nmap/success.xml",
        passive_fixture=ROOT / "tests/fixtures/passive/link-layer.json",
        protected_probe=probe,
    )
    print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
    if temporary is not None:
        temporary.cleanup()
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
