# CodexNet

CodexNet is a portable, offline-first network discovery and documentation framework designed for an authorised Raspberry Pi field appliance.

The current build scope and acceptance criteria are defined in [SPEC.md](SPEC.md).

## Project status

Foundation implementation is in progress according to [TASKLIST.md](TASKLIST.md).

## Development

CodexNet supports Python 3.11 through 3.13. Create an isolated environment and install the exact
development tool set:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --requirement requirements-dev.lock
```

Run the standard local checks:

```bash
.venv/bin/python -m ruff format --check .
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
.venv/bin/python -m pytest
```

The test command includes branch coverage and currently requires 100% coverage. See
[docs/dependencies.md](docs/dependencies.md) for dependency and ARM64 compatibility policy.

## Safety

Use CodexNet only on networks for which you have explicit authorisation. Collectors are intended to be passive or read-only and must not expose customer credentials or data.
