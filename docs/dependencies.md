# Dependency policy

CodexNet targets CPython 3.11 through 3.13 on Debian Linux ARM64. Runtime code currently
uses only the Python standard library, so the initial appliance install has no third-party
runtime dependency or native-extension requirement.

Build and quality tools are exact-version constrained in `requirements-dev.lock`. The selected
Ruff, mypy, pytest, pytest-cov, coverage, and setuptools releases publish platform-independent
wheels or Linux AArch64 wheels and do not become appliance runtime dependencies. Before adding a
runtime library, record its purpose, constrain its supported version range, and verify that it
installs on Debian ARM64 without compiling an unreviewed native component.

Create a clean development environment and run all checks with:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --requirement requirements-dev.lock
.venv/bin/python -m ruff format --check .
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
.venv/bin/python -m pytest
```
