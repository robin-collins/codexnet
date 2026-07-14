# Dependency policy

CodexNet targets CPython 3.11 through 3.13 on Debian Linux ARM64. PyYAML is the sole runtime
dependency at T003 and is used only through `safe_load` for the operator configuration. Its
pinned release supports these Python versions and has Linux AArch64 wheels as well as a pure
Python fallback; CodexNet does not require an unreviewed native extension to load configuration.

Build and quality tools are exact-version constrained in `requirements-dev.lock`. The selected
Ruff, mypy, pytest, pytest-cov, coverage, and setuptools releases publish platform-independent
wheels or Linux AArch64 wheels and do not become appliance runtime dependencies. Before adding a
runtime library, record its purpose, constrain its supported version range, and verify that it
installs on Debian ARM64 without compiling an unreviewed native component.

The lock currently provides exact version reproducibility but does not include distribution
hashes. When the dependency set grows or release artifacts are produced, generate and review a
platform-aware hash lock for stronger supply-chain verification while retaining ARM64 wheels.

Create a clean development environment and run all checks with:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --requirement requirements-dev.lock
.venv/bin/python -m ruff format --check .
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
.venv/bin/python -m pytest
```
