# Dependency policy

CodexNet targets CPython 3.11 through 3.13 on Debian Linux ARM64. PyYAML is used only through
`safe_load` for operator configuration. Its pinned release supports these Python versions and has
Linux AArch64 wheels as well as a pure Python fallback.

T401 adds PySNMP 7.1.27 and its PyASN1 0.6.4 dependency for asynchronous SNMPv3 and explicitly
enabled SNMPv2c transport. Both are pinned, pure-Python `py3-none-any` wheels compatible with the
supported CPython and Debian ARM64 targets. Cryptography 49.0.0 is pinned for SNMPv3 AES privacy and
publishes CPython manylinux ARM64 wheels; installation must use a wheel rather than compiling Rust
on the appliance. CodexNet uses numeric OIDs and does not add dynamic MIB compilers.

T502 adds dnspython 2.8.0 for bounded SRV/A resolution and stable ldap3 2.9.1 for anonymous,
base-scope RootDSE reads. Both publish platform-independent `py3-none-any` wheels and require no
native compilation on Debian ARM64. ldap3 reuses the already pinned PyASN1 dependency. Detection
constructs no authenticated LDAP connection; credential-gated collection belongs to T503.

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
