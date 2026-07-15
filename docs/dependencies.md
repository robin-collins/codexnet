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

T403's live SSH boundary requires Netmiko 4.7.0 and NTC Templates 9.2.0; both are runtime-pinned
and publish platform-independent wheels. Netmiko uses Paramiko 4.0.0 for SSH and TextFSM 2.1.0
with NTC Templates for structured operational-command parsing. The lock also pins Paramiko's
ARM64-wheel dependencies (bcrypt 5.0.0 and PyNaCl 1.6.2) and Netmiko's pure-Python dependencies.
No compiler is required on supported Debian ARM64. The G4 transport test starts a synthetic SSH
device on an unprivileged loopback port and crosses the real Netmiko/Paramiko boundary; it never
contacts an external device.

The 2026-07-15 release audit found Paramiko 4.0.0 advisory `PYSEC-2026-2858` /
`CVE-2026-44405` concerning RSA/SHA-1. No fixed Paramiko release compatible with
Netmiko 4.7.0 was available in the audit data. CodexNet therefore keeps the
exact pin and passes Paramiko `disabled_algorithms` for both host and public
keys to refuse `ssh-rsa`, while retaining RSA-SHA2. A regression test enforces
that transport setting. Re-audit and move to a patched Paramiko/Netmiko pair as
soon as one is available; do not remove the mitigation to silence an audit.

Build and quality tools are exact-version constrained in `requirements-dev.lock`. The selected
Ruff, mypy, pytest, pytest-cov, coverage, and setuptools releases publish platform-independent
wheels or Linux AArch64 wheels and do not become appliance runtime dependencies. Before adding a
runtime library, record its purpose, constrain its supported version range, and verify that it
installs on Debian ARM64 without compiling an unreviewed native component.

Pytest was updated to 9.0.3 during T606 to resolve `PYSEC-2026-1845` found in the
previous 8.4.1 development-only pin.

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
