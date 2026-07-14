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

## Command-line shell

The installed command is `field-discovery`. It accepts a non-secret configuration path and can
emit either concise operator text or newline-delimited structured JSON:

```bash
field-discovery --config config/example.yaml config validate
field-discovery --json --config config/example.yaml config validate
```

Help and version output do not read configuration, require root, or contact the network. Commands
whose implementation belongs to later tasks are visible in help and exit explicitly with status 4.
Stable statuses are 0 (success), 2 (usage), 3 (invalid configuration), 4 (not implemented), 5
(subnet resolution failure), 6 (database operation failure), 7 (scan refused), and 70
(unexpected internal failure). An invoked scan otherwise propagates the protected script's status.

`discover subnet` reads the selected interface's Linux address and route state plus resolver
configuration. It reports the normalized IPv4 CIDR, gateway, DNS servers, DHCP/kernel metadata,
and whether that CIDR satisfies both the configured host limit and approved ranges. The command is
descriptive only: it never transmits traffic or starts an active scan.

```bash
field-discovery --config config/example.yaml discover subnet
field-discovery --json --config config/example.yaml discover subnet
```

`scan nmap` is never scheduled by CodexNet. It resolves and verifies the configured
interface/CIDR, requires interactive confirmation or `--yes`, holds a concurrent-run lock,
sets an outer timeout, records the run in SQLite, and propagates the protected script's exit
status. Use it only on an explicitly authorised network. The wrapper does not invoke `sudo`.

```bash
field-discovery --config /etc/field-discovery/config.yaml scan nmap --yes
```

Database integrity, backup, and retention operations use the configured CodexNet-owned data root.
Pruning is a dry-run unless `--apply` is explicitly supplied:

```bash
field-discovery --config /etc/field-discovery/config.yaml db check
field-discovery --config /etc/field-discovery/config.yaml db backup
field-discovery --config /etc/field-discovery/config.yaml db prune
```

## Safety

Use CodexNet only on networks for which you have explicit authorisation. Collectors are intended to be passive or read-only and must not expose customer credentials or data.
