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
(subnet resolution failure), 6 (database operation failure), 7 (scan refused), 10 (collector
failure), 11 (operational diagnostics degraded), and 70
(unexpected internal failure). Status 8 reports a failed nmap import operation and status 9 a
report generation or validation failure. An invoked scan otherwise propagates the protected
script's status.

`discover subnet` reads the selected interface's Linux address and route state plus resolver
configuration. It reports the normalized IPv4 CIDR, gateway, DNS servers, DHCP/kernel metadata,
and whether that CIDR satisfies both the configured host limit and approved ranges. The command is
descriptive only: it never transmits traffic or starts an active scan.

```bash
field-discovery --config config/example.yaml discover subnet
field-discovery --json --config config/example.yaml discover subnet
```

`status` performs the fast local health checks; `doctor` adds dependency, systemd, clock, Scanopy,
and protected nmap coexistence checks. Both commands are strictly read-only, support stable JSON,
and return status 11 when an error is detected. Warnings remain visible without making the command
fail. See [docs/operational-diagnostics.md](docs/operational-diagnostics.md) for the schema, exact
checks, and interpretation guidance.

```bash
field-discovery --config /etc/field-discovery/config.yaml status
field-discovery --json --config /etc/field-discovery/config.yaml doctor
```

`import nmap` recursively reads stable, completed `.xml` artifacts from the configured
`paths.nmap_results` tree (or an explicit `--path`). It never writes to that source tree. Each
path/digest pair imports once, later scans remain historical observations, and incomplete files
are deferred for a later pass.

```bash
field-discovery --config /etc/field-discovery/config.yaml import nmap
```

`report generate` writes a paired, self-contained DOCX and deterministic JSON inventory under
the CodexNet data root. The report includes collection coverage, device and service inventories,
evidence source/age/confidence, conflicts, and explicit limitations. Mixed SNMP/SSH infrastructure
sections add switch-port, VLAN, neighbor, PoE, printer, UPS, environment, and firmware-version
inventory with per-field age/staleness and disclosed disagreements; see
[`docs/infrastructure-reporting.md`](docs/infrastructure-reporting.md). `report validate` audits
every package part for integrity, required sections/properties/images, broken or external
relationships, production filename shape, registered raw/encoded secrets, structural credential
fields, and prohibited content. Only a passing report is declared ready for manual upload.

```bash
field-discovery --config /etc/field-discovery/config.yaml report generate --format docx
field-discovery --config /etc/field-discovery/config.yaml report validate /path/to/report.docx
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

Collector lifecycle, target approval, bounded scheduling, cancellation, and durable run status are
documented in [docs/collector-framework.md](docs/collector-framework.md). Protocol-specific active
collectors remain disabled until their corresponding implementation task is complete.

SNMPv3-first collection supports bounded system, interface, IPv4 address, and LLDP profiles.
Legacy SNMPv2c requires an explicit insecure-protocol opt-in and produces a security notice. See
[docs/snmp-collection.md](docs/snmp-collection.md) for credential profiles and operation.

The default SNMP registry also normalizes bridge/neighbor tables, VLANs, PoE, physical sensors,
UPS state, printer counters and consumables, plus firmware version inventory. Native units,
unknown sentinels, source, and collection time are retained without making vulnerability claims.
See [docs/snmp-infrastructure.md](docs/snmp-infrastructure.md).

Configured UniFi OS and legacy controllers can be queried with `collect unifi`. Detection uses
existing evidence only, controller TLS verification is strict by default, and API reads are
bounded and allowlisted. Inventory, topology, firmware, alarms, events, stale-client state, and
per-resource coverage limitations are normalized into historical canonical records. See
[docs/unifi-collection.md](docs/unifi-collection.md).

Authorised Cisco IOS, HP/HPE Comware, and ArubaOS-Switch targets can be queried through the
read-only SSH adapter. The command requires both an approved IPv4 target and an explicit platform;
credentials are resolved only through the configured opaque reference and never accepted on the
command line:

```bash
field-discovery --config /etc/field-discovery/config.yaml collect ssh \
  --target 192.168.50.20 --platform cisco_ios
```

Every device command is checked against an exact platform allowlist, and bounded raw output is
redacted before retention. See [docs/ssh-collection.md](docs/ssh-collection.md).

Credential-free AD detection uses explicitly approved DNS domains, bounded AD SRV/A lookups,
existing service observations, and anonymous RootDSE base queries only to resolved IPv4 addresses
inside `active.approved_ranges`. It does not read or resolve any configured credential reference:

```bash
field-discovery --config /etc/field-discovery/config.yaml discover ad \
  --domain example.invalid --site Site-A
```

See [docs/ad-detection.md](docs/ad-detection.md) for the evidence and safety model.

Credential-gated AD documentation collection prefers Kerberos or verified LDAPS and queries only
fixed inventory attributes. It requires an approved target and the configured opaque credential
reference; documentation-group membership is opt-in by exact group name:

```bash
field-discovery --config /etc/field-discovery/config.yaml collect ad \
  --target 192.168.50.10 --server-name dc1.example.invalid
```

See [docs/ad-collection.md](docs/ad-collection.md) for credential profiles, paging, partial
coverage, and the prohibited-data boundary.
