# CodexNet 0.1.0

CodexNet 0.1.0 is the first release of the offline-first Raspberry Pi network discovery and
documentation appliance defined in `SPEC.md`. It installs on Debian ARM64, coexists with Scanopy
and the protected external nmap workflow, retains observations in provenance-aware SQLite, and
produces self-contained Word reports for manual upload to IT Glue, Datto RMM, or Autotask.

## Included

- Continuous bounded passive LLDP/CDP, mDNS, DHCP, ARP, and kernel-neighbour observation.
- Idempotent, external-entity-safe import of stable nmap XML without scheduling or invoking nmap;
  the canonical identifier-free nmap doctype is supported.
- Explicit operator-confirmed invocation of the protected nmap script with interface/range guards.
- Scheduled and one-shot read-only SNMPv3/v2c, UniFi, Active Directory, and Cisco/HP/Aruba SSH
  collection with concrete target approval, timeouts, retries, concurrency limits, and isolation.
- Deterministic normalization, history, correlation, topology, infrastructure, UniFi, and AD models.
- Production DOCX generation with embedded diagrams, upload-readiness validation, JSON companion
  output, centralized redaction, and no framework-controlled external upload.
- Hardened unprivileged systemd services, diagnostics, verified backup/restore, retention pruning,
  interrupted-run recovery, low-disk safeguards, and documented install/upgrade/removal workflows.

## Safety defaults

All credentialed collectors are disabled by default. Scheduled collection needs both an explicitly
approved private IPv4 range and concrete per-host configuration. SNMPv3, verified HTTPS,
LDAPS/Kerberos, and strict SSH host keys are the defaults. SNMPv2c, plaintext LDAP, and a
self-signed UniFi exception require explicit scoped opt-in. Active nmap remains an operator action;
CodexNet supplies no active-scan timer. Reports are uploaded manually.

The appliance owner's approved producer-side integration exposes only completed XML to the fixed
`field-discovery` group after a successful external scan. Scan logs and all non-XML output remain
root-only; no scan target, option, or schedule is changed.

## Installation and upgrades

Follow [`docs/installation.md`](docs/installation.md) from an exact `v0.1.0` checkout. Runtime data
uses forward-only numbered migrations. Before upgrading, create and verify a database backup and
retain the previous application tree. Rollback restores the previous tree and a verified backup to
a new database path; never downgrade a migrated live database in place. Removal preserves Scanopy,
the nmap script/result tree, cron, customer data, configuration, credentials, reports, and backups.

## Known lower risks

- Paramiko 4.0.0 remains affected by `PYSEC-2026-2858` / `CVE-2026-44405`; no compatible fixed
  release was available. CodexNet disables `ssh-rsa` host/public-key algorithms and the dependency
  must be re-audited on each update.
- The exact dependency lock pins every version but does not yet include distribution hashes.
- Microsoft Word was not available on this ARM64 appliance. The release passes semantic OPC/DOCX
  validation plus real LibreOffice headless open, PDF render, resave, and reopen checks.

No unresolved critical or high security issue is accepted for this release.
