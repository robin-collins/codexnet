# CodexNet Delivery Task List

This is the execution plan for [SPEC.md](SPEC.md). `SPEC.md` defines what CodexNet must do; this file defines build order, dependencies, and evidence required to advance.

## Status and dependency rules

- Status markers: `[ ]` not started, `[~]` in progress, `[x]` verified, `[!]` blocked.
- A task may start only after every task in its **Depends on** field is `[x]`.
- A stage is complete only when all of its tasks and its stage gate are `[x]`.
- Every completed task must leave reproducible evidence: tests, command output, a fixture, or a short record in the pull request/commit message.
- Tests must use local fixtures or explicitly approved targets. Never test by scanning an arbitrary live network.
- Any change that touches credentials, packet capture, active scanning, system privileges, report redaction, or customer data requires the security checks specified for that task.

## Dependency map

```text
S0 Scope/baseline
 └─ S1 Foundation and data model
     ├─ S2 Nmap import and first DOCX report
     │   └─ S3 Passive discovery and topology
     ├─ S4 SNMP and network-device SSH collectors
     └─ S5 UniFi and Active Directory collectors
          \        |        /
           S6 Reporting, operations, and release hardening
```

Cross-stage details are expressed by task IDs below. The diagram shows the primary critical path, not permission to skip individual dependencies.

## Stage 0 — Scope, baseline, and design controls

### [x] T000 Record the appliance baseline

- **Depends on:** none
- **Deliver:** `docs/baseline.md` documenting OS/architecture, Python, installed tools, selected interface, existing Scanopy containers/services, existing nmap script checksum/path, cron entry, and current resource/disk use. Do not record credentials or customer identifiers.
- **Verify:** baseline commands are documented and repeatable; the nmap cron and Scanopy state are captured without modification.
- **Balance:** compare Scanopy and cron state again at every later stage gate.

### [x] T001 Establish repository quality tooling

- **Depends on:** none
- **Deliver:** Python project metadata, `src/` layout, `tests/`, Ruff, mypy, pytest, coverage configuration, and pinned/locked runtime dependencies suitable for ARM64.
- **Verify:** clean-environment install succeeds; format, lint, type-check, and empty smoke test commands pass.
- **Balance:** dependencies must be justified, version constrained, and checked for ARM64 availability before adoption.

### [x] T002 Write architecture and threat model

- **Depends on:** T000
- **Deliver:** `docs/architecture.md` and `docs/threat-model.md` covering trust boundaries, privilege separation, data flows, credential paths, active-scan controls, retention, and failure isolation.
- **Verify:** every component in `SPEC.md` maps to an architecture component; every secret and customer-data flow has a storage, access, logging, and deletion rule.
- **Balance:** explicitly confirm no offensive AD functions, default credentials, unrestricted packet retention, cloud upload, or direct Scanopy database access.

### [x] T003 Define configuration and secret contracts

- **Depends on:** T002
- **Deliver:** versioned non-secret YAML schema, example configuration, secret-reference model, validation rules, safe defaults, and redaction contract.
- **Verify:** valid examples load; unknown keys, unsafe target ranges, inline secrets, invalid intervals, and insecure protocol choices fail with actionable errors.
- **Balance:** secrets never appear in CLI arguments, serialized config, SQLite, logs, exceptions, or test snapshots.

### [x] G0 Stage 0 gate

- **Depends on:** T000, T001, T002, T003
- **Verify:** project checks pass; architecture traces to the specification; baseline proves no appliance services were changed; threat-model review has no unresolved critical issue.
- **Evidence:** committed baseline/design documents and recorded check output.

## Stage 1 — Application foundation and normalized storage

### [x] T100 Build the application shell and CLI

- **Depends on:** G0
- **Deliver:** installable `field-discovery` package with structured logging, stable exit codes, human/JSON output modes, config loading, and placeholder command groups matching `SPEC.md`.
- **Verify:** CLI help and version work without root or network; invalid configuration returns nonzero; logs contain timestamps/run IDs and no ANSI codes in JSON mode.
- **Balance:** importing the package must cause no network, filesystem, or privilege side effects.

### [x] T101 Implement the SQLite schema and migrations

- **Depends on:** T003, T100
- **Deliver:** normalized schema for deployments, devices, aliases, interfaces, addresses, services, observations, topology, collector runs/errors, artifacts, AD entities, infrastructure readings, and reports; numbered migrations; foreign keys and WAL mode.
- **Verify:** migrate empty database to latest; rerun safely; foreign-key check and `PRAGMA integrity_check` pass; migration rollback/recovery procedure is documented.
- **Balance:** fixture scan confirms no column stores secrets; every observed fact includes source and time provenance.

### [x] T102 Implement repository operations and retention

- **Depends on:** T101
- **Deliver:** transactional CRUD/upsert layer, artifact digest tracking, run lifecycle, backup, integrity check, retention pruning, and sanitized JSON export.
- **Verify:** duplicate writes are idempotent; interrupted runs remain visibly incomplete; backup restores to a valid database; pruning respects each retention class.
- **Balance:** destructive maintenance supports dry-run and refuses to act outside configured data directories.

### [x] T103 Implement deterministic normalization and correlation

- **Depends on:** T101
- **Deliver:** canonical models and explainable correlation across MAC, IP, hostname, serial, and source IDs, including conflict handling and confidence.
- **Verify:** table-driven tests cover DHCP address reuse, hostname reuse, multiple interfaces, changing IPs, conflicting serials, and source disagreement.
- **Balance:** hostname or IP alone must never cause an irreversible device merge; merge decisions retain evidence and can be audited.

### [x] T104 Implement interface and subnet resolution

- **Depends on:** T100
- **Deliver:** configurable interface selection, IPv4 CIDR normalization, gateway/DNS metadata, excluded-interface rules, maximum-range safeguards, and `discover subnet` output.
- **Verify:** fixtures cover `/24`, `/23`, multiple addresses, no address, Docker/Tailscale interfaces, and unsafe broad prefixes; selected target matches the kernel route/address data.
- **Balance:** resolver only describes targets; it never initiates scanning.

### [x] T105 Implement redaction and safe artifact handling

- **Depends on:** T003, T100
- **Deliver:** centralized redaction filter, restrictive file creation, safe filenames/paths, artifact metadata, size limits, and retention hooks.
- **Verify:** tests cover passwords, tokens, cookies, auth headers, SNMP communities, connection URLs, encoded variants, traversal attempts, symlinks, and oversized artifacts.
- **Balance:** run automated secret-pattern scans against test logs, database exports, and generated artifacts.

### [x] G1 Stage 1 gate

- **Depends on:** T100, T102, T103, T104, T105
- **Verify:** all static/unit checks pass; schema integrity and backup/restore pass; redaction corpus passes; CLI operates offline and unprivileged.
- **Evidence:** test report, coverage report, sample sanitized JSON, and database integrity output.

## Stage 2 — Existing nmap integration and minimum useful report

### [x] T200 Build the nmap XML parser

- **Depends on:** G1
- **Deliver:** streaming parser for scan metadata, host state, IP/MAC/vendor, hostnames, OS guesses, ports, services, versions, and NSE results.
- **Verify:** sanitized fixtures cover successful, partial, malformed, large, IPv4-only, missing-field, TCP, and UDP scans; malformed input fails without partial uncommitted data.
- **Balance:** XML parsing disables external entities and network resolution.

### [x] T201 Build idempotent nmap artifact import

- **Depends on:** T102, T103, T200
- **Deliver:** configurable recursive discovery under `/var/log/network-discovery`, stable-file detection, digest/path tracking, transactional import, and `import nmap`.
- **Verify:** the same file imports once; a later distinct scan creates new observations; incomplete files defer safely; permission errors affect only that artifact.
- **Balance:** importer is read-only toward the existing result tree and does not change its retention or cron schedule.

### [x] T202 Add explicit existing-script invocation

- **Depends on:** T104, T105
- **Deliver:** `scan nmap` wrapper for `/usr/local/sbin/network-discovery-scan.sh` with operator confirmation/explicit flag, approved interface context, timeout, exit propagation, and run audit record.
- **Verify:** mock script tests cover success, failure, timeout, missing script, and concurrent invocation lock.
- **Balance:** no automatic scheduler invokes this command; the existing root cron remains the only scheduled active scanner.

### [x] T203 Generate the minimum DOCX/JSON inventory report

- **Depends on:** T102, T103, T201
- **Deliver:** deterministic JSON report model and basic `.docx` containing metadata, coverage, device inventory, services, evidence age, conflicts, and limitations.
- **Verify:** DOCX ZIP structure validates, opens in LibreOffice headless validation where available, contains no external relationships, and matches snapshot/semantic tests.
- **Balance:** secret-pattern scan passes for DOCX XML, JSON, filenames, properties, and embedded metadata.

### [x] T204 Add nmap import monitoring

- **Depends on:** T201
- **Deliver:** non-conflicting path/timer mechanism that imports completed artifacts and optionally refreshes reports without launching nmap.
- **Verify:** new completed XML is imported once; partial files wait; restart catches missed files; failures retry with rate limits.
- **Balance:** verify the original nmap cron text/checksum and Scanopy health are unchanged.

### [x] G2 Stage 2 gate

- **Depends on:** T202, T203, T204
- **Verify:** sanitized real-world nmap fixture imports twice idempotently; inventory is correct; DOCX validates; importer survives restart; existing Scanopy and cron baseline comparison passes.
- **Evidence:** import summary, database queries, report artifact/checksum, service logs, and baseline diff.

## Stage 3 — Passive discovery and topology

### [x] T300 Implement passive-event ingestion framework

- **Depends on:** G2
- **Deliver:** bounded asynchronous event pipeline, parser isolation, timestamps, deduplication, backpressure, metrics, and graceful shutdown.
- **Verify:** replayed event load remains within configured memory; malformed frames cannot stop the service; shutdown drains or marks incomplete work.
- **Balance:** no full packet payload is retained by default.

### [x] T301 Add LLDP and CDP observation

- **Depends on:** T300
- **Deliver:** LLDP/CDP parsing for identity, ports, capabilities, management address, VLAN, and TTL using fixtures and/or `lldpd` structured output.
- **Verify:** Cisco, Aruba/HP, generic LLDP, unknown TLV, truncated frame, and expiry fixtures normalize correctly.
- **Balance:** observer sends no discovery requests unless an explicitly documented protocol requirement is approved.

### [x] T302 Add mDNS/DNS-SD observation

- **Depends on:** T300
- **Deliver:** service/instance/hostname/address/TXT observations with bounded TXT handling and expiration.
- **Verify:** IPv4 fixtures, duplicate announcements, goodbye records, malformed names, oversized TXT, and cache expiry pass.
- **Balance:** sensitive TXT fields are redacted before persistence.

### [x] T303 Add DHCP observation

- **Depends on:** T300
- **Deliver:** server/offers/ACK observations for visible server/client identity, address, lease, hostname, vendor class, router, DNS, and domain options.
- **Verify:** DORA sequence, multiple servers, renewals, malformed options, and DHCP address reuse fixtures pass.
- **Balance:** service never acts as a DHCP client/server and stores no unrestricted payloads.

### [x] T304 Add ARP and neighbor observation

- **Depends on:** T300
- **Deliver:** ARP event and kernel neighbor-table ingestion with state, first/last seen, deduplication, and aging.
- **Verify:** MAC movement, IP reuse, incomplete neighbor, duplicate event, and expiry tests pass without incorrect device merges.
- **Balance:** passive service does not perform unsolicited ARP sweeps.

### [x] T305 Build topology inference and diagrams

- **Depends on:** T103, T301, T302, T303, T304
- **Deliver:** provenance/confidence-aware edges, VLAN/subnet relationships, Mermaid/Graphviz source, and rendered diagrams.
- **Verify:** fixture topology produces expected nodes/edges; conflicting sources remain visible; deterministic output hash is stable; unknown links are not presented as facts.
- **Balance:** every inferred edge in the report identifies its evidence source and confidence.

### [x] T306 Package the passive system service

- **Depends on:** T105, T300, T301, T302, T303, T304
- **Deliver:** dedicated service account, minimum packet-capture capability, systemd unit, restart limits, resource limits, journald logging, and uninstall/rollback steps.
- **Verify:** runs without root, starts after networking, recovers from failure, respects memory/CPU limits, and cannot write outside approved paths.
- **Balance:** review effective systemd sandbox and Linux capabilities; no broad `sudo` or privileged container.

### [x] G3 Stage 3 gate

- **Depends on:** T305, T306
- **Verify:** controlled fixture/replay and approved lab capture enrich inventory/topology for 24 hours without leak, crash, unbounded growth, or full-packet retention; reboot recovery passes.
- **Evidence:** resource graph, event counts, expiry results, diagram, redaction scan, and systemd security output.

## Stage 4 — SNMP and network-device SSH collection

### [x] T400 Build the collector framework and scheduler

- **Depends on:** G1
- **Deliver:** independent collector lifecycle, target approval, credential references, bounded concurrency, jitter, timeouts/retries, run status, cancellation, and failure isolation.
- **Verify:** fake collectors demonstrate success, timeout, auth failure, partial data, cancellation, and one collector failing while others complete.
- **Balance:** scheduler refuses targets outside configured ranges and never logs credential values.

### [x] T401 Implement SNMP transport and profiles

- **Depends on:** T105, T400
- **Deliver:** SNMPv3 preferred and explicit v2c support, base system/interface/address/LLDP data, profile/OID registry, raw unknown OID handling, and `collect snmp`.
- **Verify:** mocked v3/v2c, timeout, auth failure, unsupported OID, large table, and partial-response tests pass.
- **Balance:** no default/guessed communities; v2c requires explicit opt-in and generates a security notice.

### [x] T402 Add infrastructure SNMP domains

- **Depends on:** T401
- **Deliver:** bridge MAC, ARP/neighbor, VLAN, PoE, environment, UPS, and printer consumable/page-count normalization.
- **Verify:** sanitized vendor fixtures map correctly, preserve units/time, and tolerate missing/unknown values.
- **Balance:** values include collection time and source; firmware audit reports versions only, not unsupported vulnerability claims.

### [x] T403 Implement Cisco/HP/Aruba SSH collection

- **Depends on:** T105, T400
- **Deliver:** conservative platform selection, Netmiko/TextFSM adapters, approved read-only command sets, sanitized raw artifacts, and `collect ssh`.
- **Verify:** fixture/session tests cover each vendor family, unknown platform, command rejection, paging, timeout, auth failure, parse fallback, and partial output.
- **Balance:** command allowlist blocks configuration mode and write commands; credentials are not passed as command-line arguments.

### [x] T404 Add switch-port maps and infrastructure report sections

- **Depends on:** T305, T402, T403
- **Deliver:** correlated switch interfaces, VLANs, neighbors, learned MACs, PoE, printer/UPS/environment inventory, and firmware-version sections.
- **Verify:** mixed SNMP/SSH fixture yields expected port map and conflicts are disclosed rather than silently overwritten.
- **Balance:** each field exposes source and age; stale data is marked.

### [x] G4 Stage 4 gate

- **Depends on:** T404
- **Verify:** collectors pass mock/fixture tests and an explicitly approved lab-device test; failure isolation, target restriction, command allowlist, redaction, and DOCX sections pass.
- **Evidence:** collector run summaries, allowlist test, secret scan, fixture coverage matrix, and report sample.

## Stage 5 — UniFi and Active Directory collection

### [x] T500 Implement UniFi detection and API client

- **Depends on:** T105, T400
- **Deliver:** conservative discovery candidates, configured UniFi OS/legacy endpoints, TLS verification by default, read-only client behavior, bounded pagination, and `collect unifi`.
- **Verify:** mocked modern/legacy login, self-signed opt-in, invalid certificate, MFA/unsupported auth, pagination, timeout, and authorization failure tests pass.
- **Balance:** never probe credentials automatically; never disable TLS verification globally; redact cookies/tokens and response secrets.

### [x] T501 Normalize UniFi inventory and topology

- **Depends on:** T103, T500
- **Deliver:** sites, gateways, switches, APs, clients, networks/VLANs, WLANs, profiles, ports, neighbors, firmware, alarms, and events mapped to canonical records.
- **Verify:** controller IDs correlate without duplicate devices; disconnected/stale clients and cross-site IDs are handled correctly.
- **Balance:** collection permissions and omitted endpoints are reported as coverage limitations.

### [x] T502 Implement safe AD detection

- **Depends on:** T104, T400
- **Deliver:** DNS SRV, existing service evidence, and RootDSE detection limited to approved domain/targets; no credential use during detection.
- **Verify:** fixtures cover AD/non-AD DNS, multiple domains/DCs, unreachable targets, malformed records, and site-specific SRV results.
- **Balance:** detection does not invoke offensive Impacket/BloodHound functions or attempt usernames/passwords.

### [x] T503 Implement credential-gated AD collection

- **Depends on:** T105, T502
- **Deliver:** Kerberos/LDAPS-preferred LDAP client for forest/domain, sites/subnets, DCs, computers, documentation groups/memberships, OUs, trusts, and relevant roles; `collect ad`.
- **Verify:** mocked Kerberos, LDAPS, expired credential, insufficient access, referral, paging, large group, and partial-directory tests pass.
- **Balance:** plaintext LDAP requires explicit opt-in; deny/filter password, hash, ticket, secret, and attack-path attributes; no offensive collection dependencies.

### [x] T504 Build AD and UniFi report enrichment

- **Depends on:** T305, T501, T503
- **Deliver:** UniFi-enriched topology and AD domain/site/subnet/DC/trust diagrams with coverage and permissions notes.
- **Verify:** expected fixture graphs and DOCX sections are deterministic, readable, source-labelled, and omit forbidden attributes.
- **Balance:** redaction and prohibited-content scans pass against raw artifacts, SQLite, JSON, diagrams, and DOCX XML.

### [x] G5 Stage 5 gate

- **Depends on:** T504
- **Verify:** mock/fixture suites pass; explicitly approved lab tests use read-only accounts; TLS, credential, redaction, target-scope, and prohibited-AD-function reviews pass.
- **Evidence:** coverage matrices, collection summaries, security scan, diagrams, and report sample.

## Stage 6 — Production reporting, operations, and release

### [x] T600 Build the production Word report renderer

- **Depends on:** G3, G4, G5
- **Deliver:** configurable `.docx` template, title/metadata, TOC fields, numbered headings, headers/footers, page numbers, repeatable table headers, landscape sections, embedded diagrams, stable filename, and all required report sections.
- **Verify:** semantic DOCX tests plus rendering/open checks in current Word when available and LibreOffice; wide/empty/large datasets render correctly; no external relationships.
- **Balance:** generated document is self-contained and customer metadata is explicitly supplied, never inferred from secrets.

### [x] T601 Implement report validation and final redaction audit

- **Depends on:** T105, T600
- **Deliver:** `report validate` checking ZIP/XML integrity, required sections/properties, broken relationships, external resources, missing images, filename, and secret/prohibited-content patterns.
- **Verify:** valid report passes; deliberately corrupted, externally linked, missing-image, and secret-seeded reports fail clearly.
- **Balance:** validation occurs before a report is declared ready for manual IT Glue/Datto RMM/Autotask upload.

### [x] T602 Complete operational status and diagnostics

- **Depends on:** T204, T306, T400
- **Deliver:** `status` and `doctor` for dependencies, permissions, paths, interface/CIDR, database, disk, clock, services, collector success/failure/age/counts, and Scanopy/nmap coexistence.
- **Verify:** injected failures are detected with actionable messages and stable exit codes; JSON output schema is tested.
- **Balance:** diagnostics expose no secret values and perform no active collection unless explicitly requested.

### [ ] T603 Implement disk, backup, and recovery safeguards

- **Depends on:** T102, T602
- **Deliver:** disk thresholds, artifact-heavy work pause, scheduled backup, restore procedure, pruning, interrupted-run recovery, and uninstall/rollback documentation.
- **Verify:** low-disk simulation pauses safely; backup/restore and reboot tests pass; prune dry-run matches applied result; uninstall leaves Scanopy/nmap untouched.
- **Balance:** deletion is constrained to owned paths and requires path/symlink checks.

### [ ] T604 Produce installation and operator documentation

- **Depends on:** T601, T602, T603
- **Deliver:** repeatable Pi install/upgrade/remove, config and credential profiles, normal operation, manual scan warning, collector setup, report generation/upload, backup/restore, troubleshooting, and data-retention guidance.
- **Verify:** fresh-system walkthrough by a second operator or clean test environment succeeds using only documented steps.
- **Balance:** examples use placeholders/sanitized data and never recommend broad privileges or insecure defaults.

### [ ] T605 Run performance, soak, and failure testing

- **Depends on:** T601, T602, T603
- **Deliver:** representative multi-day replay/soak, resource measurements alongside Scanopy, collector outage/recovery tests, database growth projection, and report timing/size results.
- **Verify:** stays within documented CPU/memory/disk budgets; no unbounded queues/logs/artifacts; restart/reboot recovery and individual collector isolation pass.
- **Balance:** compare Scanopy availability and existing nmap cron/checksum to T000 baseline.

### [ ] T606 Complete security and privacy release review

- **Depends on:** T601, T603, T605
- **Deliver:** dependency audit, filesystem-permission review, systemd sandbox review, capability review, secret scan, prohibited-AD-feature scan, target-control test, TLS review, and customer-data inventory/deletion verification.
- **Verify:** no unresolved critical/high issue; accepted lower risks are documented with owner and rationale.
- **Balance:** review raw artifacts, SQLite, logs, JSON, diagrams, DOCX internals, process arguments, configuration, backups, and Git history.

### [ ] G6 Final release gate

- **Depends on:** T604, T606
- **Verify:** every earlier gate is `[x]`; full test suite and Pi `doctor` pass; reboot restores services; reports validate; manual upload-ready DOCX is produced; Scanopy and nmap baseline comparison passes.
- **Evidence:** signed/tagged release commit, checksums, test/security/soak summaries, sample sanitized report, migration/rollback instructions, and release notes.

## Release checks and balances

These checks apply to every release candidate:

1. **Scope:** implementation still conforms to `SPEC.md`; deviations are approved and documented before code changes.
2. **Authorization:** no test targets a live network or service without explicit approval.
3. **Coexistence:** Scanopy health, nmap script checksum, and cron entry match the recorded baseline unless an approved integration change says otherwise.
4. **Least privilege:** services are unprivileged with only narrowly required capabilities and writable paths.
5. **Secret safety:** automated and manual scans find no credentials in Git, arguments, logs, SQLite, artifacts, backups, JSON, diagrams, or DOCX internals.
6. **Data minimization:** no unrestricted PCAP retention, external upload, or unnecessary directory/device data.
7. **Failure isolation:** one collector, parser, report, or network failure cannot stop unrelated collection or corrupt committed data.
8. **Provenance:** report facts and inferred links retain source, time, and confidence; conflicts and stale evidence remain visible.
9. **Recovery:** backup/restore, interrupted runs, low disk, restart, and reboot have verified outcomes.
10. **Reproducibility:** a clean ARM64-compatible environment can install, test, and build the same deliverables from the tagged commit.

## Deferred work

The following require a specification change before implementation:

- Direct API integration or upload to IT Glue, Datto RMM, or Autotask.
- NetBox integration.
- Routed-subnet discovery or IPv6 scanning.
- Vulnerability assertions/advisory correlation.
- Automatic device configuration backup.
- Offensive AD enumeration or credential-access features.
- Direct access to Scanopy's private database.
