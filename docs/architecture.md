# CodexNet architecture

## Purpose and constraints

CodexNet is an offline-first, single-appliance network inventory and
documentation system for explicitly authorised, directly connected IPv4
networks. It runs beside Scanopy and the existing nmap script. Scanopy is an
independent system; CodexNet never reads its private database. The existing
nmap result tree is a read-only input and its active-scan schedule remains
external to CodexNet.

The deployment target is Debian ARM64 on a Raspberry Pi 4B. Application code
and its virtual environment live under `/opt/field-discovery`; configuration,
secrets, mutable data, reports, and logs use the paths specified in `SPEC.md`.
Tests substitute temporary directories and never write to runtime paths.

The T000 baseline records no nmap cron/timer at capture time despite the
expected state in the specification. CodexNet must treat that absence as the
comparison baseline and must not create a replacement schedule without explicit
approval.

## Runtime boundaries and privileges

```text
authorised network                     appliance
------------------  +----------------------------------------------+
passive frames ---->| capture boundary (capture capability only)   |
approved targets <--| protocol collectors (unprivileged)           |
                    |           |                                  |
nmap XML ---------->| importer  |                                  |
(read-only tree)     |     \     v                                  |
                    | event validation -> normalizer/correlator     |
                    |                         |                     |
                    |                    SQLite repository           |
                    |                         |                     |
operator ---------->| CLI / scheduler ------>| report engine        |
                    |       ^                 |                     |
secret provider --->|-------+                 v                     |
                    |                local DOCX/JSON/diagrams        |
                    +----------------------------------------------+
                                      |
                                      v
                             manual operator upload only
```

- `field-discovery` is a dedicated, unprivileged service account. It owns only
  approved application state and report/artifact directories.
- Passive capture is isolated from parsing. Only the capture process receives
  the minimum packet-capture capability or narrowly scoped group access; the
  scheduler, collectors, database, importer, report engine, and CLI do not run
  as root.
- Secrets are read at execution time from a mode `0600`, restricted-owner file
  or a configured secret command. Secret values are held in memory only for the
  shortest practical operation and never become ordinary CLI arguments.
- The nmap XML tree and protected script are read-only to CodexNet. Manual
  `scan nmap` requires an explicit operator action, target/interface checks, a
  lock, timeout, and an audit record; no CodexNet timer invokes it.
- systemd units apply filesystem protection, private temporary storage,
  capability bounding, resource limits, restart limits, and explicit writable
  paths. Import/report monitoring cannot launch nmap.

## Components and failure boundaries

| Component | Responsibility | Inputs and outputs | Failure boundary |
|---|---|---|---|
| Configuration loader | Load the versioned non-secret YAML contract and resolve secret references | YAML and environment/secret-command references; validated immutable settings | Invalid or unsafe configuration fails before network activity |
| Redaction service | Remove configured and structural secrets, including common encodings | Any value bound for logs, errors, artifacts, exports, or reports | Unsafe output is rejected rather than emitted |
| Interface/subnet resolver | Select configured interface, derive its global IPv4 CIDR, gateway and DNS context | Kernel/network configuration; deployment observation | Refuses absent, broad, unexpected, excluded, or unapproved targets |
| Passive capture adapter | Receive LLDP/CDP, mDNS, DHCP, ARP and neighbor evidence | Bounded frames or structured OS/daemon events | Capture loss is reported; it cannot stop import or collectors |
| Passive event pipeline | Validate, parse, deduplicate, expire and backpressure passive events | Bounded event envelopes; normalized observations | Parser errors are per-event; no unrestricted packet retention |
| Nmap artifact importer | Discover stable XML, parse safely, hash and import once | Read-only XML tree; observations and import ledger | Per-file transaction; malformed/incomplete files do not partially commit |
| Explicit nmap launcher | Invoke the protected script only on operator request | Approved interface/range and confirmation; run audit | Lock, timeout and exit propagation; never scheduled by CodexNet |
| Collector scheduler | Start independent runs with jitter and cancellation | Validated targets, credential references and intervals; run records | Bounded concurrency/retries; one run cannot block another collector |
| SNMP collector | Read approved SNMPv3 or explicitly enabled v2c inventory | Approved targets and ephemeral credential; normalized facts/artifacts | Per-target timeout and partial-result handling; never guesses communities |
| UniFi collector | Detect candidates conservatively and read configured controllers | Existing evidence/configured endpoints; normalized inventory/topology | TLS validation by default; endpoint failures remain isolated |
| AD collector | Detect AD and perform credential-gated documentation queries | Approved domain/base DN, Kerberos/LDAPS-preferred credential; directory facts | Paging/time bounds and attribute denylist; no offensive functions |
| SSH collector | Run vendor-specific read-only command allowlists | Approved devices and ephemeral credentials; parsed facts/sanitized output | Rejects unknown/write/config commands; session failures are per-device |
| Normalizer/correlator | Validate the common contract and deterministically relate evidence | Collector/passive/import observations; canonical facts and explainable links | Quarantines invalid records; never merges solely on hostname/reused IP |
| SQLite repository | Persist deployments, observations, provenance, runs and report history | Transactional canonical records; queries/backups/sanitized export | WAL, foreign keys, migrations, integrity checks and atomic transactions |
| Topology engine | Produce source-labelled observed/inferred relationships | Provenance-aware facts; deterministic graph model/source/render | Conflicts remain visible; absent evidence never becomes fact |
| Report engine/validator | Generate and validate deterministic DOCX, JSON and embedded diagrams | Read-only report model; local self-contained artifacts | Generation uses staging/atomic publish; validation failure withholds readiness |
| CLI/status/doctor | Operator control, maintenance and diagnostics | Explicit commands; human/JSON result and stable exit status | Diagnostics are passive unless collection/scan is explicitly selected |
| systemd/install tooling | Install, isolate, restart and remove owned components | Package/configuration; hardened units and owned paths | Rollback/removal is confined to CodexNet paths and preserves protected state |

Every network call has an explicit timeout, bounded retry count, bounded
concurrency and cancellation. Collector runs record success, partial success,
failure, counts and duration independently. Database transactions commit one
validated unit of work; failure cannot corrupt earlier observations. Report
failure cannot interrupt collection.

## Normalized data contract

Collectors return versioned observation envelopes rather than writing tables
directly. Each envelope contains a deployment, source type and source instance,
collection/run identifier, observed-at time, received-at time, subject aliases,
typed facts, optional relationships, confidence, and artifact provenance.
Values are length/type bounded before persistence.

Observed facts and inference remain distinct. Historical facts carry validity
or first/last-seen intervals. Correlation ranks stable identifiers such as
serial/controller identity and MAC/interface evidence; hostname or a reused IP
alone can suggest a conflict but cannot merge devices. Every merge decision is
deterministic and explainable from stored evidence.

## Data flows

1. The configuration loader validates interface, paths, approved ranges,
   schedules, limits, enabled collectors and report settings before services
   start. It resolves only references to secrets.
2. The resolver reads local interface state, records the deployment context and
   supplies an allowed CIDR. Active collectors intersect every target with the
   explicit allowlist and range-size limits.
3. Passive capture hands bounded event data to isolated parsers. The pipeline
   emits structured observations and discards packet payloads.
4. The importer waits for stable nmap XML, parses with external entity/network
   access disabled, computes a digest, and transactionally records both the
   scan observations and import ledger.
5. The scheduler supplies each collector with approved targets and ephemeral
   credentials. A collector returns versioned observations and separately
   sanitized diagnostic artifacts.
6. The normalizer validates observations, the correlator records explainable
   canonical identities and conflicts, and the repository commits provenance
   and history in one transaction.
7. The report engine queries a consistent snapshot and creates local JSON,
   diagram source/renderings and DOCX. The validator scans all content,
   metadata and DOCX relationships before atomically publishing a ready report.
8. An operator retrieves the report and may manually upload it to IT Glue,
   Datto RMM or Autotask. CodexNet contains no upload client or cloud credential.

## Scheduling and coexistence

Separate units cover continuous passive observation, collector orchestration,
and nmap artifact import/report refresh. The importer uses a path unit or a
non-conflicting timer and handles missed files after restart. It never launches
nmap. Scheduled collectors use jitter and resource ceilings so Scanopy remains
responsive. At every stage gate, checks compare Scanopy health, protected
script checksum, and the observed absence/presence of cron/timers to
`docs/baseline.md`; any change stops the gate for review.

## Storage, retention and recovery

- SQLite stores normalized history and provenance, not credentials. Foreign
  keys and WAL are enabled; numbered migrations are forward-applied and tested.
- Raw artifacts contain only bounded, sanitized collector output. Full packet
  captures are disabled by default; explicit diagnostic capture is time/size
  bounded and has a declared expiry.
- Raw artifacts and detailed observations default to 30 days. Stable normalized
  first/last-seen history may be retained longer under configured policy.
- Reports, JSON and diagrams are generated locally and are treated as customer
  data. Report history records metadata/checksum/status, not secret content.
- Disk thresholds pause artifact-heavy operations before collection threatens
  Scanopy or the operating system. Database backup/restore and pruning are
  explicit, integrity-checked operations confined to owned paths.
- Interrupted runs are marked incomplete. Atomic file replacement and database
  transactions prevent partially published imports, backups and reports.

## Specification traceability

| Specification area | Architecture realization |
|---|---|
| 2 Current state; coexistence | Protected external Scanopy/nmap boundary, read-only importer, baseline gate comparison |
| 3 Goals | Resolver, passive pipeline, importer, four collector families, repository/correlation, topology/reporting and resilient services |
| 4 Non-goals/safety | Target authorization, read-only adapters, no offensive AD, no automatic upload, one directly connected IPv4 subnet |
| 5 Implementation direction | Python `src/` package/venv, defined runtime paths, unprivileged account and narrow capture privilege |
| 6 Architecture | All nine named components map directly to component table; install/systemd/redaction are supporting controls |
| 7.1 Interface/subnet | Resolver, excluded-interface defaults, deployment record and target-range guard |
| 7.2 Passive discovery | Capture adapter plus bounded LLDP/CDP, mDNS, DHCP, ARP/neighbor event pipeline |
| 7.3 Active nmap | Safe XML importer, digest/path ledger, protected script launcher and external schedule boundary |
| 7.4 SNMP | Independent SNMPv3-first collector, explicit v2c, OID profiles and bounded runs |
| 7.5 UniFi | Conservative detection, configured modern/legacy client, TLS exception scoped per endpoint |
| 7.6 Active Directory | Credential-free detection and credential-gated Kerberos/LDAPS documentation collector with denylist |
| 7.7 Network-device SSH | Conservative vendor adapters with explicit read-only command allowlists and sanitized output |
| 7.8 Data model/SQLite | Versioned envelope, deterministic correlator and provenance/history repository |
| 7.9 Reporting/diagrams | Topology and report engines, self-contained DOCX/JSON/diagram outputs and validator |
| 7.10 CLI/operations | CLI/status/doctor component, explicit scan and stable human/JSON outcomes |
| 7.11 Services/scheduling | Hardened isolated units, path/timer import, restart/resource limits and run status |
| 8 Configuration/credentials | Versioned YAML loader, secret references/provider, ephemeral use and central redaction |
| 9 Reliability/retention | Failure boundaries, bounded resources, atomic work, disk guard, 30-day default and restart recovery |
| 10 Testing | Unit/fixture/migration/integration tests, temporary paths and offline approved targets |
| 11 Delivery phases | Components are separable along the five phases and TASKLIST stage gates |
| 12 Definition of done | Gate evidence covers install/reboot, coexistence, collectors, data integrity, redaction, reporting and operator docs |
