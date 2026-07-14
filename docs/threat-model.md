# CodexNet threat model

## Scope and security objectives

This model covers CodexNet code, services, configuration, secret retrieval,
network collection, nmap import, local persistence, report generation,
maintenance and manual handoff. Scanopy, customer systems, the protected nmap
script/schedule and destination documentation platforms are external systems.

Primary objectives are to keep credentials secret, constrain activity to
authorised targets, preserve customer-data confidentiality and provenance,
prevent malformed input from gaining code/file/network access, keep Scanopy and
existing discovery operational, and produce honest reports without silently
merging or inventing facts.

Explicitly prohibited and absent by design:

- exploitation, brute force, password cracking, guessed/default credentials,
  configuration changes, denial of service, and unrestricted packet capture;
- credential dumping, password/hash/ticket collection, Kerberoasting,
  AS-REP roasting, BloodHound/attack-path collection, `secretsdump`, or other
  offensive AD behavior;
- automatic cloud upload or platform API integration;
- direct access to Scanopy's private database;
- automatically scheduled nmap invocation by CodexNet.

## Assets and actors

Assets include protocol credentials and session material; customer network and
directory observations; normalized SQLite history; bounded raw artifacts;
backups; logs; JSON, diagrams and DOCX reports; configuration and target
allowlists; the integrity of collector/parser code; and availability of the Pi,
Scanopy and protected discovery process.

Actors are an authorised operator, the unprivileged service account, a local
administrator, customer network services/devices, potentially hostile or
malformed network responders, and a person who obtains physical/local access or
a generated report. Documentation platforms see data only after a deliberate
manual upload by the operator.

## Trust boundaries

| Boundary | Untrusted side | Trusted side and entry control |
|---|---|---|
| Network ingress | Frames, DNS, XML-derived service claims, SNMP/API/LDAP/SSH responses | Bounded parsers, schema validation, timeouts and per-source isolation |
| Active egress | Candidate or user-supplied targets | Resolver-derived CIDR plus explicit allowlist, range-size guard and protocol-specific approval |
| Privilege | Packet interface, root-owned configuration/secret files | Minimal capture capability in isolated process; all other work unprivileged |
| Secret retrieval | Restricted file or configured command output | Reference-only configuration, ownership/mode checks, bounded output and ephemeral memory |
| Protected nmap/Scanopy | Existing script, result tree, containers and private database | Read-only artifact access/checks; explicit launcher only; no database access |
| Persistence | Validated events entering SQLite/artifact paths | Transactions, migrations, path ownership, symlink checks, quotas and redaction |
| Report boundary | Database/artifacts converted to portable files | Consistent query, central redaction, deterministic rendering and DOCX ZIP/XML/relationship validation |
| Operator handoff | Local report files | Manual retrieval/upload only, confidentiality marking and documented deletion |
| Supply/install | Python/system packages and unit files | Version constraints/lock, review, ARM64 checks, least-privilege install and rollback |

## Threats and required controls

| Threat | Impact | Preventive/detective controls | Verification |
|---|---|---|---|
| Target escape or overbroad scan | Unauthorised traffic or disruption | Explicit approved CIDRs, selected-interface intersection, maximum range, no routed/IPv6 expansion, explicit scan confirmation | Boundary fixtures; rejected outside/broad targets; scan mock audit |
| Credential guessing/reuse | Account compromise | Named profiles only, no cycling/defaults; v2c and plaintext LDAP require explicit opt-in; read-only accounts | Tests prove absent/unknown profiles fail without attempts |
| Secret exposure | Credential theft from Git, process list, logs, DB or reports | Reference-only configuration, no password flags, mode/owner checks, central redaction including encodings, ephemeral use | Seeded secret corpus scanned across all outputs and DOCX internals |
| Malformed or hostile protocol input | Crash, resource exhaustion, parser exploit or forged facts | Length/depth/count limits, streaming parsers, XML entity/network disablement, timeouts, typed envelopes and parser isolation | Malformed/truncated/oversized fixture suite and memory bounds |
| Path traversal/symlink race | Read/write/delete outside owned paths | Canonical path checks, no following unsafe symlinks, fixed owners, atomic files and scoped deletion | Traversal/symlink fixtures and prune dry-run tests |
| Nmap artifact replay/partial import | Duplicate/corrupt history | Stable-file check, path plus digest ledger, per-file transaction and incomplete deferral | Import same/distinct/partial fixtures repeatedly |
| Device modification over SSH/API | Customer outage/configuration change | Read-only API account, HTTP method restrictions, SSH command allowlist and config/write command denial | Session fixtures assert exact commands/methods |
| TLS interception | Controller/directory credential and data theft | TLS verification on; self-signed exception is explicit per UniFi endpoint; LDAPS/Kerberos preferred | Invalid/self-signed/hostname mismatch tests |
| Offensive or excessive AD collection | Privacy/security harm | Approved domain/base DN, credential gate, attribute/query allowlists and forbidden-attribute filter; no offensive dependencies | Dependency and prohibited-term/query scan plus directory fixtures |
| Passive capture overcollection | Sensitive payload retention and disk exhaustion | Structured observations only, no default PCAP, bounded diagnostic capture with explicit action/expiry | Artifact inspection, retention and low-disk tests |
| False identity correlation | Incorrect documentation/action | Stable-evidence ranking, no hostname/IP-only merge, retained conflicts, provenance/time/confidence | IP reuse, MAC movement and conflict determinism tests |
| Forged topology/report facts | Misleading documentation | Observed/inferred distinction, source/confidence/age, deterministic graphs and limitations | Conflicting fixture and stable output hash |
| Collector cascading failure | Loss of unrelated discovery | Independent runs, bounded queues/workers/retries, cancellation and transaction scope | Timeout/auth/crash/partial/cancel fault injection |
| Resource exhaustion | Scanopy or appliance outage | systemd CPU/memory limits, bounded concurrency/queues, jitter, disk thresholds, retention/pruning | Soak/load/low-disk tests and Scanopy baseline comparison |
| Privilege escalation | Appliance compromise | Dedicated account, capability bounding, filesystem/systemd sandbox, no broad sudo, restricted writable paths | Effective unit/capability and permissions review |
| Data remanence | Customer data survives engagement | Data-class retention, explicit prune/delete, backup/report inventory and deletion verification | Expiry/prune/delete tests including backups and staged files |
| External exfiltration | Customer data leaves appliance unexpectedly | Offline-first behavior, no upload component/external report relationships, egress limited to approved collection | Source/dependency review and DOCX relationship validation |
| Supply-chain compromise | Code execution/data theft | Constrained reviewed dependencies, lock/checksums where supported, vulnerability audit and minimal runtime set | Clean ARM64 install and release dependency audit |
| Unauthorised local/physical access | Theft/tampering | OS-level access control, restricted secrets/data paths, report confidentiality and operational custody | Permission inventory and operator procedure review |

## Secrets and customer-data flow rules

No secret is stored in Git, YAML, SQLite, artifacts, logs, reports, backups or
process arguments. The secret provider itself is the sole at-rest secret store.
All customer-data outputs are local and inherit restricted ownership. The table
below is normative; a new flow requires a threat-model update.

| Data flow | Storage | Access | Logging rule | Deletion/retention rule |
|---|---|---|---|---|
| Non-secret configuration and approved targets | Root/admin-managed YAML under `/etc/field-discovery` | Administrator writes; service reads | May log validated non-sensitive settings, never customer labels by default | Removed during approved uninstall or site reset; configuration history is operator-managed |
| SNMP credential/community | Restricted secret provider only | Service resolves named profile for one run; v3 preferred, v2c explicit | Never log value, encoded value, auth parameters or command output containing it | Rotate/delete at provider; memory discarded after run; absent from backups made by CodexNet |
| UniFi username/password, cookie or token | Restricted secret provider; transient session in memory | UniFi collector for configured endpoint only | Redact authorization headers, cookies, tokens, URLs with credentials and response secret fields | Session closed/cleared after run; provider entry rotated/deleted by operator |
| AD bind credential/Kerberos session material | Restricted secret provider; transient protocol/library memory | AD collector only after domain/base DN approval | No bind DN plus failure detail that leaks identity; never log passwords, tickets, hashes or sensitive attributes | Session closed; caches disabled or private/short-lived and removed; provider entry rotated/deleted |
| SSH username/password/key/passphrase/session | Restricted provider/key path with strict permissions; memory during session | SSH collector only for approved target/profile | No arguments, key material, prompts, session transcript secrets or auth payloads | Session closed; provider/key removed by operator; no CodexNet backup |
| Interface/CIDR/gateway/DNS/deployment metadata | SQLite observation history | Service and authorised local operators/report queries | Structured logging may use bounded identifiers; customer-identifying fields redacted by policy | Detailed observations default 30 days; deployment deletion removes dependent records under explicit transaction |
| Passive LLDP/CDP, mDNS, DHCP, ARP/neighbor observations | Structured SQLite facts; optional sanitized bounded artifact | Passive pipeline/repository/report engine | Never log whole frames; redact sensitive TXT/options and bound displayed identifiers | No default PCAP; details default 30 days; explicit diagnostic capture has time/size limit and expiry |
| Nmap XML input | Remains in external protected result tree; digest/path and normalized facts in SQLite | Importer reads only; never deletes/changes source | Log digest/run status and sanitized error, not raw NSE content | External owner controls XML retention; CodexNet ledger/history follows configured policy |
| SNMP/API/LDAP/SSH responses | Normalized SQLite facts; only bounded sanitized diagnostic artifacts | Owning collector, normalizer, repository and authorised report path | Authentication data and sensitive/config fields redacted before any log/artifact | Raw details default 30 days; normalized history retained per policy; forbidden AD attributes are never stored |
| SQLite database | `/var/lib/field-discovery/discovery.db` | Dedicated account and authorised administrator only | Log operation status/count/duration, not row content | Explicit deployment/data-class prune; integrity-checked backup; deletion includes WAL/SHM and verified owned files |
| Logs/journal | systemd journal | Restricted local operators | Central structured redaction before emission; no payloads or secret-bearing exceptions | journald size/time limits; engagement procedure vacuums/expires according to policy |
| JSON and diagram source/renderings | Restricted report directory | Report engine and authorised operator | Log path/checksum/status only after path sanitization | Customer artifacts removed after manual handoff/retention deadline; staging files removed on failure |
| DOCX report and metadata | Restricted report directory; self-contained ZIP package | Report engine/validator and authorised operator | No document content in logs; filename/customer metadata supplied explicitly and sanitized | Manual upload is operator action; local copy and temporary/unzipped files removed per engagement policy |
| Database backup | Restricted owned backup path, integrity checked | Maintenance command and administrator | Log sanitized destination, checksum, size and result only | Same or shorter customer-data retention; included in site deletion and restore lifecycle |
| Collector/run diagnostics | SQLite run status and redacted journal events | Scheduler/status/doctor/operator | Counts, timing and classified error only; exceptions pass redaction | Run history pruned by policy; incomplete runs retained only long enough for diagnosis |

Deletion uses database transactions and canonical, owned path checks. Pruning
must include report staging directories, diagnostic captures, SQLite sidecars
and backups. It must never traverse symlinks or delete Scanopy/nmap-owned data.
Where external nmap files or manually uploaded reports exist, CodexNet reports
that their deletion remains the external owner's responsibility.

## Active-scan and collector controls

Active behavior is deny-by-default. The resolver selects the configured
customer-facing interface (default `eth0`) and excludes loopback, Docker,
Tailscale and Wi-Fi unless explicitly selected. A target must be within both the
resolved directly connected subnet and configured approved ranges, and satisfy
the maximum-prefix/host-count policy.

The scheduler may run only configured read-only collectors. It never schedules
`scan nmap`; the explicit launcher requires a confirmation/flag, validates the
same target context, serializes invocation, sets a timeout and records outcome.
SNMP never tries default communities. UniFi credentials are tried only against
configured endpoints. AD detection is credential-free and AD collection is
credential/domain/base-DN gated. SSH uses only the platform's reviewed
read-only allowlist and cannot enter configuration mode.

## Retention, failure and incident response

Default detailed/raw retention is 30 days, configurable by data class. Disk
thresholds stop artifact-heavy work before the filesystem threatens Scanopy.
Queues, parser sizes, retries, worker counts, pagination and command output are
bounded. Cancellation and shutdown mark incomplete work; transactions and
atomic publication prevent partial success from being misreported.

On suspected secret leakage, stop the affected collector without stopping
unrelated passive/import/report functions, revoke/rotate the external
credential, inventory and remove affected local artifacts/backups/reports,
review redacted logs, and rerun the seeded secret scan. On malformed input or a
collector crash, quarantine only the bounded artifact/event, record a sanitized
failure and continue other components. On coexistence drift, stop the stage
gate and compare Scanopy health, script checksum and cron/timer state with
`docs/baseline.md`; do not repair protected state without user approval.

## Residual risks and review gates

- Network inventory and reports are intrinsically sensitive even after secret
  redaction; physical/OS access control and prompt engagement deletion remain
  operational responsibilities.
- Passive visibility is incomplete and network responders may lie. Reports must
  show source, age, confidence, conflicts and limitations.
- Read-only accounts/protocol operations can still load fragile devices.
  Conservative intervals, bounded concurrency and operator-approved lab tests
  reduce but do not eliminate this risk.
- A mutable external container image tag appears in the T000 Scanopy baseline;
  CodexNet does not manage or alter it, so later comparisons record health and
  observed image identity without asserting supply-chain integrity.
- The expected nmap cron is absent in the T000 baseline. This is an unresolved
  operational discrepancy, not permission for CodexNet to create a scheduler.

T002 has no unresolved critical design threat when all listed controls are
implemented and verified at their TASKLIST stages. G0 must confirm architecture
traceability and protected-state non-modification; later gates add parser,
target, redaction, least-privilege, soak, recovery and full release reviews.
