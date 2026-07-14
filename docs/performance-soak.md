# Performance and soak profile

T605 uses a fixture-only accelerated replay. It opens no collector socket, resolves no credential,
runs no scan, installs no service, and writes only beneath a temporary directory. The production
passive parsers/queue, collector orchestrator, SQLite repository, nmap importer, and DOCX renderer
are exercised with advancing UTC timestamps.

## Predeclared acceptance budgets

These budgets were fixed before the recorded T605 run:

| Measure | Acceptance budget | Basis |
|---|---:|---|
| Harness peak RSS | 512 MiB | Combined Python, SQLite, nmap parsing, and DOCX rendering in one process; production services remain separately constrained |
| Python allocation peak | 128 MiB | Detect unbounded Python-owned queues/models |
| Passive queue peak | 256 frames | Production queue maximum |
| Passive retained payload capacity | 2,359,296 bytes | Production `256 × 9,216` transient queue bound |
| Final passive depth/in-flight/incomplete | 0 / 0 / 0 | Clean drain/restart requirement |
| Maximum daily DOCX render | 10 seconds | Pi operator workflow budget |
| Maximum DOCX size | 5 MiB | Representative fixture report bound, not a universal customer-data cap |
| Projected 30-day SQLite allocation | 128 MiB | Representative replay profile budget |
| File logs | 0 | Production logging goes to bounded systemd journal, not data-root files |
| Artifact growth | At most two files per successful synthetic collector call | One bounded payload plus one expiry metadata file |

The passive service's systemd `CPUQuota=40%` is an enforced runtime ceiling. Harness CPU seconds per
simulated day are a regression measurement, not an equivalent CPU quota. The nmap importer also has
`MemoryMax=256M` and `TasksMax=32`; the passive service retains its existing `MemoryMax=256M` and
`TasksMax=32`.

## Replay model

Each virtual day contains 24 hourly cycles. Four sanitized LLDP/CDP fixtures enter the real bounded
passive pipeline per cycle. The real collector orchestrator runs a stable collector beside a
recovering collector; the latter is unavailable for the first cycle of every day and succeeds on
the next cycle. Both persist normalized facts and bounded expiry-metadata artifacts without network
I/O.

One aged copy of the sanitized complete nmap XML fixture is imported daily. One validated DOCX/JSON
pair is generated daily. The passive pipeline is drained and recreated daily. At the midpoint an
uncommitted transaction is rolled back by interruption, a persisted `running` collector record is
recovered after repository reopen, and a second recovery is verified as a no-op. Final integrity,
foreign keys, and unfinished-run count are checked.

## Reproduction

From the repository virtual environment:

```bash
.venv/bin/python scripts/run_t605_soak.py --days 7 --cycles-per-day 24
```

The default uses an auto-cleaned temporary data root and performs only fixed read-only
name/state/health/restart-policy checks against Scanopy and the protected nmap state before and
after. `--skip-protected-probe` is for disposable automated tests only. The command emits one JSON
object and exits nonzero if any budget or state comparison fails.

For clean peak-RSS comparison, run the command in a fresh process as shown. Do not point
`--output-root` at `/var/lib/field-discovery`, customer data, the external nmap result tree, or a
Scanopy path.
