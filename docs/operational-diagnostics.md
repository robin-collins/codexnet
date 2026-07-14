# Operational status and diagnostics

`field-discovery status` and `field-discovery doctor` inspect the CodexNet appliance without
starting collection, transmitting network traffic, changing services, migrating the database, or
modifying Scanopy and the protected nmap installation. They never resolve collector credential
references. Run them with the normal unprivileged service/operator account.

## Commands and exit contract

```bash
field-discovery --config /etc/field-discovery/config.yaml status
field-discovery --json --config /etc/field-discovery/config.yaml status
field-discovery --config /etc/field-discovery/config.yaml doctor
field-discovery --json --config /etc/field-discovery/config.yaml doctor
```

Exit status `0` means no error-level check failed. Exit status `11` means at least one error-level
check failed. Warnings are reported but do not change a successful exit to `11`; they represent an
unknown or intentionally not-yet-installed condition rather than a proven fault. Configuration
and unexpected-failure statuses retain the general CLI contract documented in `README.md`.

Human output begins with a summary and then prints every check as `[OK]`, `[WARNING]`, or `[ERROR]`.
JSON output is a deterministic object with these stable top-level fields:

| Field | Meaning |
|---|---|
| `schema_version` | Diagnostics schema version, currently `1` |
| `generated_at` | UTC timestamp |
| `ok` | `true` when there are no error-level checks |
| `summary` | Total check, warning, and error counts |
| `network` | Selected interface, address, CIDR, route/DNS metadata, and target-policy result |
| `paths` | Existence, type, symlink, mode, and effective read/write access |
| `database` | Identity, schema, integrity, foreign-key, and collector aggregates |
| `disk` | Total, used, free, and free percentage for the data filesystem |
| `collectors` | Per-collector runs, outcomes, items, errors, latest status, and age |
| `checks` | Ordered check records with name, category, status, message, and safe details |
| `command`, `message` | CLI command name and stable summary text |

`doctor` adds `dependencies`, `services`, and `clock`. Consumers should tolerate future additional
fields and use `schema_version` before depending on field meanings.

## Checks performed

`status` verifies:

- the configured interface and IPv4 CIDR using the same local route/address resolver as
  `discover subnet`;
- that the data and nmap-results paths exist with the required type, are not symlinks, and have the
  necessary effective permissions;
- the configured SQLite file using URI `mode=ro` plus `PRAGMA query_only`, with no call to the
  repository migration/open path;
- SQLite application identity, current migration version, integrity, and foreign keys;
- collector success, partial, and failure counts, item/error totals, last state, and last-run age;
- filesystem capacity for the nearest existing ancestor of the configured data root.

`doctor` additionally verifies:

- required installed Python distribution versions;
- load and active state for the CodexNet passive and nmap-import systemd units;
- system clock synchronization state;
- the protected nmap script SHA-256 against the recorded appliance baseline;
- absence of a competing nmap job in the operator and root crontabs, system timers, and standard
  system cron locations; and
- the three exact Scanopy containers are running, healthy, and retain `unless-stopped` restart
  policy.

The root crontab probe is `sudo -n crontab -l`: it never prompts for a password. Only the exact
`no crontab for <account>` response is treated as an inspected empty crontab. Permission denial,
missing commands, unreadable cron locations, or unrecognized output produce a warning saying the
schedule could not be fully inspected. They are never reported as proof that no schedule exists.

Scanopy inspection requests only container name, state, health, and restart policy for the three
known container names. It does not inspect environment variables, mounts, networks, logs, or the
Scanopy database.

## Data and failure safety

Diagnostics return categorical failure messages. Raw exception text, command standard error,
service output, cron contents, collector error detail, targets, and credentials are not included.
Command output is bounded and commands run from a fixed executable path without a shell. The cron
content search returns filenames only; filenames are used solely to classify the check and are not
included in output.

The commands do not repair failed checks. In particular, they do not start or restart services,
create paths, change permissions, initialize or migrate SQLite, schedule scans, run nmap, contact a
collector target, or alter Scanopy. Correct the underlying configuration or deployment separately,
then rerun the diagnostic command.

## Operator interpretation

- An error is a verified unsafe or unhealthy condition, such as a wrong database identity, failed
  integrity check, missing dependency, installed-but-inactive CodexNet service, changed nmap
  script, competing nmap schedule, or unhealthy Scanopy container.
- A warning is incomplete evidence, such as inaccessible root cron, unavailable Docker status,
  unknown clock synchronization, or a CodexNet service that is not installed yet.
- Collector age is `null` when the saved timestamp is absent, malformed, or lacks a timezone.
  Future timestamps are bounded to zero age and should prompt a separate clock review.

For release or stage-gate evidence, save only the sanitized JSON result in the approved evidence
location and compare the coexistence checks with [baseline.md](baseline.md). Do not save runtime
reports, customer identifiers, or command debug output in Git.
