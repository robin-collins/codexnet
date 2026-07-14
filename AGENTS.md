# AGENTS.md

## Mission

Build CodexNet as a safe, offline-first Raspberry Pi network discovery and documentation appliance for explicitly authorised customer networks.

Read these files before changing the project:

1. `SPEC.md` — authoritative product scope and safety boundaries.
2. `TASKLIST.md` — build order, dependencies, stage gates, and verification evidence.
3. This file — repository working rules.

If the three disagree, stop and resolve the conflict with the user. Do not silently broaden scope.

## Current protected state

The Pi's headless base setup, Scanopy deployment, `/usr/local/sbin/network-discovery-scan.sh`, and automatic interface-derived subnet behavior already exist. A root cron schedule was expected, but T000 found no root/user/system cron entry or matching systemd timer. Treat the existing components and documented scheduling discrepancy as protected external state.

- Do not edit the existing nmap script or create, replace, or reschedule nmap cron/timers without explicit user approval.
- Do not create a competing automatic active-scan schedule.
- Do not access or modify Scanopy's private database.
- Recheck Scanopy and nmap/cron health at every stage gate.

## Workflow

- Work on the earliest unblocked task in `TASKLIST.md` unless the user chooses another task.
- Before starting, confirm its dependencies are `[x]` and mark only that task `[~]`.
- Keep changes narrow enough to review and revert.
- Add or update tests and documentation with the implementation.
- Run the task's verification plus the repository checks before marking it `[x]`.
- Record meaningful verification evidence in the commit/PR description. Do not paste secrets or customer data.
- Mark a stage gate `[x]` only after all dependencies and gate evidence pass.
- If blocked, mark `[!]` and state the concrete blocker; do not bypass a safety check.
- Commit completed logical units. Do not commit generated reports, runtime databases, captures, credentials, or customer artifacts.

## Safety and authorization

- Operate only against fixtures, mocks, loopback/disposable local services, or targets the user has explicitly authorised.
- Passive/read-only behavior is the default.
- Never add exploitation, password cracking, credential dumping, Kerberoasting, AS-REP roasting, attack-path collection, brute force, guessed/default credentials, or denial-of-service behavior.
- AD collection is documentation-focused LDAP/Kerberos inventory only.
- SSH collectors use an explicit read-only command allowlist and must never enter configuration mode.
- SNMPv3 is preferred; SNMPv2c requires explicit configuration. Never guess community strings.
- TLS verification stays enabled unless a specific endpoint has an explicit self-signed-certificate exception.
- No framework-controlled external upload. DOCX upload to IT Glue, Datto RMM, or Autotask is manual.
- Active scan targets must pass configured interface/range safeguards. No scheduled nmap job was present at T000; do not create one implicitly. `scan nmap` is an explicit operator action.

## Secrets and customer data

- Never put credentials in source, fixtures, CLI arguments, Git, SQLite, reports, logs, exceptions, diagrams, process listings, or generated artifacts.
- Commit only sanitized synthetic fixtures. Preserve useful structure but remove real names, addresses, domains, identifiers, serials, tokens, hashes, and customer content.
- Secret files must be outside Git, mode `0600`, and accessed through documented references/environment or a secret command.
- Apply centralized redaction before logging or persistence, including common encoded forms.
- Do not retain unrestricted packet captures. Store bounded structured observations; diagnostic captures require an explicit action and retention limit.
- Generated reports and runtime data belong in ignored paths. Inspect DOCX internals, not only rendered text, during redaction tests.

## Architecture rules

- Target Python 3 on Debian ARM64/Raspberry Pi 4B, using an installable `src/` package and dedicated virtual environment.
- Keep protocol collectors independent behind a common normalized contract.
- Network calls require explicit timeout, bounded retries, bounded concurrency, and cancellation.
- Collector failure must not stop other collectors, passive observation, nmap import, or reporting.
- SQLite uses foreign keys, WAL, numbered migrations, transactions, and provenance-aware historical observations.
- Correlation must be deterministic and explainable. Never merge devices solely by hostname or reused IP address.
- Imports are idempotent. XML parsing must disable external entities/network access.
- Services run unprivileged with narrowly scoped capabilities, systemd hardening, resource limits, and owned writable paths.
- Reports distinguish observed facts from inference and include source, age, confidence, conflicts, and limitations.
- `.docx` is the primary deliverable; it must be self-contained and ready for manual platform upload.

## Repository layout

Use this layout as implementation begins:

```text
src/field_discovery/   application package
tests/                 unit and integration tests
tests/fixtures/        synthetic/sanitized protocol fixtures
docs/                  architecture and operator documentation
packaging/systemd/     service and timer units
packaging/install/     install/upgrade/remove tooling
templates/             report templates without customer data
reference/             local-only source material; do not commit chat-log.json
```

Runtime locations are defined in `SPEC.md`; do not write to them during ordinary tests. Tests must use temporary directories.

## Quality gates

Once tooling is established, the standard local check sequence is:

```bash
python -m ruff format --check .
python -m ruff check .
python -m mypy src
python -m pytest
```

Until those commands exist, do not invent passing results. Add them under task `T001`, document exact supported commands in `README.md`, and keep this section synchronized.

For relevant changes, also verify:

- database migrations, foreign keys, integrity, backup, and restore;
- parser behavior with malformed/truncated/oversized fixtures;
- target allowlists and active-scan safeguards;
- timeout, retry, cancellation, restart, and partial-failure paths;
- secret/redaction patterns across logs, database, JSON, diagrams, artifacts, and unzipped DOCX XML;
- deterministic output and provenance/confidence handling;
- ARM64 dependency/install compatibility;
- Scanopy and existing nmap cron coexistence at stage gates.

Do not weaken, skip, or delete a failing check merely to make CI green. Fix the behavior or document and obtain approval for a scope change.

## File and Git hygiene

- Preserve user changes and unrelated work. Inspect status before editing.
- Use migrations for schema changes; never rewrite an already released migration.
- Avoid large generated or binary test data when a small sanitized fixture works.
- Never commit `reference/chat-log.json`, `.env`, secret files, databases, packet captures, generated reports, logs, backups, or customer exports.
- Update `SPEC.md` only for an approved requirement change. Update `TASKLIST.md` when verified work changes status or dependencies.
- Use clear commits tied to task IDs, for example: `feat(T201): import nmap XML idempotently`.

## Completion standard

A task is not complete because code was written. It is complete only when its deliverables exist, dependency-specific verification passes, safety checks pass, documentation is current, and reproducible evidence is recorded. The project is release-ready only after `G6` passes in full.
