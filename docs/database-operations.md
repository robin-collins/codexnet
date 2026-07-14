# Repository and database operations

`field_discovery.repository.Repository` owns migrated SQLite access and uses explicit
`BEGIN IMMEDIATE` transactions. Exact repeated normalized facts and artifact path/digest pairs are
idempotent; observations at a different time remain historical. Collector runs start as `running`
and may transition once to a final state. Startup recovery marks abandoned runs `failed` and adds a
source- and time-stamped `interrupted` error, so incomplete work cannot appear successful.

The configured database must be beneath `paths.data_root`. Runtime checks refuse relative paths,
parent traversal, missing parent directories, symlinked roots/components, existing backup/export
destinations, and paths outside that root. Backups use SQLite's online backup API, mode `0600`, and
an integrity check before success. Sanitized JSON export is deterministic, mode `0600`, atomically
published, and applies centralized structural and known-value redaction to every row.

`db check` runs SQLite integrity and foreign-key checks. `db backup` creates a new timestamped file
inside the data root unless `--output` names another new confined path. `db prune` is a dry-run by
default; `db prune --apply` is the explicit destructive form.

Retention has independent detailed-observation, artifact-metadata, and report-history cutoffs.
Detailed pruning covers generic facts, collector errors, software/infrastructure history, and
topology history while preserving stable canonical deployments/devices and address first/last-seen
records. Artifact pruning removes CodexNet database metadata only: it never deletes or changes the
protected external nmap result tree. CodexNet-owned artifact file expiry is handled separately by
the link-safe artifact store.
