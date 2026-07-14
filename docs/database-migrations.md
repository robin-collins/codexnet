# Database migrations and recovery

CodexNet opens SQLite with foreign-key enforcement, a five-second busy timeout, and WAL journalling.
Calling `field_discovery.database.migrate()` applies the packaged, consecutively numbered SQL files
in one transaction per migration. Applied version, name, SHA-256 checksum, and UTC application time
are recorded in `schema_migrations`; a released migration must never be edited or renumbered.

## Upgrade procedure

1. Stop CodexNet writers while leaving Scanopy and the protected nmap script untouched.
2. Back up the database together with its WAL state using the supported backup operation introduced
   by T102. Do not copy a live database file with ordinary `cp`.
3. Start the new application and apply migrations once. Re-running the migration operation is safe.
4. Run `PRAGMA foreign_key_check` and `PRAGMA integrity_check`, then resume services only when both
   succeed.

## Failure and recovery

Each migration uses `BEGIN IMMEDIATE` and rolls back on SQL or validation failure. A failed version
is not written to `schema_migrations`, and the previous schema remains usable. Preserve the failed
database and logs for diagnosis, correct the new unreleased migration, and retry from the same
version. Never change a migration already recorded in any deployed database.

If integrity checks fail, stop all CodexNet writers, preserve the damaged files for diagnosis, and
restore the verified pre-upgrade backup to a new database path. Check its foreign keys and integrity
before atomically selecting it as the runtime database. Do not delete the damaged copy until the
restored inventory and migration history have been checked. Unknown future versions or checksum
mismatches are deliberate hard failures: install the matching application version instead of
bypassing the guard.
