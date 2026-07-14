# Storage, backup, recovery, and removal

Every operation here is confined to the real configured `paths.data_root`. The external nmap
result tree, protected nmap script, cron, Docker, Scanopy containers, and Scanopy database are never
backup, restore, prune, rollback, or removal targets.

## Disk reserve

```yaml
storage:
  minimum_free_bytes: 536870912
  minimum_free_percent: 10
```

Reports, SSH artifacts, database backups, and restores subtract known pending bytes and must retain
both reserves. Crossing either threshold publishes nothing and returns status `12`. `status` and
`doctor` report the same condition as an error. A pause does not trigger deletion or stop unrelated
collectors; preview pruning and make an explicit decision.

## Scheduled verified backup

The unprivileged `field-discovery-backup.service` runs a SQLite online backup. Its timer is daily,
persistent across downtime, randomized, bounded, network-disabled, and writable only beneath the
CodexNet data root. Install files without starting them, review them, then enable explicitly:

```bash
sudo /opt/field-discovery/packaging/install/install-maintenance-services.sh /opt/field-discovery
sudo systemctl enable --now field-discovery-recovery.service
sudo systemctl enable --now field-discovery-backup.timer
systemctl list-timers field-discovery-backup.timer
```

The installer never enables or starts a unit. Manual backup is:

```bash
field-discovery --config /etc/field-discovery/config.yaml db backup
```

Success requires a new mode `0600` file with the CodexNet application identity, exact supported
schema, clean integrity, and no foreign-key violations. Backups contain customer inventory and
follow `retention.backup_days`.

## Pruning

```bash
field-discovery --json --config /etc/field-discovery/config.yaml db prune
field-discovery --json --config /etc/field-discovery/config.yaml db prune --apply
```

Preview and apply share independent detailed, artifact, report-history, and backup cutoffs. Apply
deletes database history, expiry-metadata artifacts, and direct data-root files matching only
`discovery-backup-YYYYMMDDTHHMMSSZ.db`. Backup candidates retain device, inode, size, and mtime from
preview and are all revalidated before deletion. Unexpected files and symlinks stop the operation.
The nmap input tree is not traversed. DOCX/JSON deliverables remain operator-controlled; report
history expires, but generated customer files are not automatically deleted.

## Interrupted runs and reboot

Recovery must not run on every database open because a concurrent collector may legitimately own a
`running` row. `field-discovery-recovery.service` runs once at boot and is ordered before passive
observation, nmap import, and scheduled backup. It marks then-unfinished rows failed with one
redacted `interrupted` error; a second pass is a no-op.

Manual recovery requires all CodexNet writers to be stopped:

```bash
sudo systemctl stop field-discovery-passive.service field-discovery-nmap-import.timer field-discovery-backup.timer
field-discovery --config /etc/field-discovery/config.yaml db recover --confirm-stopped
```

After reboot, inspect recovery and enabled services, then run `doctor`:

```bash
systemctl status field-discovery-recovery.service
systemctl status field-discovery-passive.service field-discovery-nmap-import.timer field-discovery-backup.timer
field-discovery --config /etc/field-discovery/config.yaml doctor
```

## Restore and rollback

Stop every CodexNet writer and restore to a new confined filename:

```bash
sudo systemctl stop field-discovery-passive.service field-discovery-nmap-import.timer field-discovery-backup.timer
field-discovery --config /etc/field-discovery/config.yaml db restore \
  /var/lib/field-discovery/discovery-backup-YYYYMMDDTHHMMSSZ.db \
  --output /var/lib/field-discovery/restored-YYYYMMDD.db
```

The source opens read-only. Source and destination pass identity/schema/integrity/foreign-key
checks, the new mode `0600` destination is fsynced, and a failed partial destination is removed.
The source and live configured database remain unchanged.

Change a copy of the configuration to the new `paths.database`, validate it, run `db check` and
`doctor`, then install the reviewed configuration and restart enabled CodexNet units. Keep the
previous application/config/database together for rollback. Schema downgrade is never in place:
select the prior application version and restore its verified pre-upgrade backup to another new
path.

## Uninstall

```bash
sudo packaging/install/remove-codexnet-services.sh
```

The script stops/disables and removes only six exact CodexNet unit names and its sysusers
declaration. It retains the account, configuration, secret provider, database and SQLite sidecars,
artifacts, reports, and backups. Inventory and remove retained customer data separately only after
confirming real paths and obligations. Never use broad recursive deletion around `/usr/local`,
`/var/log`, `/var/lib`, cron, or Docker.

Compare protected state with [baseline.md](baseline.md) afterward. The nmap script checksum and
schedule and all three Scanopy health/restart states must be unchanged. Staging tests place
sentinels at protected script, cron, nmap-results, and Scanopy paths and verify byte-for-byte
preservation across uninstall.
