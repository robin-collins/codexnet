# Raspberry Pi installation, upgrade, and removal

This runbook installs a reviewed CodexNet commit on Debian ARM64 under `/opt/field-discovery`.
It creates only CodexNet-owned application, configuration, state, account, and systemd files. It
does not alter Scanopy, Docker, `/usr/local/sbin/network-discovery-scan.sh`, cron, or the existing
`/var/log/network-discovery` result tree. Capture the read-only checks in [baseline.md](baseline.md)
before and after any installation or upgrade.

## Preconditions and release selection

Use a Raspberry Pi 4B running Debian ARM64 with Python 3.11–3.13, `python3-venv`, Git, and enough
free space to retain the configured reserve. Work from an administrator account; CodexNet itself
runs as the unprivileged `field-discovery` account. Do not run collectors or the application as
root.

Clone the repository and check out an exact reviewed commit. Replace the marker before running
these commands; do not deploy a moving branch tip.

```bash
git clone https://github.com/robin-collins/codexnet.git "$HOME/codexnet"
export SOURCE="$HOME/codexnet"
export RELEASE_COMMIT=REPLACE_WITH_REVIEWED_COMMIT
git -C "$SOURCE" fetch --tags --prune
git -C "$SOURCE" checkout --detach "$RELEASE_COMMIT"
git -C "$SOURCE" status --short
```

The final command must print nothing. Review the commit and run the repository checks before
installing. The lock is the authoritative, exact Python environment for this release.

```bash
python3 -m venv "$SOURCE/.release-check"
cd "$SOURCE"
.release-check/bin/python -m pip install --requirement requirements-dev.lock
"$SOURCE/.release-check/bin/python" -m ruff format --check "$SOURCE"
"$SOURCE/.release-check/bin/python" -m ruff check "$SOURCE"
.release-check/bin/python -m mypy src
.release-check/bin/python -m pytest
```

## Fresh installation

Export tracked files only. This excludes `.git`, local configuration, credentials, reports, and
runtime data.

```bash
sudo install -d -o root -g root -m 0755 /opt/field-discovery
git -C "$SOURCE" archive --format=tar "$RELEASE_COMMIT" | sudo tar -xf - -C /opt/field-discovery
sudo python3 -m venv /opt/field-discovery/venv
cd /opt/field-discovery
sudo venv/bin/python -m pip install --requirement requirements-dev.lock
export PATH=/opt/field-discovery/venv/bin:"$PATH"
field-discovery --version
```

Install the dedicated account and six CodexNet units. Each installer copies files and reloads
systemd but deliberately enables and starts nothing. The nmap installer schedules only completed
XML import; it cannot launch nmap.

```bash
sudo /opt/field-discovery/packaging/install/install-passive-service.sh /opt/field-discovery
sudo /opt/field-discovery/packaging/install/install-nmap-import-service.sh /opt/field-discovery
sudo /opt/field-discovery/packaging/install/install-maintenance-services.sh /opt/field-discovery
sudo systemd-analyze verify /usr/lib/systemd/system/field-discovery-*.service /usr/lib/systemd/system/field-discovery-*.timer
```

Create non-secret configuration separately from the application. Review every customer-facing
value and keep all collectors disabled until its approved range and least-privilege credential
profile have been reviewed. An empty `active.approved_ranges` is the safest initial value.

```bash
sudo install -d -o root -g field-discovery -m 0750 /etc/field-discovery
sudo install -o root -g field-discovery -m 0640 /opt/field-discovery/config/example.yaml /etc/field-discovery/config.yaml
sudoedit /etc/field-discovery/config.yaml
sudo install -o field-discovery -g field-discovery -m 0600 /dev/null /etc/field-discovery/secrets.env
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery --config /etc/field-discovery/config.yaml config validate
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery --config /etc/field-discovery/config.yaml db check
```

Populate `secrets.env` through an approved secret-management process, never shell history or a
command-line argument. Its format and collector profile shapes are in
[configuration.md](configuration.md) and [operator-guide.md](operator-guide.md). An empty file is
valid while collectors remain disabled.

Review the unit sandbox, then explicitly enable only the required services. Boot recovery must
start before other CodexNet writers.

```bash
sudo systemctl enable --now field-discovery-recovery.service
sudo systemctl enable --now field-discovery-passive.service
sudo systemctl enable --now field-discovery-nmap-import.timer
sudo systemctl enable --now field-discovery-backup.timer
systemctl list-timers field-discovery-nmap-import.timer field-discovery-backup.timer
/opt/field-discovery/venv/bin/field-discovery --config /etc/field-discovery/config.yaml doctor
```

Do not enable a CodexNet nmap scan timer: none is supplied. Resolve every error from `doctor` and
review warnings before deployment. Compare Scanopy health, the protected script checksum, and
cron/timer evidence to the saved baseline.

## Upgrade and rollback

Acquire and verify the next exact commit as above. Before changing code, create a verified backup
and save the current commit identifier outside the customer report tree.

```bash
/opt/field-discovery/venv/bin/field-discovery --config /etc/field-discovery/config.yaml db backup
sudo systemctl stop field-discovery-passive.service field-discovery-nmap-import.timer field-discovery-backup.timer
```

Export the new commit into a new empty `/opt/field-discovery.next` directory. Rename the current
tree to a uniquely named rollback directory, rename `.next` to `/opt/field-discovery`, then create
the new virtual environment at its final path and install the lock. Never merge a new release into
the live tree.

```bash
sudo install -d -o root -g root -m 0755 /opt/field-discovery.next
git -C "$SOURCE" archive --format=tar "$RELEASE_COMMIT" | sudo tar -xf - -C /opt/field-discovery.next
sudo mv /opt/field-discovery /opt/field-discovery.rollback
sudo mv /opt/field-discovery.next /opt/field-discovery
sudo python3 -m venv /opt/field-discovery/venv
cd /opt/field-discovery
sudo venv/bin/python -m pip install --requirement requirements-dev.lock
sudo packaging/install/install-passive-service.sh /opt/field-discovery
sudo packaging/install/install-nmap-import-service.sh /opt/field-discovery
sudo packaging/install/install-maintenance-services.sh /opt/field-discovery
sudo -u field-discovery venv/bin/field-discovery --config /etc/field-discovery/config.yaml config validate
sudo -u field-discovery venv/bin/field-discovery --config /etc/field-discovery/config.yaml db check
sudo systemctl start field-discovery-recovery.service field-discovery-passive.service field-discovery-nmap-import.timer field-discovery-backup.timer
venv/bin/field-discovery --config /etc/field-discovery/config.yaml doctor
```

Use a unique rollback name if `/opt/field-discovery.rollback` already exists. Database migrations
are forward-only. On failure, stop all CodexNet writers, retain the failed tree for diagnosis,
restore the previous application tree to `/opt/field-discovery`, and restore the verified
pre-upgrade backup to a new database path as described in [storage-recovery.md](storage-recovery.md).
Do not downgrade a live migrated database in place.

## Service removal and retained data

Take an inventory and optional final backup, stop/remove only CodexNet units, then repeat the
protected baseline checks.

```bash
sudo /opt/field-discovery/packaging/install/remove-codexnet-services.sh
systemctl list-unit-files 'field-discovery-*'
```

The removal script intentionally retains `/opt/field-discovery`, the service account,
`/etc/field-discovery`, `/var/lib/field-discovery`, reports, backups, and secret-provider data.
Application removal and customer-data destruction are separate approved changes: verify each real
path, retention obligation, and backup before removing that exact owned path. Never use a broad
recursive deletion around `/opt`, `/etc`, `/var/lib`, `/var/log`, `/usr/local`, cron, or Docker.
Rotate or revoke collector credentials during site closeout. See [operator-guide.md](operator-guide.md)
for the engagement retention checklist.
