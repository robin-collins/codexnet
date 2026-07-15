# Install or upgrade

Use an exact reviewed release. Do not deploy a moving branch tip to a customer appliance.

## Prerequisites

- Debian ARM64 on a Raspberry Pi 4B
- Python 3.11–3.13 and `python3-venv`
- Git and enough free space for the application, state, backups, and configured reserve
- Administrator access for package and systemd installation

## Fresh installation

```bash
git clone https://github.com/robin-collins/codexnet.git "$HOME/codexnet"
git -C "$HOME/codexnet" fetch --tags --prune
git -C "$HOME/codexnet" checkout --detach v0.1.0
git -C "$HOME/codexnet" status --short
```

The final command must print nothing. Export tracked files only:

```bash
sudo install -d -o root -g root -m 0755 /opt/field-discovery
git -C "$HOME/codexnet" archive --format=tar v0.1.0 | \
  sudo tar -xf - -C /opt/field-discovery
sudo python3 -m venv /opt/field-discovery/venv
cd /opt/field-discovery
sudo venv/bin/python -m pip install --requirement requirements-dev.lock
```

Install unit files. These installers do not enable or start services:

```bash
sudo packaging/install/install-passive-service.sh /opt/field-discovery
sudo packaging/install/install-scheduler-service.sh /opt/field-discovery
sudo packaging/install/install-nmap-import-service.sh /opt/field-discovery
sudo packaging/install/install-maintenance-services.sh /opt/field-discovery
sudo systemd-analyze verify \
  /usr/lib/systemd/system/field-discovery-*.service \
  /usr/lib/systemd/system/field-discovery-*.timer
```

Continue at [New-site setup](new-site.md). Do not alter Scanopy, the protected nmap script, its
result retention, or active-scan scheduling as part of installation.

## Upgrade

Before upgrading, validate and back up the live database:

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml db check
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml db backup
```

Stop all writers, export the new reviewed commit into an empty
`/opt/field-discovery.next`, and retain the previous tree under a unique rollback name. Never
overlay a new release onto the live tree. Install the new virtual environment and units, validate
configuration and database, then restart services and run `doctor`.

!!! warning "Schema rollback is restore-based"
    Migrations are forward-only. Roll back the application together with its verified pre-upgrade
    backup restored to a new database path. Never point older code at a newly migrated live database.

The full administrative command sequence is maintained in the repository's
[installation runbook](https://github.com/robin-collins/codexnet/blob/main/docs/installation.md).
