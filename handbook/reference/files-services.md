# Files and services

## Runtime paths

| Purpose | Path | Expected control |
|---|---|---|
| Application | `/opt/field-discovery` | `root:root`, not runtime-writable |
| Virtual environment | `/opt/field-discovery/venv` | Release-owned |
| Non-secret config | `/etc/field-discovery/config.yaml` | `root:field-discovery 0640` |
| Environment secret provider | `/etc/field-discovery/secrets.env` | `field-discovery:field-discovery 0600` |
| Database | `/var/lib/field-discovery/discovery.db` | `field-discovery:field-discovery 0600` |
| Artifacts | `/var/lib/field-discovery/artifacts` | CodexNet-owned, restrictive |
| Reports | `/var/lib/field-discovery/reports` | CodexNet-owned, restrictive |
| Backups | `/var/lib/field-discovery/discovery-backup-*.db` | Customer data, mode `0600` |
| External nmap input | `/var/log/network-discovery` | Read-only to importer |
| Logs | systemd journal | Secret-free structured events |

## Units

| Unit | Role | Normal state |
|---|---|---|
| `field-discovery-recovery.service` | One boot-time interrupted-run recovery | active/exited after boot |
| `field-discovery-passive.service` | Continuous passive observations | active/running |
| `field-discovery-scheduler.service` | Bounded configured collector schedule | active/running |
| `field-discovery-nmap-import.timer` | Poll completed external XML | active/waiting |
| `field-discovery-nmap-import.service` | One import pass | inactive/success between runs |
| `field-discovery-backup.timer` | Persistent daily backup schedule | active/waiting |
| `field-discovery-backup.service` | One verified backup | inactive/success between runs |

## Protected external state

CodexNet does not own Scanopy, its Docker data/database, the nmap scanner script, non-XML scan
outputs, or active-scan scheduling. Do not use CodexNet installation, troubleshooting, retention,
or removal as permission to change them.
