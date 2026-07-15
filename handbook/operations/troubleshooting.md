# Troubleshooting

Begin with read-only evidence. Diagnostics do not repair, scan, resolve credentials, or contact a
collector target.

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml status
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml doctor
systemctl --failed --no-pager
```

## Common conditions

| Symptom / status | Safe response |
|---|---|
| Configuration `3` | Run `config validate`; correct only the named non-secret field |
| Diagnostics `11` | Read the failing category; compare paths, units, clock, database and protected state |
| Storage `12` | Pause artifact-heavy work; preview pruning or add approved storage |
| Collector `10` | Check scope, concrete target, provider, least privilege, TLS/host-key trust and limitations |
| Report `9` | Correct metadata/permissions or regenerate; never upload the failed file |
| Nmap import deferred | Wait for the external writer to finish; do not alter the XML |
| Service restart loop | Stop only the affected CodexNet unit, inspect bounded journal output, validate config |
| Database integrity failure | Stop all CodexNet writers and follow restore-to-new-path procedure |

## Service evidence

```bash
systemctl status field-discovery-passive.service --no-pager
systemctl status field-discovery-scheduler.service --no-pager
systemctl status field-discovery-nmap-import.timer --no-pager
systemctl status field-discovery-backup.timer --no-pager
journalctl -u field-discovery-scheduler.service --since today --no-pager
```

Do not copy raw journal content into an unapproved system. Summarize the unit, timestamp, categorical
error, and remediation instead.

## Database and disk

```bash
df -h /var/lib/field-discovery
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml db check
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --json --config /etc/field-discovery/config.yaml db prune
```

Prune is a preview unless `--apply` is explicitly supplied. Never manually delete arbitrary files
under `/var/lib`, `/var/log`, Docker, or Scanopy to recover space.

## Escalate immediately when

- the connected subnet differs from authorised scope;
- a credential or customer artifact may have leaked;
- the protected nmap script checksum or scheduling changed unexpectedly;
- Scanopy became unhealthy after a CodexNet action;
- database integrity or foreign keys fail; or
- a requested workaround requires disabling TLS, SSH host-key checks, target safeguards, or service confinement.
