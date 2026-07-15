# Command reference

The executable is `/opt/field-discovery/venv/bin/field-discovery`. Global options appear before the
command:

```text
field-discovery [--config PATH] [--json] COMMAND
```

| Command | Purpose | Network effect |
|---|---|---|
| `config validate` | Validate non-secret schema and policy | None |
| `discover subnet` | Resolve local interface/CIDR/route/DNS | None |
| `status` | Fast paths/database/disk/collector health | None |
| `doctor` | Extended dependencies/services/clock/coexistence health | None |
| `import nmap [--path PATH]` | Import stable completed XML once | Reads local files only |
| `scan nmap [--yes] [--timeout S]` | Explicitly invoke protected active scanner | **Active scan** |
| `collect snmp --target IP` | Poll configured SNMP target | Read-only network collection |
| `collect unifi [--controller URL]` | Read configured controller | Read-only HTTPS collection |
| `discover ad --domain NAME [--site NAME]` | Bounded AD evidence discovery | DNS/anonymous RootDSE reads |
| `collect ad --target IP [--server-name NAME]` | Read documentation inventory | LDAP/Kerberos reads |
| `collect ssh --target IP --platform PLATFORM` | Run fixed show-command allowlist | Read-only SSH session |
| `report generate --format docx` | Generate DOCX and JSON | None |
| `report validate REPORT.docx` | Validate exact report package | None |
| `db check` | Integrity/schema/foreign-key check | None |
| `db backup [--output PATH]` | Verified online backup | None |
| `db prune [--apply]` | Preview/apply bounded retention | None |
| `db restore BACKUP --output NEW_PATH` | Restore to a new database | None |
| `db recover --confirm-stopped` | Mark interrupted runs after all writers stop | None |

## Stable exit statuses

| Status | Meaning |
|---:|---|
| 0 | Success |
| 2 | Command usage error |
| 3 | Invalid configuration |
| 5 | Subnet resolution failure |
| 6 | Database operation failure |
| 7 | Active scan refused |
| 8 | Nmap import failure |
| 9 | Report generation/validation failure |
| 10 | Collector failure |
| 11 | Operational diagnostics degraded |
| 12 | Low-disk safety pause |
| 70 | Unexpected internal failure |

Use `--json` for approved structured evidence. It does not make customer data safe to publish.
