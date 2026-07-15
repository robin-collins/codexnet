# CodexNet operator guide

Use CodexNet only on a customer network covered by explicit written authorisation. This guide
assumes [installation.md](installation.md) is complete, the customer-facing interface is connected,
and `/etc/field-discovery/config.yaml` has been reviewed. Commands are unprivileged unless a
specific service-administration step says otherwise.
The examples assume `/opt/field-discovery/venv/bin` is in the operator's current `PATH`; otherwise
use the absolute executable path. Do not add the secrets file or its contents to the environment.

## Configuration and credential profiles

Start from the complete [example configuration](../config/example.yaml). Set the interface,
explicitly authorised directly connected private ranges, storage reserves, retention periods, and
customer/site/author report metadata. `config validate` checks syntax and policy; `discover subnet`
then proves the live interface and range intersection without scanning.

```bash
field-discovery --config /etc/field-discovery/config.yaml config validate
field-discovery --config /etc/field-discovery/config.yaml discover subnet
```

Configuration contains only opaque references. The mode `0600` environment file has one
`UPPERCASE_KEY=one-line JSON profile` per enabled collector. Insert real values with an approved
secret editor; the following shapes show fields only and must not be copied with placeholder
values:

| Collector | Preferred secret profile shape |
|---|---|
| SNMPv3 | `{"username":"…","auth_key":"…","auth_protocol":"sha256","priv_key":"…","priv_protocol":"aes128"}` |
| UniFi | `{"username":"…","password":"…"}` for a read-only controller account |
| AD LDAPS | `{"username":"…","password":"…"}` for a least-privilege directory account |
| AD Kerberos | `{"principal":"…","use_system_ccache":true}`; CodexNet does not create/export tickets |
| SSH | `{"username":"…","password":"…"}` or the documented private-key fields |

SNMPv3, verified HTTPS, LDAPS/Kerberos, and strict SSH host-key checking are the production
defaults. Do not weaken them merely to make collection succeed. A justified per-endpoint
self-signed UniFi exception or legacy protocol opt-in must be approved and disclosed in the final
report. See [snmp-collection.md](snmp-collection.md), [unifi-collection.md](unifi-collection.md),
[ad-collection.md](ad-collection.md), and [ssh-collection.md](ssh-collection.md).

## Deployment start and normal operation

Before collection, compare Scanopy/nmap state to [baseline.md](baseline.md), validate local health,
and confirm storage headroom. Diagnostics are read-only and never resolve credentials or contact a
collector target.

```bash
field-discovery --config /etc/field-discovery/config.yaml status
field-discovery --config /etc/field-discovery/config.yaml doctor
systemctl status field-discovery-passive.service field-discovery-scheduler.service field-discovery-nmap-import.timer field-discovery-backup.timer
```

The passive service records bounded structured LLDP/CDP, mDNS, DHCP, ARP, and neighbor evidence;
it does not retain unrestricted packet captures. The nmap-import timer reads completed XML from the
protected result tree and never launches a scan. Inspect recent service events without copying
customer content into tickets or Git:

```bash
journalctl -u field-discovery-passive.service --since today
journalctl -u field-discovery-scheduler.service --since today
journalctl -u field-discovery-nmap-import.service --since today
field-discovery --json --config /etc/field-discovery/config.yaml status
```

The scheduler runs only collector profiles whose `enabled` flag is true and whose concrete targets
are listed in configuration. Restart `field-discovery-scheduler.service` after an approved config
change. You can also run configured collectors explicitly against approved targets. One collector
failure does not stop the others; review partial coverage before reporting.

```bash
field-discovery --config /etc/field-discovery/config.yaml collect snmp --target 192.168.50.2
field-discovery --config /etc/field-discovery/config.yaml collect unifi
field-discovery --config /etc/field-discovery/config.yaml collect ad --target 192.168.50.10 --server-name dc1.example.invalid
field-discovery --config /etc/field-discovery/config.yaml collect ssh --target 192.168.50.3 --platform cisco_ios
```

The addresses and names above are documentation examples, not authorisation. Never pass a password,
community, token, private key, or profile JSON on the command line.

## Explicit manual nmap scan

**`scan nmap` actively invokes the existing protected script. It is never a normal health check,
collector prerequisite, or automatic CodexNet schedule.** Before running it, confirm written
authorisation, the selected interface, the exact directly connected CIDR, the approved range, the
absence of another scan, and the customer change window.

Interactive confirmation is preferred:

```bash
field-discovery --config /etc/field-discovery/config.yaml discover subnet
field-discovery --config /etc/field-discovery/config.yaml scan nmap
```

`--yes` is only for an operator-controlled non-interactive invocation after the same checks. Never
put it in cron, a systemd timer, remote automation, or an RMM policy. CodexNet does not use `sudo`
to launch the script and does not create or repair the protected schedule.

## Word report and manual platform handoff

Confirm explicit customer, site, author, version, and confidentiality metadata, then generate the
self-contained DOCX/JSON pair. Generation performs validation before returning `upload_ready`.
Run validation again on the exact file being handed off and record its checksum in the authorised
ticket or assessment record.

```bash
field-discovery --json --config /etc/field-discovery/config.yaml report generate --format docx
field-discovery --json --config /etc/field-discovery/config.yaml report validate /var/lib/field-discovery/reports/Customer-Site-Network-Discovery-YYYYMMDD.docx
sha256sum /var/lib/field-discovery/reports/Customer-Site-Network-Discovery-YYYYMMDD.docx
```

Open the report locally in a current Word or LibreOffice viewer, update the table of contents, and
review coverage, failed collectors, ages, conflicts, limitations, diagrams, customer/site labels,
and confidentiality. If the file changes after validation, validate and checksum it again.

Uploading is a manual operator action outside CodexNet. In the authorised customer record in IT Glue,
Datto RMM, or Autotask, use that platform's normal authenticated attachment/document UI,
select the validated DOCX, confirm the customer/site mapping and access controls, and record the
checksum and upload time. Do not configure CodexNet with platform credentials, add an automatic
upload, or attach the internal JSON/database. Retain or remove the local DOCX according to the
engagement policy after the recipient confirms access.

## Backup, restore, and retention

Create a verified backup before upgrades, restoration, or risky maintenance. Prune is preview-only
until `--apply`; restore writes a new file and never replaces the live database.

```bash
field-discovery --config /etc/field-discovery/config.yaml db check
field-discovery --config /etc/field-discovery/config.yaml db backup
field-discovery --json --config /etc/field-discovery/config.yaml db prune
```

Follow [storage-recovery.md](storage-recovery.md) for the exact stopped-writer `db restore`
command, scheduled backups, interrupted-run recovery, restore switching, and rollback. Detailed
observations, artifacts, report history, backups, and
diagnostic captures have independent retention settings. Generated DOCX/JSON files and the
external nmap result tree are not deleted by CodexNet pruning.

At engagement closeout:

1. Confirm the customer accepted the validated DOCX and identify every authorised local copy.
2. Preview then apply due retention pruning; review counts before and after.
3. Remove expired report files only by their verified exact paths, and include temporary/unzipped
   copies and manually created diagnostics.
4. Account for the SQLite database, WAL/SHM files, artifacts, backups, journals, and the external
   nmap owner’s retention separately.
5. Rotate/revoke collector credentials and remove their exact provider entries.
6. Repeat the protected Scanopy/nmap baseline comparison.

Do not claim immediate customer-data deletion while a database or backup still contains it. Never
traverse or delete the nmap result tree, Scanopy data, Docker state, cron, or unrelated `/var/lib`
content as part of CodexNet retention.

## Troubleshooting

| Symptom | Safe response |
|---|---|
| Configuration status `3` | Run `config validate`; correct only the named non-secret field. Do not paste the config or secret file into a ticket. |
| Diagnostics status `11` | Read the categorical failing check in `doctor`; compare paths/services/protected state. Diagnostics do not repair it. |
| Storage status `12` | Stop artifact-heavy work, preview pruning, and expand approved storage or apply reviewed retention. Do not delete arbitrary files. |
| Collector status `10` | Check approved range, protocol profile, least-privilege access, TLS/host-key trust, and partial coverage. Do not guess credentials or weaken verification. |
| Report status `9` | Correct metadata/output permissions or regenerate from trusted data. A failed validation file is not upload-ready. |
| Nmap import defers XML | Wait for the protected writer to finish; do not edit, rename, or truncate its file. |
| Service restart loop | Stop the affected CodexNet unit, inspect bounded journal messages and configuration, then run `doctor`. Do not alter Scanopy to compensate. |
| Database integrity failure | Stop all CodexNet writers and follow verified restore-to-new-path procedure. Do not overwrite the live database. |

Escalate a suspected secret leak immediately: stop the affected collector, rotate the credential,
inventory reports/artifacts/backups, and follow the incident process in [threat-model.md](threat-model.md).
