# Onsite runbook

Use this sequence for a normal engagement. Commands run as the unprivileged service account unless
the step explicitly administers systemd.

## 1. Start-of-day health

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml status
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml doctor
systemctl list-timers field-discovery-nmap-import.timer field-discovery-backup.timer
```

Confirm the reported interface/CIDR, database integrity, disk reserve, service state, and collector
ages. Review warnings; resolve all errors before collection.

## 2. Let passive observation work

The passive service records bounded LLDP/CDP, mDNS, DHCP, ARP, and kernel-neighbour facts. It does
not retain unrestricted packet captures.

```bash
systemctl status field-discovery-passive.service --no-pager
journalctl -u field-discovery-passive.service --since today --no-pager
```

Leave the Pi connected for the planned observation window. Do not restart it merely because no
immediate topology appears; passive evidence depends on customer traffic and protocol intervals.

## 3. Review nmap import

The import timer reads completed XML and never launches nmap:

```bash
systemctl status field-discovery-nmap-import.timer --no-pager
journalctl -u field-discovery-nmap-import.service --since today --no-pager
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml import nmap
```

Repeated imports safely skip the same path/digest. A deferred file is still being written; wait
instead of editing the external artifact.

## 4. Run approved collectors

Follow [Collectors](collectors.md). Start with one explicit approved target and review its success,
partial coverage, or safe failure before enabling scheduled runs.

## 5. Optional explicit active scan

!!! danger "Active scan — confirm scope again"
    `scan nmap` invokes the protected external scanner. It is not a health check or required daily
    step. Use it only when the written scope and current change window authorise active scanning.

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml discover subnet
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml scan nmap
```

Use interactive confirmation. `--yes` is reserved for an operator-controlled invocation after the
same checks; never place it in cron, a timer, an RMM policy, or remote automation.

## 6. End-of-day review

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --json --config /etc/field-discovery/config.yaml status
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml db check
```

Record sanitized run counts, failures, limitations, and next actions. Never paste raw customer
inventory or journal payloads into GitHub or an unapproved ticket.
