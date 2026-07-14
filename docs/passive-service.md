# Passive observer service

The passive observer is a dedicated unprivileged process. Its only elevated privilege is
`CAP_NET_RAW`, bounded in both the systemd capability and ambient sets so it can open a receive-only
Linux `AF_PACKET` socket on the configured interface. It does not transmit frames, issue discovery
requests, run an ARP sweep, retain packet captures, invoke nmap, or access Scanopy.

The adapter accepts Ethernet frames up to 9216 bytes and extracts only LLDP, CDP, ARP, mDNS, and
DHCP payloads. The existing bounded pipeline parses them and persists structured observations.
Unsupported traffic is discarded. Service shutdown stops capture and gives the pipeline 20 seconds
to drain; systemd allows 30 seconds before enforcing termination.

## Install and verification

Install the application and dedicated virtual environment under `/opt/field-discovery` first. Review
the files, then install the account/unit without enabling it:

```bash
sudo packaging/install/install-passive-service.sh /home/osit/codexnet
sudo systemd-analyze verify /usr/lib/systemd/system/field-discovery-passive.service
sudo systemd-analyze security field-discovery-passive.service
```

Ensure `/etc/field-discovery/config.yaml` is root-owned, non-secret configuration and the selected
interface is correct. Enable only on an explicitly authorised network:

```bash
sudo systemctl enable --now field-discovery-passive.service
sudo systemctl status field-discovery-passive.service
sudo journalctl -u field-discovery-passive.service
```

Confirm `User=field-discovery`, the sole `CAP_NET_RAW` capability, memory/CPU/task/file limits, and
the effective sandbox in `systemctl show`/`systemd-analyze security`. Confirm the process cannot write
outside `/var/lib/field-discovery` and its systemd-created runtime directory. A deliberate process
failure should be restarted subject to the unit's start-rate limits.

## Rollback and uninstall

```bash
sudo packaging/install/remove-passive-service.sh
```

Removal stops/disables only `field-discovery-passive.service`, removes its unit and sysusers entry,
and reloads systemd. It deliberately retains the account, `/etc/field-discovery`, and
`/var/lib/field-discovery` to prevent accidental customer-data deletion. Remove retained CodexNet
state only under the later documented data-retention procedure. The scripts do not inspect or modify
Scanopy, `/usr/local/sbin/network-discovery-scan.sh`, cron, nmap timers, or nmap result files.
