# Before you leave

Prepare the appliance and the engagement record before travelling. Do not discover scope onsite by
trial and error.

## Engagement information

- [ ] Written authorisation names the customer, site, date/time window, and directly connected IPv4 range.
- [ ] Active scanning is explicitly included or excluded.
- [ ] Approved infrastructure IP addresses are listed for SNMP, UniFi, AD, and SSH.
- [ ] Read-only collector accounts are created and tested by the customer or service owner.
- [ ] The required report destination and authorised recipient are known.
- [ ] Local retention, backup, and destruction requirements are recorded.
- [ ] A customer contact and escalation path are available.

## Equipment

- Raspberry Pi 4B CodexNet appliance and known-good power supply
- Ethernet cables and any approved console/display equipment
- Administrator access to the Pi, preferably using an individual SSH key
- Secure method for receiving collector credentials onsite
- Laptop with current Microsoft Word or LibreOffice for visual report review
- Offline copy of the reviewed CodexNet release and dependency cache when Internet is uncertain

## Appliance readiness

Run these before departure while the Pi is on a trusted staging network:

```bash
/opt/field-discovery/venv/bin/field-discovery --version
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml doctor
systemctl is-enabled field-discovery-recovery.service \
  field-discovery-passive.service \
  field-discovery-scheduler.service \
  field-discovery-nmap-import.timer \
  field-discovery-backup.timer
systemctl --failed --no-pager
```

Confirm available disk space and take a verified backup if the appliance contains retained data:

```bash
df -h /var/lib/field-discovery
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml db check
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml db backup
```

!!! warning "Do not pre-load site secrets into Git or notes"
    Credentials belong only in the approved mode `0600` provider on the appliance. Never place a
    password, SNMP community, token, profile JSON, or private key in a ticket comment, shell command,
    repository file, or screenshot.
