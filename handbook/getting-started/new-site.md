# New-site setup

This runbook assumes CodexNet is already installed. For a new or upgraded appliance, complete
[Install or upgrade](install.md) first.

## 1. Establish physical scope

1. Confirm the switch port/VLAN with the customer contact.
2. Connect only `eth0` to the authorised customer-facing segment.
3. Leave Wi-Fi, Docker, Tailscale, and other interfaces out of scope unless the engagement
   explicitly requires and approves one.
4. Record the expected IPv4 CIDR before inspecting the Pi's result.

Inspect local interface state; these commands do not scan:

```bash
ip -brief link
ip -brief -4 address
ip -4 route show default
```

## 2. Create the site configuration

Start from the complete installed example and preserve its ownership:

```bash
sudo install -d -o root -g field-discovery -m 0750 /etc/field-discovery
sudo install -o root -g field-discovery -m 0640 \
  /opt/field-discovery/config/example.yaml \
  /etc/field-discovery/config.yaml
sudoedit /etc/field-discovery/config.yaml
```

At minimum, set:

- `interface.name` to the approved customer-facing interface;
- `active.approved_ranges` to only the written, directly connected scope;
- explicit collector targets, leaving unapproved collectors disabled;
- customer, site, technician, version, and confidentiality report metadata; and
- retention and disk-reserve values from the engagement plan.

See [Site configuration](../configuration/site-config.md) for a reviewed example.

## 3. Prove configuration and subnet

Run validation first, then resolve the connected subnet. Neither command contacts a collector
target or invokes nmap.

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml config validate
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml discover subnet
```

Stop if the interface, address, gateway, or normalized CIDR differs from the work order. Correct
the physical connection or obtain written scope clarification; do not expand `approved_ranges` to
silence a refusal.

## 4. Establish secret providers

If credentialed collectors are approved, create the provider before enabling them:

```bash
sudo install -o field-discovery -g field-discovery -m 0600 \
  /dev/null /etc/field-discovery/secrets.env
sudoedit /etc/field-discovery/secrets.env
sudo stat -c '%a %U:%G %n' /etc/field-discovery/secrets.env
```

The final line must report mode `600`. Follow [Credentials](../configuration/credentials.md); never
paste provider contents into diagnostic output.

## 5. Start and verify services

```bash
sudo systemctl enable --now field-discovery-recovery.service
sudo systemctl enable --now field-discovery-passive.service
sudo systemctl enable --now field-discovery-scheduler.service
sudo systemctl enable --now field-discovery-nmap-import.timer
sudo systemctl enable --now field-discovery-backup.timer

sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml doctor
```

Warnings mean evidence is incomplete and must be reviewed. An error means the deployment is not
ready. CodexNet supplies no active-scan timer; do not create one.

## 6. Record the site start

Record only sanitized facts in the engagement ticket: release version, start time, expected CIDR,
enabled collectors, diagnostic outcome, and planned collection duration. Do not paste configuration,
journal payloads, device inventories, or credentials.
