# Collectors

Collectors are read-only, independently bounded, and disabled until configured. Every target must
be a concrete IPv4 address inside both the selected directly connected subnet and an explicit
approved range.

## SNMP

Prefer SNMPv3 authPriv. Configure the target list, protocol, and credential reference, validate,
then run one target:

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml collect snmp \
  --target 192.168.50.20
```

SNMPv2c requires `allow_insecure_v2c: true` and an explicit v2c profile. Never try common or default
communities. Unsupported OIDs and restricted views should become partial coverage rather than
prompting broader credentials.

## UniFi

Configure the exact HTTPS endpoint, matching literal `approved_address`, API type, TLS policy, and
read-only credential reference:

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml collect unifi
```

Use `--controller` only to narrow the already configured endpoint list. TLS verification remains
enabled. A self-signed exception is per endpoint, explicitly approved, and disclosed in the report;
never disable verification globally.

## Active Directory

Credential-free detection is bounded to the configured domain and approved targets:

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml discover ad \
  --domain example.invalid --site Site-A
```

Collection requires an explicit DC IPv4 and its certificate/SPN hostname:

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml collect ad \
  --target 192.168.50.10 --server-name dc1.example.invalid
```

Prefer Kerberos or verified LDAPS. Plain LDAP requires an explicit approved opt-in. CodexNet
collects documentation inventory only; it does not collect passwords, hashes, tickets, secrets, or
attack-path data.

## Cisco, HP/HPE, and Aruba SSH

Choose the platform conservatively from approved existing evidence:

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml collect ssh \
  --target 192.168.50.30 --platform cisco_ios
```

Supported values are `cisco_ios`, `hp_comware`, and `aruba_aos`. Strict host-key checking is the
default. Commands pass a fixed read-only allowlist and never enter configuration mode.

## Interpreting outcomes

| Outcome | Meaning | Response |
|---|---|---|
| Succeeded | Configured reads completed | Review item count and evidence age |
| Partial | Some safe reads failed or were unavailable | Preserve the limitation; investigate permissions/protocol support |
| Authentication failure | Provider/account rejected | Verify the intended profile; never guess alternatives |
| Target refusal | Outside approved/directly connected scope | Stop and reconcile scope/configuration |
| TLS/host-key failure | Identity verification failed | Verify identity and trust; do not bypass globally |
| Timeout | Target or path did not respond within bounds | Verify reachability and approved timing; keep bounds finite |
