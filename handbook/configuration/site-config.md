# Site configuration

`/etc/field-discovery/config.yaml` is non-secret YAML. Keep it `root:field-discovery 0640` and put
credentials only in a configured secret provider.

## Minimal safe pattern

```yaml
schema_version: 1

interface:
  name: eth0
  allow_excluded_interface: false

active:
  approved_ranges:
    - 192.168.50.0/24  # Documentation example: replace with written site scope.
  max_hosts: 256
  scan_timeout_seconds: 7200

paths:
  nmap_results: /var/log/network-discovery
  data_root: /var/lib/field-discovery
  database: /var/lib/field-discovery/discovery.db

scheduler:
  interval_seconds: 3600
  jitter_seconds: 120
  timeout_seconds: 30
  retries: 1
  concurrency: 4

storage:
  minimum_free_bytes: 536870912
  minimum_free_percent: 10
```

Copy the collector, secret-provider, report, and retention sections from
`/opt/field-discovery/config/example.yaml`; the schema rejects unknown or misspelled keys.

## Target rules

- Use canonical, private IPv4 CIDRs only.
- A range must be directly connected through the selected interface at runtime.
- `active.max_hosts` limits accidental broad scope; do not raise it merely to pass validation.
- Scheduled collectors need concrete targets as well as an enclosing approved range.
- UniFi uses an HTTPS URL whose literal IP matches `approved_address`.
- AD and SSH require an explicit target; SSH also requires an explicit supported platform.
- An empty target list means no scheduled traffic for that collector.

## Collector enablement

Keep all collectors disabled until their exact targets and least-privilege credentials are ready:

```yaml
collectors:
  snmp:
    enabled: false
    targets: []
    protocol: v3
    allow_insecure_v2c: false
    credential_ref:
      provider: appliance_env
      key: SNMP_SITE_PROFILE
```

Enable one collector at a time, validate, run it explicitly, review its result, and only then let
the scheduler operate it. A collector failure should produce partial coverage, not an excuse to
weaken TLS, host-key, or authentication controls.

## Report and retention

Set customer-facing metadata explicitly:

```yaml
report:
  customer_name: Example Customer
  site_name: Adelaide Office
  author: Example Technician
  company_name: Example MSP
  document_version: "1.0"
  confidentiality: Confidential
  template: null

retention:
  detailed_days: 30
  artifact_days: 30
  report_days: 30
  backup_days: 30
  diagnostic_capture_hours: 24
```

Use the actual authorised customer and site values in the appliance copy. The published examples
are synthetic and do not grant target authorisation.

## Validate every change

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml config validate
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml discover subnet
sudo systemctl restart field-discovery-scheduler.service
```

Restart the scheduler only after both validation commands match the work order.
