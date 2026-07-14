# Configuration, secrets, and redaction contract

CodexNet configuration is non-secret YAML governed by
[`config/schema-v1.json`](../config/schema-v1.json). `schema_version: 1` is
mandatory; incompatible versions and every unknown key fail before network or
database activity. [`config/example.yaml`](../config/example.yaml) is the
complete operator example. Site-specific copies and all secret files are
ignored and must not be committed.

## Safe defaults and target validation

Omitted collectors are disabled, the approved range list is empty, SNMPv3 and
LDAPS are selected, TLS and SSH host-key verification are strict, concurrency
and retries are bounded, and detailed observations expire after 30 days.
Approved targets must be canonical private IPv4 CIDRs and each range must fit
`active.max_hosts` (256 by default). Runtime resolution must additionally
intersect them with the selected directly connected subnet; schema validation
does not itself authorise a target. Loopback, link-local, public, IPv6, and
over-size ranges fail validation. Excluded interfaces require an explicit
override.

The minimum collector interval is 60 seconds. Timeout, retry, concurrency,
jitter, and retention ranges are bounded in the schema and runtime validator.
SNMPv2c and plaintext LDAP require visibly named explicit opt-ins. A UniFi
self-signed exception is per endpoint and requires both `verify_tls: false` and
`allow_self_signed: true`. HTTP controller URLs and disabled SSH host-key
checking are never accepted.

## Secret references

A `credential_ref` contains exactly a provider name and an uppercase opaque
key. It never contains a username, password, community, token, key material, or
authentication parameters. There are two provider contracts:

- `env_file`: an absolute path to a root/admin-managed, service-readable file.
  The future resolver must reject files not owned by the approved account or
  not mode `0600`; it reads the named key without adding it to the environment
  of child processes.
- `command`: an absolute executable invoked directly without a shell. The
  future resolver writes the reference key to standard input, accepts one
  bounded value from standard output, uses a 1–30 second timeout, supplies a
  minimal environment, and never places either key or value in command-line
  arguments. Non-zero, excess, or malformed output fails closed.

Secret resolution is deliberately not implemented in T003. Resolution must be
ephemeral at collector execution time; values must never be inserted into the
validated `Configuration`, serialized YAML/JSON, SQLite, artifacts, logs,
exceptions, reports, diagrams, backups, process arguments, or test snapshots.
Enabled collectors must later fail without attempting authentication when a
reference is absent or cannot be resolved. Rotation changes only the provider.

## Redaction boundary

`field_discovery.redaction.Redactor` is the mandatory boundary for any log,
exception, diagnostic artifact, export, diagram label, report model, or status
output. Callers seed it with secrets only in ephemeral memory. It removes exact
values, URL-encoded and standard/URL-safe base64 forms, authentication headers,
URI userinfo, common assignments, and values under structurally sensitive
keys. Values shorter than four characters are not registered because broad
replacement would corrupt ordinary output; such secrets must be rejected by a
future provider policy.

Encoded matching is deterministic and bounded: percent/form decoding performs
at most two passes, covering single and double encoding without generating an
unbounded transform set. Standard and URL-safe base64 (padded or unpadded) and
mixed-case hexadecimal forms are also checked. Configuration URL authority,
query-key, and fragment validation applies the same two-pass ceiling.

Redaction is defense in depth, not permission to collect or persist sensitive
fields. If safe output cannot be proven, the output boundary must reject it.
Errors name only a configuration path and rule—never the rejected value or
secret-provider output. DOCX ZIP/XML and relationships receive the same scan at
the reporting stage.

## Validation API

`load_config(Path(...))` accepts at most 1 MiB and uses PyYAML `safe_load`.
`validate_config(...)` validates an already parsed mapping. Both return an
immutable wrapper with deterministic non-secret JSON serialization or raise a
`ConfigurationError` with an actionable, secret-free message. This API only
parses configuration; it performs no network, secret-provider, database, or
runtime-path access.
