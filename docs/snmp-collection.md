# SNMP collection

CodexNet collects SNMP only from an operator-supplied IPv4 target that passes the common
`active.approved_ranges` boundary. It never discovers or guesses community strings and it never
tries a default credential. SNMPv3 is the default. SNMPv2c requires `protocol: v2c` and
`allow_insecure_v2c: true`; every CLI run prints a security notice because v2c exposes its
community and payload without encryption.

The `credential_ref` value identifies a restricted environment-file or helper-command provider.
The environment file must be a real, non-symlink regular file with mode `0600` or stricter. A
helper receives only the reference key on standard input, never as an argument, and has a bounded
runtime and output. Profiles are JSON secret values:

```json
{"username":"readonly","auth_key":"...","auth_protocol":"sha256","priv_key":"...","priv_protocol":"aes128"}
```

For explicitly enabled v2c, the only accepted profile field is `community`. Supported v3
authentication algorithms are SHA-1 and SHA-2 (224/256/384/512); supported privacy algorithms are
AES-128/192/256. Secrets exist only in the collector process memory, are excluded from object
representations, registered with the redactor before persistence, and are never logged.

The base numeric-OID registry contains system identity, interface identity/state, legacy IPv4
address mappings, and LLDP remote-neighbor columns. Numeric OIDs avoid network MIB downloads or a
dynamic compiler. Table collection has a global row bound. Unknown OIDs are retained as bounded,
redacted structured observations up to a fixed limit; unsupported, malformed, partial, and
truncated results become explicit collector issues rather than aborting unrelated runs.

Run one or more explicit targets with:

```bash
field-discovery --config /etc/field-discovery/config.yaml collect snmp \
  --target 192.168.50.2 --target 192.168.50.3
```

The normal scheduler supplies concurrency, per-run timeout, retry, cancellation, failure
isolation, durable status, and approved-range enforcement. Tests use injected transports and never
open a network socket.
