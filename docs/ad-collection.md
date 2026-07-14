# Active Directory documentation collection

`collect ad` performs bounded, read-only directory inventory after the target,
domain, base DN, server name, and opaque credential reference have all been
configured. It collects forest/domain metadata, sites and subnets, domain
controllers and their roles, computers, organisational units, trusts, and only
the documentation groups named in `documentation_groups`. It does not perform
user enumeration, attack-path analysis, authentication attacks, or credential
access.

## Transport and credentials

Kerberos and LDAPS are the preferred transports. Kerberos uses the system
credential cache and its secret-provider JSON is exactly
`{"principal":"collector@example.invalid","use_system_ccache":true}`. LDAPS
uses `{"username":"EXAMPLE\\collector","password":"..."}`. Plain LDAP uses
the same bind profile but is rejected unless both `transport: ldap` and
`allow_plaintext_ldap: true` are explicitly configured.

Secret JSON is resolved at execution time from the configured `env_file` or
direct-exec `command` provider. Provider files must be mode `0600`; helper keys
are sent on standard input and never placed in arguments. Do not store these
examples with real values in the repository.

LDAPS certificate-chain and hostname verification are mandatory. Kerberos uses
SASL/GSSAPI with the system cache; CodexNet does not accept passwords for that
profile or create/export tickets.

## Bounded directory reads

Queries have fixed filters and attribute allowlists. Password, hash, ticket,
secret, credential, and attack-path fields are rejected even if returned by a
server. Results use bounded page size and entry count. Referrals are disclosed
but never followed automatically. Large group memberships use explicit AD
range continuation, with repetition and size limits. Insufficient permissions,
individual query failures, and unavailable ranges are reported as partial
coverage without stopping independent queries.

Run only against an explicitly authorised, approved IPv4 target:

```bash
field-discovery --config /etc/field-discovery/config.yaml collect ad \
  --target 192.168.50.10 --server-name dc1.example.invalid
```

`--domain` may confirm the configured domain but cannot change it. Facts are
stored with LDAP provenance and observation time; credentials and session
material are never persisted. Use a dedicated least-privilege read-only
account and review partial-coverage notices before relying on a report.
