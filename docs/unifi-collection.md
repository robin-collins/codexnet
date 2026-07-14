# UniFi collection

`collect unifi` contacts only controller URLs explicitly listed under
`collectors.unifi.endpoints`. Candidate detection derives likely controllers from existing nmap,
DNS, or mDNS observations and never probes endpoints or credentials.

Set `api_type` to `modern` for UniFi OS or `legacy` for the legacy controller API. TLS certificate
verification is enabled by default. A self-signed exception is scoped to one endpoint and requires
both `verify_tls: false` and `allow_self_signed: true`; redirects are refused.

The referenced secret is bounded JSON containing exactly `username` and `password`.
Environment-file providers must be regular, owned by root or the service account, and mode `0600`.
Command providers receive only the opaque key on standard input, never in argv. Use a read-only
controller account. MFA and other interactive authentication flows are reported as unsupported.

The client permits a login POST and allowlisted GET operations only, caps response sizes, pages,
and item counts, and never persists cookies, CSRF tokens, or credentials. T501 extends normalized
inventory beyond the initial site read.

```bash
field-discovery --config /etc/field-discovery/config.yaml collect unifi
field-discovery --config /etc/field-discovery/config.yaml collect unifi \
  --controller https://unifi.example.invalid
```
