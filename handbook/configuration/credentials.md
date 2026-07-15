# Credentials

CodexNet configuration contains opaque references, never secret values. Resolve credentials only
at collector execution time through a mode `0600` file or an approved secret helper.

## Environment-file provider

```yaml
secret_providers:
  appliance_env:
    type: env_file
    path: /etc/field-discovery/secrets.env
```

Create and edit it safely:

```bash
sudo install -o field-discovery -g field-discovery -m 0600 \
  /dev/null /etc/field-discovery/secrets.env
sudoedit /etc/field-discovery/secrets.env
sudo stat -c '%a %U:%G %n' /etc/field-discovery/secrets.env
```

Each line is `UPPERCASE_KEY=one-line JSON profile`. Do not export the file into the shell.

## Supported profile shapes

The values below show field names only. Enter real values through the approved secret editor, not
by copying placeholders into a command.

| Collector | Preferred profile |
|---|---|
| SNMPv3 | `username`, `auth_key`, `auth_protocol`, `priv_key`, `priv_protocol` |
| SNMPv2c | `community`; allowed only when the configuration explicitly opts in |
| UniFi | `username`, `password` for a read-only controller account |
| AD LDAPS | `username`, `password` for least-privilege directory reads |
| AD Kerberos | `principal`, `use_system_ccache: true`; CodexNet does not create or export tickets |
| SSH | `username` with `password`, or the documented private-key reference fields |

SNMPv3, verified HTTPS, LDAPS/Kerberos, and strict SSH host keys are production defaults.

## Secret-helper provider

```yaml
secret_providers:
  secret_helper:
    type: command
    executable: /usr/local/libexec/field-discovery-secret
    timeout_seconds: 5
```

The helper receives only the opaque key on standard input and returns one bounded value on standard
output. It is executed directly without a shell. Never place the key's value in the executable
arguments, logs, or environment.

## Rotation and incidents

Rotate a credential by replacing only its provider value, then run the single approved collector
and inspect the outcome. No application-code or database change is needed.

If a secret may have leaked:

1. Stop the affected collector or scheduler.
2. Revoke or rotate the credential at the source.
3. Inventory journals, artifacts, reports, backups, ticket attachments, and temporary files.
4. Follow the organisation's incident process.
5. Resume only after the leak boundary and replacement credential are verified.

Do not paste the suspected value into a search command, ticket, or chat transcript.
