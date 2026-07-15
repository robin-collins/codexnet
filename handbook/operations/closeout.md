# Site closeout

Closeout is part of the engagement, not optional cleanup.

## Final evidence and report

1. Run `status`, `doctor`, and `db check`.
2. Generate, validate, visually review, and checksum the final DOCX.
3. Upload only the DOCX through the authorised customer platform.
4. Confirm the recipient can open it and record the checksum and handoff time.
5. Record collector limitations and any incomplete evidence honestly.

## Backup or destruction decision

If retention is authorised, create a verified backup and record its exact protected location:

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --config /etc/field-discovery/config.yaml db backup
```

For expiry, preview then apply only reviewed CodexNet retention:

```bash
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --json --config /etc/field-discovery/config.yaml db prune
sudo -u field-discovery /opt/field-discovery/venv/bin/field-discovery \
  --json --config /etc/field-discovery/config.yaml db prune --apply
```

Generated DOCX/JSON files, SQLite backups, journald, and the external nmap result tree have separate
ownership and retention. Do not claim deletion while any authorised copy remains.

## Credential closeout

- Revoke or rotate temporary customer accounts.
- Remove only the exact provider entries approved for deletion.
- Check for temporary Kerberos caches or copied key files.
- Never archive the secrets file with the report or database.

## Protected-state comparison

Confirm all three Scanopy containers remain healthy, the approved nmap script checksum matches the
saved baseline, and no competing active-scan schedule was introduced. Do not inspect Scanopy's
private database.

## Disconnect

Stop or leave services according to the deployment plan, shut down cleanly when removing the Pi,
disconnect Ethernet, and update the engagement record. Preserve the appliance chain of custody when
it still contains customer data.
