# Nmap artifact monitoring

CodexNet polls the protected nmap result tree with a persistent systemd timer.
It does not use a path unit because systemd path monitoring is not recursive and
the existing script writes into a result tree. It never launches nmap or the
protected scan script.

## Behavior

`field-discovery-nmap-import.timer` starts two minutes after boot and then two
minutes after the preceding import pass becomes inactive, with up to 30 seconds
of random delay. `Persistent=true` catches an elapsed timer after downtime. Each
pass recursively calls only:

```text
field-discovery --config /etc/field-discovery/config.yaml import nmap --stability-seconds 30
```

The importer opens the configured result tree read-only. A file younger than 30
seconds, changing during its read, lacking nmap completion metadata, or ending
in incomplete XML is deferred. A later timer pass retries it. Completed files
are keyed by relative path and SHA-256 digest, so restart and repeated polling
do not duplicate an import. Per-artifact failures remain isolated and retry on a
later pass.

Fatal service failures are limited to five starts per 15 minutes. Timer starts
are also naturally bounded to one non-overlapping pass approximately every two
minutes. The oneshot has a five-minute execution timeout. This prevents tight
failure loops while retaining automatic recovery.

The service runs as `field-discovery`, permits no network sockets beyond local
Unix sockets, grants no capabilities, mounts `/var/log/network-discovery` and
configuration read-only, and allows writes only beneath
`/var/lib/field-discovery`. Adjust those paths together with the installed
configuration and unit sandbox if a deployment uses non-default paths.

## Optional report refresh

Report generation is disabled by default. After the report command is
implemented and configured, an administrator may copy
`packaging/systemd/optional-report-refresh.conf` to:

```text
/etc/systemd/system/field-discovery-nmap-import.service.d/report-refresh.conf
```

Then run `systemctl daemon-reload`. The drop-in refreshes the report after every
import pass. Its command is prefixed with `-`, so a report failure cannot prevent
future nmap artifact imports. CodexNet does not upload the resulting report.

## Installation and rollback

After installing the application, copy the importer units without enabling them, review the
service sandbox, then explicitly enable only the import timer:

```bash
sudo /opt/field-discovery/packaging/install/install-nmap-import-service.sh /opt/field-discovery
sudo systemd-analyze verify /usr/lib/systemd/system/field-discovery-nmap-import.service /usr/lib/systemd/system/field-discovery-nmap-import.timer
sudo systemctl enable --now field-discovery-nmap-import.timer
```

The installer never enables or starts a unit and supplies no nmap scan service or timer. The
protected script, cron, result tree, and Scanopy remain untouched. Full install and rollback steps
are in [installation.md](installation.md).
