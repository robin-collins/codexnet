#!/bin/sh
set -eu

root=${DESTDIR:-}
if [ -z "$root" ] && [ "$(id -u)" -ne 0 ]; then
    echo "remove-codexnet-services: must run as root" >&2
    exit 1
fi

units="field-discovery-passive.service field-discovery-nmap-import.timer field-discovery-nmap-import.service field-discovery-backup.timer field-discovery-backup.service field-discovery-recovery.service"

if [ -z "$root" ]; then
    for unit in $units; do
        systemctl disable --now "$unit" || true
    done
fi

for unit in $units; do
    rm -f "$root/usr/lib/systemd/system/$unit"
done
rm -f "$root/usr/lib/sysusers.d/field-discovery.conf"

if [ -z "$root" ]; then
    systemctl daemon-reload
fi

echo "CodexNet services removed; account, configuration, database, reports, artifacts, and backups retained."
