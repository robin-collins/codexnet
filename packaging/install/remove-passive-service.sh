#!/bin/sh
set -eu

root=${DESTDIR:-}
if [ -z "$root" ] && [ "$(id -u)" -ne 0 ]; then
    echo "remove-passive-service: must run as root" >&2
    exit 1
fi

if [ -z "$root" ]; then
    systemctl disable --now field-discovery-passive.service || true
fi

rm -f "$root/usr/lib/systemd/system/field-discovery-passive.service"
rm -f "$root/usr/lib/sysusers.d/field-discovery.conf"

if [ -z "$root" ]; then
    systemctl daemon-reload
fi

echo "Passive service removed; configuration, database, reports, and service account retained."
