#!/bin/sh
set -eu

root=${DESTDIR:-}
if [ -z "$root" ] && [ "$(id -u)" -ne 0 ]; then
    echo "install-maintenance-services: must run as root" >&2
    exit 1
fi

project=${1:-.}
unit_dir="$root/usr/lib/systemd/system"
install -d -m 0755 "$unit_dir"
for unit in \
    field-discovery-backup.service \
    field-discovery-backup.timer \
    field-discovery-recovery.service
do
    install -m 0644 "$project/packaging/systemd/$unit" "$unit_dir/$unit"
done

if [ -z "$root" ]; then
    systemctl daemon-reload
fi

echo "Maintenance units installed but not enabled or started."
