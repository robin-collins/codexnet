#!/bin/sh
set -eu

root=${DESTDIR:-}
if [ -z "$root" ] && [ "$(id -u)" -ne 0 ]; then
    echo "install-scheduler-service: must run as root" >&2
    exit 1
fi

project=${1:-.}
unit_dir="$root/usr/lib/systemd/system"
install -d -m 0755 "$unit_dir"
install -m 0644 "$project/packaging/systemd/field-discovery-scheduler.service" \
    "$unit_dir/field-discovery-scheduler.service"

if [ -z "$root" ]; then
    systemctl daemon-reload
fi

echo "Collector scheduler unit installed but not enabled or started."
