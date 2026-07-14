#!/bin/sh
set -eu

root=${DESTDIR:-}
if [ -z "$root" ] && [ "$(id -u)" -ne 0 ]; then
    echo "install-nmap-import-service: must run as root" >&2
    exit 1
fi

project=${1:-.}
unit_dir="$root/usr/lib/systemd/system"
install -d -m 0755 "$unit_dir"
for unit in \
    field-discovery-nmap-import.service \
    field-discovery-nmap-import.timer
do
    install -m 0644 "$project/packaging/systemd/$unit" "$unit_dir/$unit"
done

if [ -z "$root" ]; then
    systemctl daemon-reload
fi

echo "Nmap import units installed but not enabled or started; no scan was scheduled."
