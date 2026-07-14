#!/bin/sh
set -eu

root=${DESTDIR:-}
if [ -z "$root" ] && [ "$(id -u)" -ne 0 ]; then
    echo "install-passive-service: must run as root" >&2
    exit 1
fi

project=${1:-.}

install -d -m 0755 "$root/usr/lib/sysusers.d" "$root/usr/lib/systemd/system"
install -m 0644 "$project/packaging/sysusers.d/field-discovery.conf" \
    "$root/usr/lib/sysusers.d/field-discovery.conf"
install -m 0644 "$project/packaging/systemd/field-discovery-passive.service" \
    "$root/usr/lib/systemd/system/field-discovery-passive.service"

if [ -z "$root" ]; then
    systemd-sysusers /usr/lib/sysusers.d/field-discovery.conf
    install -d -o field-discovery -g field-discovery -m 0750 /var/lib/field-discovery
    systemctl daemon-reload
fi

echo "Passive service files installed but not enabled or started."
