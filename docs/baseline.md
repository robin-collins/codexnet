# Appliance baseline

Recorded on 2026-07-14 (Australia/Adelaide) using read-only commands. This
document intentionally omits hostnames, IP and MAC addresses, routes, customer
identifiers, credentials, and application data.

## Platform

| Item | Observed value |
|---|---|
| Operating system | Debian GNU/Linux 13 (trixie), Debian 13.6 |
| Kernel | Linux 6.18.34+rpt-rpi-v8 |
| Architecture | `aarch64`, 64-bit |
| CPU availability | 4 logical CPUs |
| Python | 3.13.5 |
| Memory | 7.6 GiB total; 617 MiB used; 7.0 GiB available at capture |
| Swap | 2.0 GiB total; 0 used at capture |
| Root filesystem | ext4, 220 GiB total; 9.0 GiB used; 202 GiB available (5%) |
| Uptime | Approximately 2 hours at capture |
| systemd state | `degraded`; `smartmontools.service` was the only failed unit |

The selected customer-facing interface is `eth0`. It was up and was the source
interface for the default IPv4 route. Address and hardware identifiers are
deliberately not recorded. `wlan0` was down; Tailscale and Docker interfaces
were present and are not selected.

## Installed discovery and support tools

| Tool | Version/status |
|---|---|
| Git | 2.47.3 |
| GitHub CLI | 2.46.0 |
| Nmap | 7.95 |
| Docker Engine | 29.6.1 |
| SQLite | 3.46.1 |
| systemd | 257.13 |
| `iproute2` (`ip`) | installed |
| cron (`crontab`) | installed |
| Podman | not installed |

## Protected Scanopy state

Docker and containerd services were active and running. The three observed
Scanopy containers were running and healthy:

| Role | Image | Restart policy | Health |
|---|---|---|---|
| server | `ghcr.io/scanopy/scanopy/server:latest` | `unless-stopped` | healthy |
| database | `postgres:17-alpine` | `unless-stopped` | healthy |
| daemon | `ghcr.io/scanopy/scanopy/daemon:latest` | `unless-stopped` | healthy |

Only Docker status metadata was read. Scanopy's database and application data
were not accessed.

## Protected nmap script and schedule

The existing script was observed without reading or changing its contents:

| Item | Observed value |
|---|---|
| Path | `/usr/local/sbin/network-discovery-scan.sh` |
| SHA-256 | `09bfdfd6d034c38882dfddf7cb648d64fc326fcf164f4c68ae49cb103eb2e526` |
| Mode and owner | `0755`, `root:root` |
| Size | 9,018 bytes |
| Modification time | 2026-07-14 22:07:29 +09:30 |

No nmap schedule was found at capture time. Both `crontab -l` and
`sudo -n crontab -l` reported no crontab for `osit` and `root`, respectively.
A read-only search found no `network-discovery`, `network-discovery-scan`, or
`nmap` entry in `/etc/crontab`, `/etc/cron.d`, the standard periodic cron
directories, or `/var/spool/cron`. No matching systemd timer was listed.

`SPEC.md` and `AGENTS.md` now record this verified scheduling discrepancy.
Later gates must compare against the observed absence recorded here and must
not create, replace, or reschedule an active scan without explicit user
approval.

The initial restricted T000 execution view reported script ownership as
`nobody:nogroup`. A direct full-access `stat` during the G1 audit reported the
actual host ownership as `root:root`; checksum, size, mode, and nanosecond mtime
were identical. The ownership row above records the host value for subsequent
gates.

## Repeatable read-only checks

Run these on the appliance with sufficient read permissions. Do not redirect
output into protected/runtime locations.

```bash
cat /etc/os-release
uname -m
getconf LONG_BIT
python3 --version
git --version
gh --version
nmap --version
docker --version
sqlite3 --version
systemctl --version
ip -brief link
ip -brief -4 address
ip -4 route show default
systemctl is-system-running
systemctl --failed --no-pager --plain
systemctl list-units --type=service --all --no-pager --plain
docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}'
docker inspect --format '{{.Name}}|restart={{.HostConfig.RestartPolicy.Name}}|health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|status={{.State.Status}}' scanopy-server-1 scanopy-postgres-1 scanopy-daemon
stat -c '%n|mode=%a|owner=%U:%G|bytes=%s|mtime=%y' /usr/local/sbin/network-discovery-scan.sh
sha256sum /usr/local/sbin/network-discovery-scan.sh
crontab -l
sudo -n crontab -l
rg -n 'network-discovery|network-discovery-scan|nmap' /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron
systemctl list-timers --all --no-pager --plain
df -hPT /
free -h
uptime
nproc
```

Before saving output as evidence, remove interface addresses, MAC addresses,
routes, hostnames, customer labels, container environment, and secrets. At each
stage gate, repeat the script checksum, cron/timer search, and Scanopy container
health checks and compare them with this baseline.
