"""T603 scheduled backup, boot recovery, and protected uninstall tests."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
SYSTEMD = ROOT / "packaging" / "systemd"
INSTALL = ROOT / "packaging" / "install" / "install-maintenance-services.sh"
REMOVE = ROOT / "packaging" / "install" / "remove-codexnet-services.sh"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_backup_timer_and_recovery_order_are_restart_safe(tmp_path: Path) -> None:
    backup = (SYSTEMD / "field-discovery-backup.service").read_text()
    timer = (SYSTEMD / "field-discovery-backup.timer").read_text()
    recovery = (SYSTEMD / "field-discovery-recovery.service").read_text()
    passive = (SYSTEMD / "field-discovery-passive.service").read_text()
    importer = (SYSTEMD / "field-discovery-nmap-import.service").read_text()
    assert " db backup" in backup and "TimeoutStartSec=10min" in backup
    assert "User=field-discovery" in backup and "RestrictAddressFamilies=AF_UNIX" in backup
    assert (
        "CapabilityBoundingSet=\n" in backup and "ReadWritePaths=/var/lib/field-discovery" in backup
    )
    assert "OnCalendar=daily" in timer and "Persistent=true" in timer
    assert "RandomizedDelaySec=1h" in timer and "WantedBy=timers.target" in timer
    assert "db recover --confirm-stopped" in recovery and "RemainAfterExit=true" in recovery
    for name in (
        "field-discovery-passive.service",
        "field-discovery-nmap-import.service",
        "field-discovery-backup.service",
    ):
        assert name in recovery.split("Before=", 1)[1].splitlines()[0]
    assert "After=network-online.target field-discovery-recovery.service" in passive
    assert "After=network-online.target field-discovery-recovery.service" in importer
    combined = backup + timer + recovery
    assert "scan nmap" not in combined and "network-discovery-scan.sh" not in combined

    analyzer = shutil.which("systemd-analyze")
    if analyzer is not None:
        for name in ("field-discovery-backup.service", "field-discovery-recovery.service"):
            target = tmp_path / name
            target.write_text(
                (SYSTEMD / name)
                .read_text()
                .replace(
                    next(
                        line
                        for line in (SYSTEMD / name).read_text().splitlines()
                        if line.startswith("ExecStart=")
                    ),
                    "ExecStart=/bin/true",
                )
            )
        result = subprocess.run(
            [
                analyzer,
                "verify",
                str(tmp_path / "field-discovery-backup.service"),
                str(tmp_path / "field-discovery-recovery.service"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr


def test_staged_install_and_uninstall_preserve_protected_state(tmp_path: Path) -> None:
    for script in (INSTALL, REMOVE):
        assert stat.S_IMODE(script.stat().st_mode) == 0o755
        subprocess.run(["sh", "-n", str(script)], check=True)
    environment = {**os.environ, "DESTDIR": str(tmp_path)}
    installed = subprocess.run(
        [str(INSTALL), str(ROOT)], env=environment, capture_output=True, text=True, check=False
    )
    assert installed.returncode == 0 and "not enabled or started" in installed.stdout
    for name in (
        "field-discovery-backup.service",
        "field-discovery-backup.timer",
        "field-discovery-recovery.service",
    ):
        assert (tmp_path / "usr/lib/systemd/system" / name).is_file()

    protected = (
        tmp_path / "usr/local/sbin/network-discovery-scan.sh",
        tmp_path / "var/log/network-discovery/result.xml",
        tmp_path / "var/lib/scanopy/state",
        tmp_path / "etc/crontab",
    )
    for index, path in enumerate(protected):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"protected-{index}")
    before = {str(path): digest(path) for path in protected}
    removed = subprocess.run(
        [str(REMOVE)], env=environment, capture_output=True, text=True, check=False
    )
    assert removed.returncode == 0 and "retained" in removed.stdout
    assert before == {str(path): digest(path) for path in protected}
    assert not (tmp_path / "usr/lib/systemd/system/field-discovery-backup.service").exists()
    text = REMOVE.read_text()
    assert "/usr/local" not in text and "/var/log/network-discovery" not in text
    assert "scanopy" not in text.casefold() and "docker" not in text.casefold()
