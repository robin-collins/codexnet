"""Read-only Cisco, HP, and Aruba SSH collection with injectable sessions."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from field_discovery.artifacts import ArtifactStore, safe_filename
from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CollectorError,
    CollectorIssue,
    CollectorResult,
    CredentialReference,
    RetryableCollectorError,
)
from field_discovery.repository import Repository

MAX_SECRET_BYTES = 65_536
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
_PAGING_MARKER = re.compile(
    r"(?:--\s*more\s*--|press\s+(?:any\s+key|space)|<---\s*more\s*--->)", re.I
)
_PLATFORM_ALIASES = {
    "cisco": "cisco_ios",
    "cisco_ios": "cisco_ios",
    "ios": "cisco_ios",
    "hp": "hp_comware",
    "hpe": "hp_comware",
    "hp_comware": "hp_comware",
    "comware": "hp_comware",
    "aruba": "aruba_aos",
    "aruba_aos": "aruba_aos",
    "arubaos-switch": "aruba_aos",
    "procurve": "aruba_aos",
}
_NETMIKO_DEVICE_TYPES = {
    "cisco_ios": "cisco_ios",
    "hp_comware": "hp_comware",
    "aruba_aos": "aruba_os",
}


class SSHCollectionError(CollectorError):
    """A safe, secret-free SSH collection failure."""


class UnknownPlatformError(SSHCollectionError):
    """Available evidence cannot identify exactly one supported platform."""


class CommandRejectedError(SSHCollectionError):
    """A command was not an exact member of the read-only platform allowlist."""


class SSHSession(Protocol):
    """Small async boundary implemented by Netmiko or fixture sessions."""

    async def run(self, command: str, *, structured: bool) -> object:
        """Run one already-approved command and return structured or raw output."""

    async def close(self) -> None:
        """Close transport resources without changing the target."""


class SSHSessionFactory(Protocol):
    """Create one authenticated session without placing credentials in argv."""

    async def connect(
        self,
        target: str,
        platform: str,
        credential: Mapping[str, str],
        *,
        host_key_policy: str,
    ) -> SSHSession:
        """Open a bounded network-device session."""


class SecretResolver(Protocol):
    """Resolve an opaque reference to a bounded JSON credential profile."""

    def resolve(self, reference: CredentialReference) -> Mapping[str, str]:
        """Return an in-memory profile; callers must never persist or log it."""


@dataclass(frozen=True)
class CommandProfile:
    """One vendor's paging setup and exact read-only operational commands."""

    paging_command: str
    commands: tuple[str, ...]


COMMAND_PROFILES: dict[str, CommandProfile] = {
    "cisco_ios": CommandProfile(
        "terminal length 0",
        (
            "show version",
            "show inventory",
            "show interfaces status",
            "show interfaces",
            "show vlan brief",
            "show mac address-table",
            "show ip arp",
            "show lldp neighbors detail",
            "show cdp neighbors detail",
            "show power inline",
            "show environment all",
        ),
    ),
    "hp_comware": CommandProfile(
        "screen-length disable",
        (
            "display version",
            "display device manuinfo",
            "display interface brief",
            "display interface",
            "display vlan all",
            "display mac-address",
            "display arp",
            "display lldp neighbor-information verbose",
            "display poe device",
            "display environment",
        ),
    ),
    "aruba_aos": CommandProfile(
        "no page",
        (
            "show system",
            "show version",
            "show modules",
            "show interfaces brief",
            "show interfaces",
            "show vlans",
            "show mac-address",
            "show arp",
            "show lldp info remote-device detail",
            "show power-over-ethernet brief",
            "show system temperature",
        ),
    ),
}


def select_platform(*, explicit: str | None = None, evidence: Sequence[str] = ()) -> str:
    """Select a supported platform only when explicit or unambiguous evidence exists."""
    if explicit is not None:
        selected = _PLATFORM_ALIASES.get(explicit.strip().casefold())
        if selected is None:
            raise UnknownPlatformError("explicit SSH platform is not supported")
        return selected
    matches: set[str] = set()
    for item in evidence:
        folded = item.casefold()
        if "cisco" in folded or re.search(r"\bios(?:-xe)?\b", folded):
            matches.add("cisco_ios")
        if "comware" in folded or "h3c" in folded:
            matches.add("hp_comware")
        if "aruba" in folded or "procurve" in folded or "arubaos-switch" in folded:
            matches.add("aruba_aos")
    if len(matches) != 1:
        raise UnknownPlatformError("SSH platform evidence is absent, ambiguous, or unsupported")
    return matches.pop()


def approved_commands(platform: str) -> tuple[str, ...]:
    """Expose the auditable exact allowlist including the session-only paging command."""
    try:
        profile = COMMAND_PROFILES[platform]
    except KeyError as exc:
        raise UnknownPlatformError("SSH platform is not supported") from exc
    return (profile.paging_command, *profile.commands)


def require_approved_command(platform: str, command: str) -> str:
    """Reject all free-form, configuration, write, and abbreviated commands."""
    if not isinstance(command, str) or command not in approved_commands(platform):
        raise CommandRejectedError("SSH command is outside the exact read-only allowlist")
    return command


def _credential_profile(raw: str) -> Mapping[str, str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SSHCollectionError("referenced SSH credential profile is not valid JSON") from exc
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        raise SSHCollectionError("referenced SSH credential profile must be a string mapping")
    allowed = {"username", "password", "key_file", "passphrase", "port"}
    if set(value) - allowed or not value.get("username"):
        raise SSHCollectionError("referenced SSH credential profile has unsupported fields")
    if not value.get("password") and not value.get("key_file"):
        raise SSHCollectionError("referenced SSH credential profile lacks authentication material")
    if "port" in value:
        try:
            port = int(value["port"])
        except ValueError as exc:
            raise SSHCollectionError("referenced SSH credential profile port is invalid") from exc
        if not 1 <= port <= 65535:
            raise SSHCollectionError("referenced SSH credential profile port is invalid")
    return value


@dataclass(frozen=True)
class ConfigSecretResolver:
    """Resolve env-file or helper references without shell/argv secret exposure."""

    providers: Mapping[str, Mapping[str, object]]

    def resolve(self, reference: CredentialReference) -> Mapping[str, str]:
        provider = self.providers.get(reference.provider)
        if provider is None:
            raise SSHCollectionError("SSH credential provider is unavailable")
        provider_type = provider.get("type")
        if provider_type == "env_file":
            raw = self._from_env_file(Path(str(provider["path"])), reference.key)
        elif provider_type == "command":
            raw = self._from_command(provider, reference.key)
        else:  # guarded by configuration validation
            raise SSHCollectionError("SSH credential provider type is unsupported")
        return _credential_profile(raw)

    @staticmethod
    def _from_env_file(path: Path, key: str) -> str:
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise SSHCollectionError("SSH secret file must be regular and mode 0600")
            raw = path.read_bytes()
        except OSError as exc:
            raise SSHCollectionError("SSH secret file cannot be read") from exc
        if len(raw) > MAX_SECRET_BYTES:
            raise SSHCollectionError("SSH secret file exceeds the size limit")
        values: dict[str, str] = {}
        for line in raw.decode("utf-8").splitlines():
            if not line or line.lstrip().startswith("#"):
                continue
            name, separator, value = line.partition("=")
            if not separator:
                raise SSHCollectionError("SSH secret file contains an invalid line")
            values[name.strip()] = value.strip()
        if key not in values:
            raise SSHCollectionError("SSH credential reference is not defined")
        return values[key]

    @staticmethod
    def _from_command(provider: Mapping[str, object], key: str) -> str:
        timeout_value = provider.get("timeout_seconds", 5)
        if not isinstance(timeout_value, int):  # guarded by configuration validation
            raise SSHCollectionError("SSH secret helper timeout is invalid")
        try:
            completed = subprocess.run(
                [str(provider["executable"])],
                input=f"{key}\n",
                capture_output=True,
                text=True,
                timeout=timeout_value,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SSHCollectionError("SSH secret helper failed") from exc
        if completed.returncode != 0:
            raise SSHCollectionError("SSH secret helper rejected the reference")
        if len(completed.stdout.encode()) > MAX_SECRET_BYTES:
            raise SSHCollectionError("SSH secret helper output exceeds the size limit")
        return completed.stdout.strip()


class _NetmikoSession:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    async def run(self, command: str, *, structured: bool) -> object:
        try:
            return await asyncio.to_thread(
                self._connection.send_command,
                command,
                use_textfsm=structured,
                read_timeout=20,
            )
        except Exception as exc:
            name = type(exc).__name__.casefold()
            if "auth" in name:
                raise CollectorAuthenticationError(
                    "referenced SSH credential was rejected"
                ) from exc
            if "timeout" in name:
                raise RetryableCollectorError("SSH command timed out") from exc
            raise SSHCollectionError("SSH command transport failed") from exc

    async def close(self) -> None:
        await asyncio.to_thread(self._connection.disconnect)


class NetmikoSessionFactory:
    """Dependency-safe Netmiko adapter; imported only for an actual SSH collection."""

    async def connect(
        self,
        target: str,
        platform: str,
        credential: Mapping[str, str],
        *,
        host_key_policy: str,
    ) -> SSHSession:
        try:
            from netmiko import ConnectHandler  # type: ignore[import-not-found,unused-ignore]
        except ImportError as exc:
            raise SSHCollectionError("Netmiko SSH support is not installed") from exc
        parameters: dict[str, object] = {
            "device_type": _NETMIKO_DEVICE_TYPES[platform],
            "host": target,
            "username": credential["username"],
            "timeout": 20,
            "auth_timeout": 20,
            "banner_timeout": 20,
            "ssh_strict": host_key_policy == "strict",
        }
        if credential.get("password"):
            parameters["password"] = credential["password"]
        if credential.get("key_file"):
            parameters.update(
                {
                    "use_keys": True,
                    "key_file": credential["key_file"],
                    "passphrase": credential.get("passphrase"),
                }
            )
        if credential.get("port"):
            parameters["port"] = int(credential["port"])
        try:
            connection = await asyncio.to_thread(ConnectHandler, **parameters)
        except Exception as exc:
            name = type(exc).__name__.casefold()
            if "auth" in name:
                raise CollectorAuthenticationError(
                    "referenced SSH credential was rejected"
                ) from exc
            if "timeout" in name:
                raise RetryableCollectorError("SSH connection timed out") from exc
            raise SSHCollectionError("SSH connection failed") from exc
        return _NetmikoSession(connection)


@dataclass
class NetworkDeviceSSHCollector:
    """Collect approved operational facts and sanitized raw artifacts from one target."""

    repository: Repository
    deployment_id: int
    artifact_store: ArtifactStore
    session_factory: SSHSessionFactory
    secret_resolver: SecretResolver
    platform: str | None = None
    evidence: Sequence[str] = ()
    host_key_policy: str = "strict"
    retention: timedelta = timedelta(days=30)
    clock: Any = lambda: datetime.now(UTC)
    name: str = "ssh"

    async def collect(self, context: CollectorContext) -> CollectorResult:
        if context.credential_ref is None:
            raise SSHCollectionError("SSH collection requires an explicit credential reference")
        platform = select_platform(explicit=self.platform, evidence=self.evidence)
        credential = self.secret_resolver.resolve(context.credential_ref)
        session = await self.session_factory.connect(
            context.target,
            platform,
            credential,
            host_key_policy=self.host_key_policy,
        )
        item_count = 0
        issues: list[CollectorIssue] = []
        try:
            paging = COMMAND_PROFILES[platform].paging_command
            await session.run(require_approved_command(platform, paging), structured=False)
            for index, command in enumerate(COMMAND_PROFILES[platform].commands):
                if context.cancellation.is_set():
                    raise asyncio.CancelledError
                try:
                    output = await session.run(
                        require_approved_command(platform, command), structured=True
                    )
                    count, command_issues = self._persist_output(
                        context.target, platform, command, output, index=index
                    )
                    item_count += count
                    issues.extend(command_issues)
                except (CollectorAuthenticationError, RetryableCollectorError):
                    raise
                except SSHCollectionError as exc:
                    issues.append(CollectorIssue("ssh_command", str(exc)))
        finally:
            await session.close()
        return CollectorResult(item_count, tuple(issues))

    def _persist_output(
        self, target: str, platform: str, command: str, output: object, *, index: int
    ) -> tuple[int, list[CollectorIssue]]:
        observed = self.clock().astimezone(UTC)
        if isinstance(output, str):
            payload = output
            parsed: object = {"raw_artifact_only": True}
            issues = [CollectorIssue("ssh_parse_fallback", f"no structured parser for {command}")]
        elif isinstance(output, dict | list):
            payload = json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            parsed = output
            issues = []
        else:
            raise SSHCollectionError("SSH parser returned an unsupported result type")
        encoded = payload.encode("utf-8", errors="replace")
        if len(encoded) > MAX_COMMAND_OUTPUT_BYTES:
            raise SSHCollectionError("SSH command output exceeds the artifact size limit")
        if _PAGING_MARKER.search(payload):
            issues.append(CollectorIssue("ssh_paging", f"paging marker remained for {command}"))
            payload = _PAGING_MARKER.sub("[PAGING]", payload)
        digest = hashlib.sha256(
            f"{target}|{platform}|{command}|{observed.isoformat()}".encode()
        ).hexdigest()[:12]
        filename = safe_filename(f"{index:02d}-{platform}-{digest}", suffix=".txt")
        metadata = self.artifact_store.write_text(
            filename,
            payload,
            category="ssh",
            retention=self.retention,
            now=observed,
        )
        relative_path = f"ssh/{metadata.filename}"
        self.repository.register_artifact(
            deployment_id=self.deployment_id,
            collector_run_id=None,
            relative_path=relative_path,
            sha256_digest=metadata.sha256,
            media_type=metadata.media_type,
            size_bytes=metadata.size_bytes,
            collected_at=metadata.created_at,
            imported_at=metadata.created_at,
            source=f"ssh:{platform}",
            observed_at=metadata.created_at,
        )
        self.repository.record_observation(
            self.deployment_id,
            subject_type="network_device_target",
            subject_id=None,
            fact_type=f"ssh.{_command_fact(command)}",
            fact_value={
                "target": target,
                "command": command,
                "value": parsed,
                "artifact": relative_path,
            },
            confidence=0.9 if not issues else 0.6,
            inferred=False,
            source=f"ssh:{platform}",
            observed_at=metadata.created_at,
        )
        count = len(output) if isinstance(output, list) else 1
        return count, issues


def _command_fact(command: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", command.casefold()).strip("_")[:80]
