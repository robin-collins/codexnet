"""Offline SSH adapter, allowlist, artifact, and failure-matrix tests."""

from __future__ import annotations

import asyncio
import json
import stat
import subprocess
import sys
import types
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from field_discovery.artifacts import ArtifactStore, audit_outputs
from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CredentialReference,
    RetryableCollectorError,
)
from field_discovery.redaction import Redactor
from field_discovery.repository import Repository
from field_discovery.ssh_collection import (
    COMMAND_PROFILES,
    MAX_SECRET_BYTES,
    CommandRejectedError,
    ConfigSecretResolver,
    NetmikoSessionFactory,
    NetworkDeviceSSHCollector,
    SSHCollectionError,
    SSHSession,
    UnknownPlatformError,
    _credential_profile,
    approved_commands,
    require_approved_command,
    select_platform,
)

NOW = datetime(2026, 7, 15, 1, 2, 3, tzinfo=UTC)
REFERENCE = CredentialReference("fixture", "SSH_PROFILE")


class FixtureResolver:
    def __init__(self, profile: Mapping[str, str] | BaseException | None = None) -> None:
        self.profile = profile or {"username": "operator", "password": "synthetic-secret"}
        self.references: list[CredentialReference] = []

    def resolve(self, reference: CredentialReference) -> Mapping[str, str]:
        self.references.append(reference)
        if isinstance(self.profile, BaseException):
            raise self.profile
        return self.profile


class FixtureSession:
    def __init__(self, actions: Mapping[str, object] | None = None) -> None:
        self.actions = actions or {}
        self.calls: list[tuple[str, bool]] = []
        self.closed = False

    async def run(self, command: str, *, structured: bool) -> object:
        self.calls.append((command, structured))
        action = self.actions.get(command, [{"field": command, "password": "synthetic-secret"}])
        if isinstance(action, BaseException):
            raise action
        return action

    async def close(self) -> None:
        self.closed = True


class FixtureFactory:
    def __init__(self, session: FixtureSession | BaseException) -> None:
        self.session = session
        self.calls: list[tuple[str, str, Mapping[str, str], str]] = []

    async def connect(
        self,
        target: str,
        platform: str,
        credential: Mapping[str, str],
        *,
        host_key_policy: str,
    ) -> SSHSession:
        self.calls.append((target, platform, credential, host_key_policy))
        if isinstance(self.session, BaseException):
            raise self.session
        return self.session


def setup(tmp_path: Path) -> tuple[Repository, int, ArtifactStore]:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    repository = Repository.open(
        root / "discovery.db", data_root=root, redactor=Redactor(["synthetic-secret"])
    )
    deployment = repository.upsert_deployment("fixture", "Fixture", NOW.isoformat())
    store = ArtifactStore(root / "artifacts" / "ssh", redactor=repository.redactor)
    return repository, deployment, store


def context(*, credential: CredentialReference | None = REFERENCE) -> CollectorContext:
    return CollectorContext("192.168.50.20", credential, asyncio.Event())


@pytest.mark.parametrize(
    ("explicit", "evidence", "expected"),
    [
        ("Cisco", (), "cisco_ios"),
        ("ios", (), "cisco_ios"),
        ("HPE", (), "hp_comware"),
        ("comware", (), "hp_comware"),
        ("Aruba", (), "aruba_aos"),
        ("procurve", (), "aruba_aos"),
        (None, ("Cisco IOS-XE Software",), "cisco_ios"),
        (None, ("H3C Comware 7",), "hp_comware"),
        (None, ("ArubaOS-Switch",), "aruba_aos"),
    ],
)
def test_platform_selection_is_explicit_or_unambiguous(
    explicit: str | None, evidence: Sequence[str], expected: str
) -> None:
    assert select_platform(explicit=explicit, evidence=evidence) == expected


@pytest.mark.parametrize(
    ("explicit", "evidence"),
    [
        ("unknown", ()),
        (None, ()),
        (None, ("generic switch",)),
        (None, ("Cisco IOS with Aruba management",)),
    ],
)
def test_unknown_or_ambiguous_platform_is_rejected(
    explicit: str | None, evidence: Sequence[str]
) -> None:
    with pytest.raises(UnknownPlatformError, match="platform"):
        select_platform(explicit=explicit, evidence=evidence)
    with pytest.raises(UnknownPlatformError, match="supported"):
        approved_commands("unknown")


@pytest.mark.parametrize("platform", sorted(COMMAND_PROFILES))
def test_allowlist_accepts_only_exact_audited_commands(platform: str) -> None:
    commands = approved_commands(platform)
    assert COMMAND_PROFILES[platform].paging_command in commands
    for command in commands:
        assert require_approved_command(platform, command) == command
    for rejected in (
        "configure terminal",
        "conf t",
        "write memory",
        "copy running-config startup-config",
        "show running-config",
        "reload",
        commands[-1] + " ",
        "",
    ):
        with pytest.raises(CommandRejectedError, match="allowlist"):
            require_approved_command(platform, rejected)
    with pytest.raises(CommandRejectedError):
        require_approved_command(platform, cast(str, None))


@pytest.mark.parametrize("platform", sorted(COMMAND_PROFILES))
def test_each_vendor_collects_structured_facts_and_sanitized_artifacts(
    tmp_path: Path, platform: str
) -> None:
    repository, deployment, store = setup(tmp_path)
    session = FixtureSession()
    factory = FixtureFactory(session)
    resolver = FixtureResolver()
    collector = NetworkDeviceSSHCollector(
        repository,
        deployment,
        store,
        factory,
        resolver,
        platform=platform,
        host_key_policy="strict",
        clock=lambda: NOW,
    )
    result = asyncio.run(collector.collect(context()))
    assert result.item_count == len(COMMAND_PROFILES[platform].commands)
    assert not result.issues
    assert session.calls[0] == (COMMAND_PROFILES[platform].paging_command, False)
    assert all(structured for _command, structured in session.calls[1:])
    assert session.closed
    assert factory.calls[0][0:2] == ("192.168.50.20", platform)
    assert factory.calls[0][3] == "strict"
    assert resolver.references == [REFERENCE]
    artifacts = list((store.root).glob("*.txt"))
    assert len(artifacts) == len(COMMAND_PROFILES[platform].commands)
    assert audit_outputs([store.root], redactor=repository.redactor) == []
    assert repository.connection.execute("SELECT count(*) FROM artifacts").fetchone()[0] == len(
        artifacts
    )
    assert repository.connection.execute("SELECT count(*) FROM observations").fetchone()[0] == len(
        artifacts
    )
    repository.close()


def test_parse_fallback_paging_and_partial_output_remain_visible(tmp_path: Path) -> None:
    repository, deployment, store = setup(tmp_path)
    profile = COMMAND_PROFILES["cisco_ios"]
    actions: dict[str, object] = {
        profile.commands[0]: "Version secret password=synthetic-secret --More-- next",
        profile.commands[1]: object(),
        profile.commands[2]: [{"port": "Gi1/0/1"}, {"port": "Gi1/0/2"}],
    }
    session = FixtureSession(actions)
    collector = NetworkDeviceSSHCollector(
        repository,
        deployment,
        store,
        FixtureFactory(session),
        FixtureResolver(),
        platform="cisco",
        clock=lambda: NOW,
    )
    result = asyncio.run(collector.collect(context()))
    categories = [issue.category for issue in result.issues]
    assert categories == ["ssh_parse_fallback", "ssh_paging", "ssh_command"]
    assert result.item_count == len(profile.commands)
    raw = (sorted(store.root.glob("*.txt"))[0]).read_text()
    assert "synthetic-secret" not in raw
    assert "[PAGING]" in raw
    assert session.closed
    repository.close()


@pytest.mark.parametrize(
    "failure",
    [
        CollectorAuthenticationError("secret must not escape"),
        RetryableCollectorError("SSH connection timed out"),
    ],
)
def test_connection_auth_and_timeout_fail_without_artifacts(
    tmp_path: Path, failure: BaseException
) -> None:
    repository, deployment, store = setup(tmp_path)
    collector = NetworkDeviceSSHCollector(
        repository,
        deployment,
        store,
        FixtureFactory(failure),
        FixtureResolver(),
        platform="cisco",
        clock=lambda: NOW,
    )
    with pytest.raises(type(failure)):
        asyncio.run(collector.collect(context()))
    assert not list(store.root.glob("*.txt"))
    repository.close()


def test_command_timeout_closes_session_and_missing_credentials_are_rejected(
    tmp_path: Path,
) -> None:
    repository, deployment, store = setup(tmp_path)
    command = COMMAND_PROFILES["cisco_ios"].commands[0]
    session = FixtureSession({command: RetryableCollectorError("SSH command timed out")})
    collector = NetworkDeviceSSHCollector(
        repository,
        deployment,
        store,
        FixtureFactory(session),
        FixtureResolver(),
        platform="cisco",
        clock=lambda: NOW,
    )
    with pytest.raises(RetryableCollectorError):
        asyncio.run(collector.collect(context()))
    assert session.closed
    with pytest.raises(SSHCollectionError, match="explicit credential"):
        asyncio.run(collector.collect(context(credential=None)))
    repository.close()


def test_cancellation_is_checked_between_commands(tmp_path: Path) -> None:
    repository, deployment, store = setup(tmp_path)
    session = FixtureSession()
    collector = NetworkDeviceSSHCollector(
        repository,
        deployment,
        store,
        FixtureFactory(session),
        FixtureResolver(),
        platform="cisco",
        clock=lambda: NOW,
    )
    cancelled = context()
    cancelled.cancellation.set()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(collector.collect(cancelled))
    assert session.closed
    repository.close()


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "[]",
        '{"username":1,"password":"x"}',
        '{"username":"u","password":"p","extra":"x"}',
        '{"username":"","password":"p"}',
        '{"username":"u"}',
        '{"username":"u","password":"p","port":"bad"}',
        '{"username":"u","password":"p","port":"0"}',
        '{"username":"u","password":"p","port":"65536"}',
    ],
)
def test_credential_profile_validation_is_bounded_and_actionable(raw: str) -> None:
    with pytest.raises(SSHCollectionError, match="credential profile"):
        _credential_profile(raw)
    assert _credential_profile('{"username":"u","password":"p","port":"22"}')["port"] == "22"
    assert _credential_profile('{"username":"u","key_file":"/safe/key"}')["key_file"] == (
        "/safe/key"
    )


def test_env_file_secret_resolver_requires_restricted_valid_reference(tmp_path: Path) -> None:
    path = tmp_path / "secrets.env"
    profile = json.dumps({"username": "operator", "password": "synthetic-secret"})
    path.write_text(f"# fixture\nSSH_PROFILE={profile}\n")
    path.chmod(0o600)
    resolver = ConfigSecretResolver({"fixture": {"type": "env_file", "path": str(path)}})
    assert resolver.resolve(REFERENCE)["username"] == "operator"

    path.chmod(0o644)
    with pytest.raises(SSHCollectionError, match="0600"):
        resolver.resolve(REFERENCE)
    path.chmod(0o400)
    with pytest.raises(SSHCollectionError, match="0600"):
        resolver.resolve(REFERENCE)
    path.chmod(0o600)
    path.write_text("broken-line")
    with pytest.raises(SSHCollectionError, match="invalid line"):
        resolver.resolve(REFERENCE)
    path.write_text("OTHER=value")
    with pytest.raises(SSHCollectionError, match="not defined"):
        resolver.resolve(REFERENCE)
    path.write_bytes(b"x" * (MAX_SECRET_BYTES + 1))
    with pytest.raises(SSHCollectionError, match="size"):
        resolver.resolve(REFERENCE)
    path.unlink()
    with pytest.raises(SSHCollectionError, match="cannot be read"):
        resolver.resolve(REFERENCE)
    target = tmp_path / "target.env"
    target.write_text(f"SSH_PROFILE={profile}\n")
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(SSHCollectionError, match="regular"):
        resolver.resolve(REFERENCE)
    path.unlink()
    path.mkdir()
    path.chmod(0o600)
    with pytest.raises(SSHCollectionError, match="regular"):
        resolver.resolve(REFERENCE)


def test_command_secret_resolver_uses_stdin_and_maps_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider: dict[str, object] = {
        "type": "command",
        "executable": "/fixture/helper",
        "timeout_seconds": 2,
    }
    resolver = ConfigSecretResolver({"fixture": provider})
    profile = json.dumps({"username": "operator", "password": "synthetic-secret"})
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def successful(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(["/fixture/helper"], 0, profile, "")

    monkeypatch.setattr(subprocess, "run", successful)
    assert resolver.resolve(REFERENCE)["username"] == "operator"
    assert calls[0][1]["input"] == "SSH_PROFILE\n"
    assert calls[0][0][0] == ["/fixture/helper"]

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(["helper"], 1, "", "private"),
    )
    with pytest.raises(SSHCollectionError, match="rejected"):
        resolver.resolve(REFERENCE)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["helper"], 0, "x" * (MAX_SECRET_BYTES + 1), ""
        ),
    )
    with pytest.raises(SSHCollectionError, match="size"):
        resolver.resolve(REFERENCE)
    monkeypatch.setattr(
        subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())
    )
    with pytest.raises(SSHCollectionError, match="failed"):
        resolver.resolve(REFERENCE)
    provider["timeout_seconds"] = "bad"
    with pytest.raises(SSHCollectionError, match="timeout"):
        resolver.resolve(REFERENCE)


def test_secret_resolver_rejects_missing_or_unknown_provider() -> None:
    resolver = ConfigSecretResolver({})
    with pytest.raises(SSHCollectionError, match="unavailable"):
        resolver.resolve(REFERENCE)
    resolver = ConfigSecretResolver({"fixture": {"type": "vault"}})
    with pytest.raises(SSHCollectionError, match="unsupported"):
        resolver.resolve(REFERENCE)


class FakeConnection:
    def __init__(self, action: object = "raw") -> None:
        self.action = action
        self.calls: list[tuple[str, bool, int]] = []
        self.disconnected = False

    def send_command(self, command: str, *, use_textfsm: bool, read_timeout: int) -> object:
        self.calls.append((command, use_textfsm, read_timeout))
        if isinstance(self.action, BaseException):
            raise self.action
        return self.action

    def disconnect(self) -> None:
        self.disconnected = True


class NetMikoAuthenticationException(Exception):
    pass


class NetMikoTimeoutException(Exception):
    pass


def install_fake_netmiko(monkeypatch: pytest.MonkeyPatch, handler: object) -> types.ModuleType:
    module = types.ModuleType("netmiko")
    module.ConnectHandler = handler  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "netmiko", module)
    return module


def test_netmiko_adapter_passes_in_memory_profile_and_runs_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection([{"version": "fixture"}])
    parameters: dict[str, object] = {}

    def handler(**kwargs: object) -> FakeConnection:
        parameters.update(kwargs)
        return connection

    install_fake_netmiko(monkeypatch, handler)
    factory = NetmikoSessionFactory()
    profile = {
        "username": "operator",
        "password": "synthetic-secret",
        "key_file": "/fixture/key",
        "passphrase": "synthetic-passphrase",
        "port": "2222",
    }

    async def scenario() -> None:
        session = await factory.connect(
            "192.168.50.20", "cisco_ios", profile, host_key_policy="strict"
        )
        assert await session.run("show version", structured=True) == [{"version": "fixture"}]
        await session.close()

    asyncio.run(scenario())
    assert parameters["host"] == "192.168.50.20"
    assert parameters["device_type"] == "cisco_ios"
    assert parameters["password"] == "synthetic-secret"
    assert parameters["ssh_strict"] is True
    assert parameters["disabled_algorithms"] == {
        "keys": ["ssh-rsa"],
        "pubkeys": ["ssh-rsa"],
    }
    assert parameters["use_keys"] is True
    assert parameters["port"] == 2222
    assert connection.calls == [("show version", True, 20)]
    assert connection.disconnected


def test_netmiko_uses_non_privilege_escalating_aruba_channel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parameters: dict[str, object] = {}

    def handler(**kwargs: object) -> FakeConnection:
        parameters.update(kwargs)
        return FakeConnection()

    install_fake_netmiko(monkeypatch, handler)
    asyncio.run(
        NetmikoSessionFactory().connect(
            "192.168.50.20",
            "aruba_aos",
            {"username": "u", "password": "p"},
            host_key_policy="strict",
        )
    )
    assert parameters["device_type"] == "terminal_server"


def test_netmiko_strict_known_hosts_file_is_validated_before_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    def handler(**_kwargs: object) -> FakeConnection:
        nonlocal calls
        calls += 1
        return FakeConnection()

    install_fake_netmiko(monkeypatch, handler)
    base_profile = {"username": "u", "password": "p"}
    missing = tmp_path / "missing-known-hosts"
    with pytest.raises(SSHCollectionError, match="unavailable"):
        asyncio.run(
            NetmikoSessionFactory().connect(
                "192.0.2.1",
                "cisco_ios",
                {**base_profile, "known_hosts_file": str(missing)},
                host_key_policy="strict",
            )
        )

    regular = tmp_path / "known_hosts"
    regular.write_text("fixture.invalid ssh-rsa synthetic\n")
    monkeypatch.chdir(tmp_path)
    invalid_paths = ["known_hosts", str(tmp_path)]
    linked = tmp_path / "linked-known-hosts"
    linked.symlink_to(regular)
    invalid_paths.append(str(linked))
    for path in invalid_paths:
        with pytest.raises(SSHCollectionError, match="absolute regular non-symlink"):
            asyncio.run(
                NetmikoSessionFactory().connect(
                    "192.0.2.1",
                    "cisco_ios",
                    {**base_profile, "known_hosts_file": path},
                    host_key_policy="strict",
                )
            )
    assert calls == 0


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (NetMikoAuthenticationException(), CollectorAuthenticationError),
        (NetMikoTimeoutException(), RetryableCollectorError),
        (RuntimeError(), SSHCollectionError),
    ],
)
def test_netmiko_connect_failure_mapping(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException, expected: type[BaseException]
) -> None:
    def handler(**_kwargs: object) -> object:
        raise failure

    install_fake_netmiko(monkeypatch, handler)
    with pytest.raises(expected):
        asyncio.run(
            NetmikoSessionFactory().connect(
                "192.168.50.20",
                "cisco_ios",
                {"username": "u", "password": "p"},
                host_key_policy="accept-new",
            )
        )


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (NetMikoAuthenticationException(), CollectorAuthenticationError),
        (NetMikoTimeoutException(), RetryableCollectorError),
        (RuntimeError(), SSHCollectionError),
    ],
)
def test_netmiko_command_failure_mapping(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException, expected: type[BaseException]
) -> None:
    connection = FakeConnection(failure)
    install_fake_netmiko(monkeypatch, lambda **_kwargs: connection)

    async def scenario() -> None:
        session = await NetmikoSessionFactory().connect(
            "192.168.50.20",
            "cisco_ios",
            {"username": "u", "key_file": "/fixture/key"},
            host_key_policy="accept-new",
        )
        with pytest.raises(expected):
            await session.run("show version", structured=True)

    asyncio.run(scenario())


def test_netmiko_missing_dependency_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, "netmiko", raising=False)
    original_import = __import__

    def blocked(name: str, *args: object, **kwargs: object) -> object:
        if name == "netmiko":
            raise ImportError("fixture")
        return original_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("builtins.__import__", blocked)
    with pytest.raises(SSHCollectionError, match="not installed"):
        asyncio.run(
            NetmikoSessionFactory().connect(
                "192.168.50.20",
                "cisco_ios",
                {"username": "u", "password": "p"},
                host_key_policy="strict",
            )
        )


def test_oversized_output_is_partial_and_store_remains_bounded(tmp_path: Path) -> None:
    repository, deployment, store = setup(tmp_path)
    command = COMMAND_PROFILES["cisco_ios"].commands[0]
    session = FixtureSession({command: "x" * (4 * 1024 * 1024 + 1)})
    collector = NetworkDeviceSSHCollector(
        repository,
        deployment,
        store,
        FixtureFactory(session),
        FixtureResolver(),
        platform="cisco",
        clock=lambda: NOW,
    )
    result = asyncio.run(collector.collect(context()))
    assert result.issues[0].category == "ssh_command"
    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    repository.close()
