"""Disposable loopback transport evidence for the Stage 4 collector gate."""

from __future__ import annotations

import asyncio
import importlib
import json
import socket
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from field_discovery.artifacts import ArtifactStore, audit_outputs
from field_discovery.collectors import (
    CollectorContext,
    CredentialReference,
    RetryableCollectorError,
)
from field_discovery.redaction import Redactor
from field_discovery.repository import Repository
from field_discovery.snmp import (
    OidField,
    PySnmpTransport,
    SnmpCollector,
    SnmpConfigurationError,
    SnmpV2cCredential,
)
from field_discovery.ssh_collection import (
    COMMAND_PROFILES,
    ConfigSecretResolver,
    NetmikoSessionFactory,
    NetworkDeviceSSHCollector,
    approved_commands,
)

NOW = datetime(2026, 7, 15, 5, 0, tzinfo=UTC)
LAB_COMMUNITY = "synthetic-lab-value"
LAB_SSH_PASSWORD = "synthetic-ssh-secret"


def _length(value: int) -> bytes:
    if value < 0x80:
        return bytes((value,))
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes((tag,)) + _length(len(value)) + value


def _read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, bytes, int]:
    start = offset
    if offset + 2 > len(data):
        raise ValueError("truncated TLV")
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("invalid TLV length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("truncated TLV value")
    return tag, data[offset:end], data[start:end], end


def _synthetic_v2c_response(request: bytes) -> bytes:
    """Return a minimal response preserving request IDs/OIDs, without an SNMP agent package."""
    message_tag, message, _raw, message_end = _read_tlv(request)
    if message_tag != 0x30 or message_end != len(request):
        raise ValueError("invalid SNMP message")
    _version_tag, _version, version_raw, offset = _read_tlv(message)
    _community_tag, _community, community_raw, offset = _read_tlv(message, offset)
    request_tag, request_pdu, _request_raw, offset = _read_tlv(message, offset)
    if request_tag != 0xA0 or offset != len(message):
        raise ValueError("expected one SNMP GetRequest")
    _id_tag, _request_id, request_id_raw, pdu_offset = _read_tlv(request_pdu)
    _error_tag, _error, _error_raw, pdu_offset = _read_tlv(request_pdu, pdu_offset)
    _index_tag, _index, _index_raw, pdu_offset = _read_tlv(request_pdu, pdu_offset)
    varbind_tag, varbinds, _varbinds_raw, pdu_offset = _read_tlv(request_pdu, pdu_offset)
    if varbind_tag != 0x30 or pdu_offset != len(request_pdu):
        raise ValueError("invalid SNMP variable bindings")

    response_varbinds = bytearray()
    varbind_offset = 0
    while varbind_offset < len(varbinds):
        varbind_item_tag, varbind, _item_raw, varbind_offset = _read_tlv(varbinds, varbind_offset)
        oid_tag, _oid, oid_raw, value_offset = _read_tlv(varbind)
        _value_tag, _value, _value_raw, value_offset = _read_tlv(varbind, value_offset)
        if varbind_item_tag != 0x30 or oid_tag != 0x06 or value_offset != len(varbind):
            raise ValueError("invalid SNMP variable binding")
        value = _tlv(0x04, b"password=" + LAB_COMMUNITY.encode("ascii"))
        response_varbinds.extend(_tlv(0x30, oid_raw + value))

    response_pdu = b"".join(
        (
            request_id_raw,
            _tlv(0x02, b"\x00"),
            _tlv(0x02, b"\x00"),
            _tlv(0x30, bytes(response_varbinds)),
        )
    )
    return _tlv(0x30, version_raw + community_raw + _tlv(0xA2, response_pdu))


@dataclass
class _LoopbackSnmpAgent(asyncio.DatagramProtocol):
    respond: bool = True
    requests: list[tuple[bytes, tuple[str, int]]] = field(default_factory=list)
    transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        self.requests.append((data, address))
        if self.respond and self.transport is not None:
            self.transport.sendto(_synthetic_v2c_response(data), address)


async def _bind_agent(
    *, respond: bool = True
) -> tuple[asyncio.DatagramTransport, _LoopbackSnmpAgent]:
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _LoopbackSnmpAgent(respond), local_addr=("127.0.0.1", 0)
    )
    return transport, protocol


class _LoopbackSshDevice:
    """One-connection synthetic Cisco-like shell, strictly local to this test process."""

    def __init__(self) -> None:
        self.paramiko: ModuleType = importlib.import_module("paramiko")
        self.host_key: Any = self.paramiko.RSAKey.generate(2048)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(0.25)
        self.port = int(self.listener.getsockname()[1])
        self.commands: list[str] = []
        self.errors: list[BaseException] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self.listener.close()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise AssertionError("loopback SSH device did not stop")
        if self.errors:
            raise self.errors[0]

    def _serve(self) -> None:
        client: socket.socket | None = None
        transport: Any = None
        try:
            while not self._stop.is_set():
                try:
                    client, address = self.listener.accept()
                    break
                except TimeoutError:
                    continue
            if client is None:
                return
            if address[0] != "127.0.0.1":
                raise AssertionError("non-loopback SSH peer refused")
            paramiko = self.paramiko
            shell_ready = threading.Event()

            class Server(paramiko.ServerInterface):  # type: ignore[misc,name-defined]
                def check_auth_password(self, username: str, password: str) -> int:
                    if username == "lab-reader" and password == LAB_SSH_PASSWORD:
                        return int(paramiko.AUTH_SUCCESSFUL)
                    return int(paramiko.AUTH_FAILED)

                def get_allowed_auths(self, username: str) -> str:
                    del username
                    return "password"

                def check_channel_request(self, kind: str, channel_id: int) -> int:
                    del channel_id
                    if kind == "session":
                        return int(paramiko.OPEN_SUCCEEDED)
                    return int(paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

                def check_channel_pty_request(self, *args: object) -> bool:
                    del args
                    return True

                def check_channel_shell_request(self, channel: object) -> bool:
                    del channel
                    shell_ready.set()
                    return True

            transport = paramiko.Transport(client)
            transport.add_server_key(self.host_key)
            transport.start_server(server=Server())
            channel = transport.accept(5)
            if channel is None or not shell_ready.wait(5):
                raise AssertionError("loopback SSH shell was not established")
            channel.settimeout(0.25)
            channel.send("lab-switch#")
            buffer = b""
            while not self._stop.is_set() and transport.is_active():
                try:
                    chunk = channel.recv(4096)
                except TimeoutError:
                    continue
                if not chunk:
                    break
                buffer += chunk.replace(b"\r", b"\n")
                while b"\n" in buffer:
                    raw_command, buffer = buffer.split(b"\n", 1)
                    command = raw_command.decode("utf-8", errors="replace").strip()
                    if not command:
                        channel.send("lab-switch#")
                        continue
                    self.commands.append(command)
                    if command not in approved_commands("cisco_ios"):
                        raise AssertionError(f"non-allowlisted SSH command: {command}")
                    if command == "show version":
                        output = "Cisco IOS Software, password=" + LAB_SSH_PASSWORD
                    else:
                        output = ""
                    channel.send(f"{command}\r\n{output}\r\nlab-switch#")
        except (OSError, EOFError) as exc:
            if not self._stop.is_set():
                self.errors.append(exc)
        except BaseException as exc:
            self.errors.append(exc)
        finally:
            if transport is not None:
                transport.close()
            if client is not None:
                client.close()


def test_real_loopback_snmp_transport_is_bounded_explicit_and_redacted(tmp_path: Path) -> None:
    async def scenario() -> None:
        socket_transport, agent = await _bind_agent()
        try:
            socket_name = socket_transport.get_extra_info("sockname")
            assert socket_name[0] == "127.0.0.1"
            port = int(socket_name[1])
            root = tmp_path / "data"
            root.mkdir()
            repository = Repository.open(root / "discovery.db", data_root=root)
            deployment = repository.upsert_deployment("loopback", "Synthetic lab", NOW.isoformat())
            secret_file = tmp_path / "secrets.env"
            secret_file.write_text("SNMP_LAB=" + json.dumps({"community": LAB_COMMUNITY}) + "\n")
            secret_file.chmod(0o600)
            collector = SnmpCollector(
                repository,
                deployment,
                protocol="v2c",
                allow_insecure_v2c=True,
                providers={"lab": {"type": "env_file", "path": str(secret_file)}},
                transport=PySnmpTransport(endpoint_port=port),
                registry=(OidField("1.3.6.1.2.1.1.1.0", "snmp.system.description"),),
                max_table_rows=1,
                timeout_seconds=0.25,
                clock=lambda: NOW,
            )
            result = await collector.collect(
                CollectorContext(
                    "127.0.0.1", CredentialReference("lab", "SNMP_LAB"), asyncio.Event()
                )
            )
            assert result.item_count == 1
            assert not result.issues
            assert len(agent.requests) == 1
            assert agent.requests[0][1][0] == "127.0.0.1"
            persisted = repository.connection.execute(
                "SELECT fact_value_json FROM observations WHERE fact_type = ?",
                ("snmp.system.description",),
            ).fetchone()[0]
            assert LAB_COMMUNITY not in persisted
            assert "[REDACTED]" in persisted
            repository.close()
        finally:
            socket_transport.close()

    asyncio.run(scenario())


def test_real_loopback_snmp_timeout_is_secret_free_and_port_is_validated() -> None:
    async def scenario() -> None:
        socket_transport, agent = await _bind_agent(respond=False)
        try:
            socket_name = socket_transport.get_extra_info("sockname")
            port = int(socket_name[1])
            with pytest.raises(RetryableCollectorError, match="did not respond") as failure:
                await PySnmpTransport(endpoint_port=port).collect(
                    "127.0.0.1",
                    SnmpV2cCredential(LAB_COMMUNITY),
                    scalar_oids=("1.3.6.1.2.1.1.1.0",),
                    table_oids=(),
                    max_table_rows=1,
                    timeout_seconds=0.05,
                    cancellation=asyncio.Event(),
                )
            assert LAB_COMMUNITY not in str(failure.value)
            assert len(agent.requests) == 1
        finally:
            socket_transport.close()

    asyncio.run(scenario())
    for port in (0, 65_536):
        with pytest.raises(SnmpConfigurationError, match="port"):
            PySnmpTransport(endpoint_port=port)


def test_real_loopback_netmiko_transport_is_read_only_and_redacted(tmp_path: Path) -> None:
    device = _LoopbackSshDevice()
    device.start()
    repository: Repository | None = None
    try:
        root = tmp_path / "ssh-data"
        root.mkdir()
        repository = Repository.open(
            root / "discovery.db", data_root=root, redactor=Redactor([LAB_SSH_PASSWORD])
        )
        deployment = repository.upsert_deployment("loopback", "Synthetic lab", NOW.isoformat())
        secret_file = tmp_path / "ssh-secrets.env"
        known_hosts = tmp_path / "known_hosts"
        known_hosts.write_text(
            f"[127.0.0.1]:{device.port} {device.host_key.get_name()} "
            f"{device.host_key.get_base64()}\n"
        )
        secret_file.write_text(
            "SSH_LAB="
            + json.dumps(
                {
                    "username": "lab-reader",
                    "password": LAB_SSH_PASSWORD,
                    "port": str(device.port),
                    "known_hosts_file": str(known_hosts),
                }
            )
            + "\n"
        )
        secret_file.chmod(0o600)
        store = ArtifactStore(root / "artifacts" / "ssh", redactor=repository.redactor)
        collector = NetworkDeviceSSHCollector(
            repository,
            deployment,
            store,
            NetmikoSessionFactory(),
            ConfigSecretResolver({"lab": {"type": "env_file", "path": str(secret_file)}}),
            platform="cisco_ios",
            host_key_policy="strict",
            clock=lambda: NOW,
        )
        result = asyncio.run(
            collector.collect(
                CollectorContext(
                    "127.0.0.1", CredentialReference("lab", "SSH_LAB"), asyncio.Event()
                )
            )
        )
        assert result.item_count == len(COMMAND_PROFILES["cisco_ios"].commands)
        assert set(COMMAND_PROFILES["cisco_ios"].commands) <= set(device.commands)
        # Netmiko's pinned Cisco session preparation sends only these two transient terminal
        # display controls before the collector's exact allowlisted operational commands.
        assert set(device.commands) <= set(approved_commands("cisco_ios"))
        assert not any(
            token in command.casefold()
            for command in device.commands
            for token in ("configure", "write", "copy", "reload", "running-config")
        )
        assert audit_outputs([root], redactor=repository.redactor) == []
        database_text = "\n".join(
            str(value)
            for row in repository.connection.execute(
                "SELECT fact_value_json FROM observations"
            ).fetchall()
            for value in row
        )
        assert LAB_SSH_PASSWORD not in database_text
    finally:
        if repository is not None:
            repository.close()
        device.close()
