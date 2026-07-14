"""T306 passive runtime and least-privilege packaging verification."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import socket
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from field_discovery.config import Configuration, ConfigurationError
from field_discovery.neighbor import NeighborTracker
from field_discovery.passive import PassiveFrame, PassiveObservation
from field_discovery.passive_service import (
    CDP_DESTINATION,
    CDP_SNAP,
    ETH_P_8021Q,
    ETH_P_ARP,
    ETH_P_IP,
    ETH_P_LLDP,
    MAX_CAPTURE_BYTES,
    KernelNeighborError,
    PacketSocketSource,
    _repository_sink,
    _run_bounded_command,
    build_pipeline,
    build_runtime,
    decode_ethernet,
    main,
    maintenance_loop,
    maintenance_once,
    observe,
    poll_kernel_neighbors,
    run_service,
)
from field_discovery.repository import Repository

ROOT = Path(__file__).parents[1]
UNIT = ROOT / "packaging/systemd/field-discovery-passive.service"
SYSUSERS = ROOT / "packaging/sysusers.d/field-discovery.conf"
INSTALL = ROOT / "packaging/install/install-passive-service.sh"
REMOVE = ROOT / "packaging/install/remove-passive-service.sh"
NOW = datetime(2026, 7, 15, 2, 0, tzinfo=UTC)


def _ethernet(
    protocol: int, payload: bytes, destination: bytes = b"\x02\x00\x00\x00\x00\x01"
) -> bytes:
    return destination + b"\x02\x00\x00\x00\x00\x02" + protocol.to_bytes(2, "big") + payload


def _udp_ipv4(source: int, destination: int, body: bytes, *, flags: int = 0) -> bytes:
    udp = struct_pack("!HHHH", source, destination, len(body) + 8, 0) + body
    total = 20 + len(udp)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = total.to_bytes(2, "big")
    ip[6:8] = flags.to_bytes(2, "big")
    ip[8] = 64
    ip[9] = socket.IPPROTO_UDP
    return bytes(ip) + udp


def struct_pack(format_string: str, *values: int) -> bytes:
    import struct

    return struct.pack(format_string, *values)


def _dns_name(value: str) -> bytes:
    return b"".join(bytes((len(label),)) + label.encode() for label in value.split(".")) + b"\0"


def _mdns_address(ttl: int = 1) -> bytes:
    name = _dns_name("silent.local")
    address = ipaddress.IPv4Address("192.0.2.88").packed
    record = name + struct_pack("!HHIH", 1, 0x8001, ttl, len(address)) + address
    return struct_pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + record


def test_ethernet_decoder_extracts_only_supported_passive_payloads() -> None:
    assert decode_ethernet(_ethernet(ETH_P_LLDP, b"lldp")) == ("lldp", b"lldp")
    assert decode_ethernet(_ethernet(ETH_P_ARP, b"arp")) == ("arp", b"arp")
    cdp = _ethernet(100, CDP_SNAP + b"cdp", CDP_DESTINATION)
    assert decode_ethernet(cdp) == ("cdp", b"cdp")
    vlan = _ethernet(ETH_P_8021Q, b"\x00\x01" + ETH_P_LLDP.to_bytes(2, "big") + b"v")
    assert decode_ethernet(vlan) == ("lldp", b"v")
    mdns = _ethernet(ETH_P_IP, _udp_ipv4(5353, 5353, b"dns"))
    dhcp = _ethernet(ETH_P_IP, _udp_ipv4(68, 67, b"bootp"))
    assert decode_ethernet(mdns) == ("mdns", b"dns")
    assert decode_ethernet(dhcp) == ("dhcp", b"bootp")


@pytest.mark.parametrize(
    "packet",
    [
        b"",
        b"x" * (MAX_CAPTURE_BYTES + 1),
        _ethernet(ETH_P_8021Q, b"x"),
        _ethernet(0x9999, b"ignored"),
        _ethernet(100, CDP_SNAP + b"x"),
        _ethernet(ETH_P_IP, b"short"),
        _ethernet(ETH_P_IP, b"\x65" + b"\x00" * 27),
        _ethernet(ETH_P_IP, b"\x44" + b"\x00" * 27),
        _ethernet(ETH_P_IP, _udp_ipv4(1, 2, b"x", flags=1)),
        _ethernet(ETH_P_IP, _udp_ipv4(1, 2, b"x")),
    ],
)
def test_ethernet_decoder_ignores_malformed_or_unrelated_packets(packet: bytes) -> None:
    assert decode_ethernet(packet) is None


def test_ipv4_udp_length_and_protocol_bounds() -> None:
    valid = bytearray(_udp_ipv4(5353, 5353, b"x"))
    variants: list[bytes] = []
    too_short_total = valid.copy()
    too_short_total[2:4] = (20).to_bytes(2, "big")
    variants.append(bytes(too_short_total))
    too_long_total = valid.copy()
    too_long_total[2:4] = (999).to_bytes(2, "big")
    variants.append(bytes(too_long_total))
    not_udp = valid.copy()
    not_udp[9] = socket.IPPROTO_TCP
    variants.append(bytes(not_udp))
    short_udp = valid.copy()
    short_udp[24:26] = (7).to_bytes(2, "big")
    variants.append(bytes(short_udp))
    long_udp = valid.copy()
    long_udp[24:26] = (999).to_bytes(2, "big")
    variants.append(bytes(long_udp))
    assert all(decode_ethernet(_ethernet(ETH_P_IP, item)) is None for item in variants)


class _FakeSocket:
    def __init__(self, *, fail_bind: bool = False) -> None:
        self.fail_bind = fail_bind
        self.blocking: bool | None = None
        self.bound: tuple[str, int] | None = None
        self.closed = False

    def setblocking(self, value: bool) -> None:
        self.blocking = value

    def bind(self, address: tuple[str, int]) -> None:
        if self.fail_bind:
            raise OSError("synthetic bind failure")
        self.bound = address

    def close(self) -> None:
        self.closed = True


def test_packet_source_opens_receive_socket_and_closes_on_bind_failure() -> None:
    created: list[tuple[int, int, int]] = []
    fake = _FakeSocket()

    def factory(family: int, kind: int, protocol: int) -> socket.socket:
        created.append((family, kind, protocol))
        return cast(socket.socket, fake)

    source = PacketSocketSource("eth-test", socket_factory=factory)
    assert created == [(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))]
    assert fake.blocking is False and fake.bound == ("eth-test", 0)
    source.close()
    assert fake.closed

    failing = _FakeSocket(fail_bind=True)
    with pytest.raises(OSError, match="synthetic"):
        PacketSocketSource("eth-test", socket_factory=lambda *_args: cast(socket.socket, failing))
    assert failing.closed


def test_packet_source_async_receive() -> None:
    async def scenario() -> None:
        receiving, sending = socket.socketpair()
        receiving.setblocking(False)
        source = PacketSocketSource.__new__(PacketSocketSource)
        source._socket = receiving
        sending.send(b"frame")
        assert await source.receive() == b"frame"
        source.close()
        sending.close()

    asyncio.run(scenario())


class _ReplaySource:
    def __init__(self, packets: list[bytes], stop: asyncio.Event, *, fail: bool = False) -> None:
        self.packets = packets
        self.stop = stop
        self.fail = fail
        self.closed = False

    async def receive(self) -> bytes:
        if self.fail:
            raise OSError("synthetic receive failure")
        if self.packets:
            return self.packets.pop(0)
        self.stop.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    def close(self) -> None:
        self.closed = True


def test_observer_replays_then_drains_and_closes() -> None:
    async def scenario() -> None:
        fixture = json.loads(
            (ROOT / "tests/fixtures/passive/link-layer.json").read_text(encoding="utf-8")
        )["generic_lldp"]
        packet = _ethernet(ETH_P_LLDP, bytes.fromhex(fixture["payload_hex"]))
        stop = asyncio.Event()
        source = _ReplaySource([b"ignored", packet], stop)
        output: list[PassiveObservation] = []

        async def sink(item: PassiveObservation) -> None:
            output.append(item)

        pipeline = build_pipeline(sink)
        await observe(source, pipeline, stop, interface="eth-test")
        assert source.closed
        assert len(output) == 1
        assert output[0].fields["system_name"] == "generic-switch"

        failed_source = _ReplaySource([], asyncio.Event(), fail=True)
        failed_pipeline = build_pipeline(sink)
        with pytest.raises(OSError, match="receive"):
            await observe(failed_source, failed_pipeline, failed_source.stop, interface="eth-test")
        assert failed_source.closed

    asyncio.run(scenario())


def _configuration(data_root: Path) -> dict[str, Any]:
    return {
        "interface": {"name": "eth-test"},
        "paths": {"data_root": str(data_root), "database": str(data_root / "discovery.db")},
    }


def test_repository_sink_records_only_structured_observation(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    repository = Repository.open(data_root / "discovery.db", data_root=data_root)
    deployment = repository.upsert_deployment("test", "Test", NOW.isoformat())
    observation = PassiveObservation(
        "test_fact",
        {"safe": "value"},
        "synthetic",
        observed_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
    )
    asyncio.run(_repository_sink(repository, deployment)(observation))
    asyncio.run(
        _repository_sink(repository, deployment)(
            PassiveObservation("current_fact", {"safe": "current"}, "synthetic", observed_at=NOW)
        )
    )
    row = repository.connection.execute(
        "SELECT fact_value_json FROM observations WHERE fact_type = 'test_fact'"
    ).fetchone()
    assert json.loads(row[0]) == {
        "safe": "value",
        "valid_until": (NOW + timedelta(seconds=30)).isoformat(),
    }
    current = repository.connection.execute(
        "SELECT fact_value_json FROM observations WHERE fact_type = 'current_fact'"
    ).fetchone()
    assert json.loads(current[0]) == {"safe": "current"}
    repository.close()


def test_run_service_marks_success_and_failure(tmp_path: Path) -> None:
    async def scenario() -> None:
        successful_root = tmp_path / "success"
        successful_root.mkdir()
        stop = asyncio.Event()
        stop.set()
        source = _ReplaySource([], stop)
        await run_service(
            _configuration(successful_root),
            source_factory=lambda _interface: source,
            stop_event=stop,
        )
        repository = Repository.open(successful_root / "discovery.db", data_root=successful_root)
        status = repository.connection.execute(
            "SELECT status FROM collector_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        repository.close()
        assert status == "succeeded"

        failed_root = tmp_path / "failed"
        failed_root.mkdir()
        with pytest.raises(OSError, match="factory"):
            await run_service(
                _configuration(failed_root),
                source_factory=lambda _interface: (_ for _ in ()).throw(OSError("factory")),
                stop_event=asyncio.Event(),
            )
        repository = Repository.open(failed_root / "discovery.db", data_root=failed_root)
        status = repository.connection.execute(
            "SELECT status FROM collector_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        repository.close()
        assert status == "failed"

    asyncio.run(scenario())


def test_run_service_registers_signals_when_event_not_injected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        data_root = tmp_path / "signals"
        data_root.mkdir()
        callbacks: list[Any] = []
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(
            loop, "add_signal_handler", lambda _signal, callback: callbacks.append(callback)
        )

        class SignallingSource:
            closed = False

            async def receive(self) -> bytes:
                callbacks[0]()
                await asyncio.Event().wait()
                return b""

            def close(self) -> None:
                self.closed = True

        source = SignallingSource()
        await run_service(_configuration(data_root), source_factory=lambda _interface: source)
        assert len(callbacks) == 2 and source.closed

    asyncio.run(scenario())


def test_bounded_neighbor_command_success_failure_timeout_oversize_and_cancel() -> None:
    async def scenario() -> None:
        printf = shutil.which("printf")
        false = shutil.which("false")
        sleep = shutil.which("sleep")
        yes = shutil.which("yes")
        assert all((printf, false, sleep, yes))
        assert await _run_bounded_command((str(printf), "[]"), 1, 16) == b"[]"
        with pytest.raises(KernelNeighborError, match="size"):
            await _run_bounded_command((str(printf), "finished-output"), 1, 1)
        with pytest.raises(KernelNeighborError, match="failed"):
            await _run_bounded_command((str(false),), 1, 16)
        with pytest.raises(KernelNeighborError, match="timed out"):
            await _run_bounded_command((str(sleep), "1"), 0.01, 16)
        with pytest.raises(KernelNeighborError, match="size"):
            await _run_bounded_command((str(yes),), 1, 16)

        pending = asyncio.create_task(_run_bounded_command((str(sleep), "1"), 2, 16))
        await asyncio.sleep(0.01)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending

    asyncio.run(scenario())


def test_kernel_neighbor_poll_is_bounded_normalized_and_no_shell() -> None:
    async def scenario() -> None:
        calls: list[tuple[tuple[str, ...], float, int]] = []
        records = [
            {
                "dst": "192.0.2.10",
                "dev": "eth-test",
                "lladdr": "02:00:00:00:00:10",
                "state": ["REACHABLE"],
            },
            {"dst": "192.0.2.11", "dev": "other", "state": "STALE"},
            {"bad": "record"},
            "not-a-record",
        ]

        async def runner(command: Any, timeout: float, maximum: int) -> bytes:
            calls.append((tuple(command), timeout, maximum))
            return json.dumps(records).encode()

        tracker = NeighborTracker()
        output = await poll_kernel_neighbors(
            "eth-test", tracker, observed_at=NOW, runner=runner, timeout=2, max_output_bytes=4096
        )
        assert [item.kind for item in output] == ["neighbor_observation"]
        assert output[0].fields["address"] == "192.0.2.10"
        assert calls == [
            (
                ("/usr/sbin/ip", "-j", "neigh", "show", "dev", "eth-test"),
                2,
                4096,
            )
        ]
        assert "sh" not in calls[0][0] and "shell" not in calls[0][0]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b"{}",
        json.dumps([{}] * 4097).encode(),
    ],
)
def test_kernel_neighbor_poll_rejects_malformed_or_excessive_sets(payload: bytes) -> None:
    async def runner(_command: Any, _timeout: float, _maximum: int) -> bytes:
        return payload

    async def scenario() -> None:
        with pytest.raises(KernelNeighborError):
            await poll_kernel_neighbors(
                "eth-test", NeighborTracker(), observed_at=NOW, runner=runner
            )

    asyncio.run(scenario())


def test_kernel_neighbor_poll_defends_against_injected_runner_oversize() -> None:
    async def runner(_command: Any, _timeout: float, maximum: int) -> bytes:
        return b"x" * (maximum + 1)

    async def scenario() -> None:
        with pytest.raises(KernelNeighborError, match="size"):
            await poll_kernel_neighbors(
                "eth-test",
                NeighborTracker(),
                observed_at=NOW,
                runner=runner,
                max_output_bytes=8,
            )

    asyncio.run(scenario())


def test_maintenance_expires_silent_state_after_24_hours_and_isolates_failures() -> None:
    async def scenario() -> None:
        persisted: list[PassiveObservation] = []

        async def sink(item: PassiveObservation) -> None:
            persisted.append(item)

        runtime = build_runtime(sink)
        tuple(runtime.mdns(PassiveFrame("mdns", _mdns_address(), NOW, "eth-test")))
        evidence = {
            "dst": "192.0.2.20",
            "dev": "eth-test",
            "lladdr": "02:00:00:00:00:20",
            "state": "REACHABLE",
        }

        async def initial_runner(_command: Any, _timeout: float, _maximum: int) -> bytes:
            return json.dumps([evidence]).encode()

        assert (
            await maintenance_once(
                interface="eth-test",
                runtime=runtime,
                sink=sink,
                observed_at=NOW,
                runner=initial_runner,
            )
            == 1
        )

        async def silent_runner(_command: Any, _timeout: float, _maximum: int) -> bytes:
            return b"[]"

        count = await maintenance_once(
            interface="eth-test",
            runtime=runtime,
            sink=sink,
            observed_at=NOW + timedelta(hours=24),
            runner=silent_runner,
        )
        assert count == 2
        assert [item.kind for item in persisted] == [
            "neighbor_observation",
            "mdns_address",
            "neighbor_expired",
        ]
        assert persisted[1].fields["action"] == "expired"

        async def failed_runner(_command: Any, _timeout: float, _maximum: int) -> bytes:
            raise KernelNeighborError("synthetic")

        assert (
            await maintenance_once(
                interface="eth-test",
                runtime=runtime,
                sink=sink,
                observed_at=NOW + timedelta(hours=25),
                runner=failed_runner,
            )
            == 0
        )

        runtime = build_runtime(sink)
        tuple(runtime.mdns(PassiveFrame("mdns", _mdns_address(), NOW, "eth-test")))

        async def failing_sink(_item: PassiveObservation) -> None:
            raise RuntimeError("synthetic sink failure")

        assert (
            await maintenance_once(
                interface="eth-test",
                runtime=runtime,
                sink=failing_sink,
                observed_at=NOW + timedelta(hours=24),
                runner=silent_runner,
            )
            == 0
        )

    asyncio.run(scenario())


def test_maintenance_loop_polls_on_interval_and_stops_cleanly() -> None:
    async def scenario() -> None:
        stop = asyncio.Event()
        calls = 0

        async def runner(_command: Any, _timeout: float, _maximum: int) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 2:
                stop.set()
            return b"[]"

        async def sink(_item: PassiveObservation) -> None:
            return None

        total = await maintenance_loop(
            stop,
            interface="eth-test",
            runtime=build_runtime(sink),
            sink=sink,
            runner=runner,
            interval_seconds=0.001,
        )
        assert calls == 2 and total == 0

    asyncio.run(scenario())


def test_service_runtime_polls_and_restart_preserves_expiring_history(tmp_path: Path) -> None:
    async def scenario() -> None:
        data_root = tmp_path / "restart"
        data_root.mkdir()
        evidence = {
            "dst": "192.0.2.30",
            "dev": "eth-test",
            "lladdr": "02:00:00:00:00:30",
            "state": "STALE",
        }

        for payload in (json.dumps([evidence]).encode(), b"[]"):
            stop = asyncio.Event()

            async def runner(
                _command: Any,
                _timeout: float,
                _maximum: int,
                data: bytes = payload,
                event: asyncio.Event = stop,
            ) -> bytes:
                event.set()
                return data

            source = _ReplaySource([], stop)
            await run_service(
                _configuration(data_root),
                source_factory=lambda _interface, actual=source: actual,
                neighbor_runner=runner,
                stop_event=stop,
            )

        repository = Repository.open(data_root / "discovery.db", data_root=data_root)
        rows = repository.connection.execute(
            "SELECT fact_value_json FROM observations WHERE fact_type = 'neighbor_observation'"
        ).fetchall()
        runs = repository.connection.execute(
            "SELECT status FROM collector_runs WHERE collector = 'passive' ORDER BY id"
        ).fetchall()
        repository.close()
        assert len(rows) == 1
        assert "valid_until" in json.loads(rows[0][0])
        assert [row[0] for row in runs] == ["succeeded", "succeeded"]

    asyncio.run(scenario())


def test_main_reports_configuration_failure_and_clean_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    async def no_op(_configuration: Any) -> None:
        return None

    monkeypatch.setattr("field_discovery.passive_service.run_service", no_op)
    monkeypatch.setattr(
        "field_discovery.passive_service.load_config", lambda _path: Configuration({})
    )
    assert main(["--config", str(tmp_path / "unused")]) == 0

    def invalid(_path: Path) -> Configuration:
        raise ConfigurationError("synthetic invalid configuration")

    monkeypatch.setattr("field_discovery.passive_service.load_config", invalid)
    assert main(["--config", str(tmp_path / "invalid")]) == 1


def test_systemd_unit_is_narrowly_privileged_and_resource_bounded(tmp_path: Path) -> None:
    unit = UNIT.read_text(encoding="utf-8")
    assert "After=network-online.target" in unit and "Wants=network-online.target" in unit
    assert "User=field-discovery" in unit and "Group=field-discovery" in unit
    assert "CapabilityBoundingSet=CAP_NET_RAW" in unit
    assert "AmbientCapabilities=CAP_NET_RAW" in unit
    assert "CAP_NET_ADMIN" not in unit and "sudo" not in unit.casefold()
    assert "Restart=on-failure" in unit and "StartLimitBurst=5" in unit
    assert "MemoryMax=256M" in unit and "CPUQuota=40%" in unit
    assert "TasksMax=32" in unit and "LimitNOFILE=256" in unit
    assert "ProtectSystem=strict" in unit and "ProtectHome=true" in unit
    assert "ReadWritePaths=/var/lib/field-discovery" in unit
    assert "RestrictAddressFamilies=AF_UNIX AF_PACKET AF_NETLINK" in unit
    assert "IPAddressDeny=any" in unit
    assert "SystemCallFilter=~@mount @privileged @reboot @resources @swap" in unit
    assert "PrivateMounts=true" in unit and "RemoveIPC=true" in unit
    assert "AF_INET" not in unit and "AF_INET6" not in unit
    assert "scan nmap" not in unit and "network-discovery-scan.sh" not in unit
    assert "field-discovery" in SYSUSERS.read_text(encoding="utf-8")

    analyzer = shutil.which("systemd-analyze")
    if analyzer is not None:
        verifiable = tmp_path / "field-discovery-passive.service"
        verifiable.write_text(
            unit.replace(
                "/opt/field-discovery/venv/bin/field-discovery-passive "
                "--config /etc/field-discovery/config.yaml",
                "/bin/true",
            ),
            encoding="utf-8",
        )
        result = subprocess.run(
            [analyzer, "verify", str(verifiable)], capture_output=True, text=True, check=False
        )
        assert result.returncode == 0, result.stderr


def test_install_and_remove_scripts_stage_without_starting_services(tmp_path: Path) -> None:
    for script in (INSTALL, REMOVE):
        assert stat.S_IMODE(script.stat().st_mode) == 0o755
        subprocess.run(["sh", "-n", str(script)], check=True)
        text = script.read_text(encoding="utf-8")
        assert "network-discovery-scan.sh" not in text and "scanopy" not in text.casefold()

    environment = {**os.environ, "DESTDIR": str(tmp_path)}
    installed = subprocess.run(
        [str(INSTALL), str(ROOT)], env=environment, capture_output=True, text=True, check=False
    )
    assert installed.returncode == 0
    assert "not enabled or started" in installed.stdout
    assert (tmp_path / "usr/lib/systemd/system/field-discovery-passive.service").is_file()
    assert (tmp_path / "usr/lib/sysusers.d/field-discovery.conf").is_file()
    assert not (tmp_path / "etc/systemd/system").exists()

    removed = subprocess.run(
        [str(REMOVE)], env=environment, capture_output=True, text=True, check=False
    )
    assert removed.returncode == 0
    assert not (tmp_path / "usr/lib/systemd/system/field-discovery-passive.service").exists()
    assert not (tmp_path / "usr/lib/sysusers.d/field-discovery.conf").exists()
