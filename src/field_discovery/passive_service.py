"""Least-privilege passive observer runtime for the systemd service."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import socket
import struct
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from field_discovery.config import ConfigurationError, load_config
from field_discovery.dhcp import DhcpParser
from field_discovery.link_layer import parse_cdp, parse_lldp
from field_discovery.logging import configure_logging
from field_discovery.mdns import MDNSParser
from field_discovery.neighbor import ArpParser, NeighborTracker, parse_kernel_neighbor
from field_discovery.passive import PassiveEventPipeline, PassiveObservation
from field_discovery.repository import Repository

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
ETH_P_LLDP = 0x88CC
MAX_CAPTURE_BYTES = 9_216
CDP_DESTINATION = b"\x01\x00\x0c\xcc\xcc\xcc"
CDP_SNAP = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
KERNEL_NEIGHBOR_COMMAND = ("/usr/sbin/ip", "-j", "neigh", "show", "dev")
KERNEL_POLL_INTERVAL_SECONDS = 60.0
KERNEL_COMMAND_TIMEOUT_SECONDS = 5.0
MAX_KERNEL_OUTPUT_BYTES = 1_048_576
MAX_KERNEL_RECORDS = 4_096

CommandRunner = Callable[[Sequence[str], float, int], Awaitable[bytes]]


class KernelNeighborError(RuntimeError):
    """A bounded kernel-neighbor read could not be completed safely."""


@dataclass(frozen=True)
class PassiveRuntime:
    """Pipeline and stateful parsers shared with periodic maintenance."""

    pipeline: PassiveEventPipeline
    mdns: MDNSParser
    neighbors: NeighborTracker


class FrameSource(Protocol):
    """Receive-only source contract used for deterministic service tests."""

    async def receive(self) -> bytes: ...  # pragma: no cover

    def close(self) -> None: ...  # pragma: no cover


class PacketSocketSource:
    """Non-transmitting Linux AF_PACKET source requiring only CAP_NET_RAW."""

    def __init__(
        self,
        interface: str,
        *,
        socket_factory: Callable[[int, int, int], socket.socket] = socket.socket,
    ) -> None:
        self._socket = socket_factory(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        try:
            self._socket.setblocking(False)
            self._socket.bind((interface, 0))
        except Exception:
            self._socket.close()
            raise

    async def receive(self) -> bytes:
        return await asyncio.get_running_loop().sock_recv(self._socket, MAX_CAPTURE_BYTES)

    def close(self) -> None:
        self._socket.close()


def decode_ethernet(packet: bytes) -> tuple[str, bytes] | None:
    """Extract one supported payload without retaining the Ethernet frame."""
    if len(packet) < 14 or len(packet) > MAX_CAPTURE_BYTES:
        return None
    destination = packet[:6]
    protocol = int.from_bytes(packet[12:14], "big")
    offset = 14
    if protocol in {ETH_P_8021Q, ETH_P_8021AD}:
        if len(packet) < 18:
            return None
        protocol = int.from_bytes(packet[16:18], "big")
        offset = 18
    payload = packet[offset:]
    if protocol == ETH_P_LLDP:
        return "lldp", payload
    if protocol == ETH_P_ARP:
        return "arp", payload
    if protocol == ETH_P_IP:
        return _decode_ipv4_udp(payload)
    if protocol <= 1_500 and destination == CDP_DESTINATION and payload.startswith(CDP_SNAP):
        return "cdp", payload[len(CDP_SNAP) :]
    return None


def _decode_ipv4_udp(payload: bytes) -> tuple[str, bytes] | None:
    if len(payload) < 28 or payload[0] >> 4 != 4:
        return None
    header_length = (payload[0] & 0x0F) * 4
    total_length = int.from_bytes(payload[2:4], "big")
    fragmented = bool(int.from_bytes(payload[6:8], "big") & 0x3FFF)
    if (
        header_length < 20
        or total_length < header_length + 8
        or total_length > len(payload)
        or payload[9] != socket.IPPROTO_UDP
        or fragmented
    ):
        return None
    udp = payload[header_length:total_length]
    source_port, destination_port, udp_length = struct.unpack("!HHH", udp[:6])
    if udp_length < 8 or udp_length > len(udp):
        return None
    body = udp[8:udp_length]
    ports = {source_port, destination_port}
    if 5353 in ports:
        return "mdns", body
    if ports & {67, 68}:
        return "dhcp", body
    return None


def build_pipeline(
    sink: Callable[[PassiveObservation], Awaitable[None]],
) -> PassiveEventPipeline:
    """Create bounded production parser registrations without opening capture."""
    return build_runtime(sink).pipeline


def build_runtime(
    sink: Callable[[PassiveObservation], Awaitable[None]],
) -> PassiveRuntime:
    """Create one runtime whose capture and maintenance paths share bounded state."""
    mdns = MDNSParser()
    neighbors = NeighborTracker()
    pipeline = PassiveEventPipeline(
        parsers={
            "lldp": (parse_lldp,),
            "cdp": (parse_cdp,),
            "mdns": (mdns,),
            "dhcp": (DhcpParser(),),
            "arp": (ArpParser(neighbors),),
        },
        sink=sink,
        queue_size=256,
        worker_count=2,
        max_frame_bytes=MAX_CAPTURE_BYTES,
        dedupe_capacity=4_096,
    )
    return PassiveRuntime(pipeline, mdns, neighbors)


async def _run_bounded_command(
    command: Sequence[str], timeout: float, max_output_bytes: int
) -> bytes:
    """Execute an argument vector without a shell and cap time and stdout memory."""
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout = process.stdout
    assert stdout is not None

    async def read_output() -> bytes:
        output = bytearray()
        while True:
            chunk = await stdout.read(min(65_536, max_output_bytes + 1 - len(output)))
            if not chunk:
                return bytes(output)
            output.extend(chunk)
            if len(output) > max_output_bytes:
                raise KernelNeighborError("kernel neighbor output exceeds its size limit")

    async def terminate_and_reap() -> None:
        if (
            process.returncode is None
        ):  # pragma: no branch - SIGCHLD delivery is event-loop dependent
            process.kill()
        # A killed child may leave a bounded kernel pipe buffer behind. Drain
        # without accumulating it so Process.wait() cannot deadlock on PIPE.
        while await stdout.read(65_536):
            pass
        await process.wait()

    try:
        output = await asyncio.wait_for(read_output(), timeout=timeout)
        return_code = await asyncio.wait_for(process.wait(), timeout=timeout)
    except TimeoutError as exc:
        await terminate_and_reap()
        raise KernelNeighborError("kernel neighbor command timed out") from exc
    except BaseException:
        await terminate_and_reap()
        raise
    if return_code != 0:
        raise KernelNeighborError("kernel neighbor command failed")
    return output


async def poll_kernel_neighbors(
    interface: str,
    tracker: NeighborTracker,
    *,
    observed_at: datetime,
    runner: CommandRunner = _run_bounded_command,
    timeout: float = KERNEL_COMMAND_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_KERNEL_OUTPUT_BYTES,
) -> tuple[PassiveObservation, ...]:
    """Read and normalize bounded ``ip -j neigh`` metadata without probing peers."""
    raw = await runner((*KERNEL_NEIGHBOR_COMMAND, interface), timeout, max_output_bytes)
    if len(raw) > max_output_bytes:
        raise KernelNeighborError("kernel neighbor output exceeds its size limit")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise KernelNeighborError("kernel neighbor output is not valid JSON") from exc
    if not isinstance(document, list) or len(document) > MAX_KERNEL_RECORDS:
        raise KernelNeighborError("kernel neighbor output has an invalid record set")
    observations: list[PassiveObservation] = []
    for record in document:
        if not isinstance(record, dict):
            continue
        try:
            evidence = parse_kernel_neighbor(
                record, observed_at=observed_at, selected_interface=interface
            )
        except ValueError:
            continue
        if evidence is not None:
            observations.extend(tracker.observe(evidence))
    return tuple(observations)


async def maintenance_once(
    *,
    interface: str,
    runtime: PassiveRuntime,
    sink: Callable[[PassiveObservation], Awaitable[None]],
    observed_at: datetime,
    runner: CommandRunner = _run_bounded_command,
    logger: logging.Logger | None = None,
) -> int:
    """Poll kernel metadata and expire caches; each failure remains isolated."""
    actual_logger = logger or logging.getLogger(__name__)
    observations: list[PassiveObservation] = []
    try:
        observations.extend(
            await poll_kernel_neighbors(
                interface, runtime.neighbors, observed_at=observed_at, runner=runner
            )
        )
    except (KernelNeighborError, OSError, ValueError):
        actual_logger.warning("kernel_neighbor_poll_failed")
    observations.extend(runtime.mdns.expire(observed_at))
    observations.extend(runtime.neighbors.expire(observed_at))
    emitted = 0
    for observation in observations:
        try:
            await sink(observation)
        except Exception:
            actual_logger.warning("passive_maintenance_sink_failed")
            continue
        emitted += 1
    return emitted


async def maintenance_loop(
    stop_event: asyncio.Event,
    *,
    interface: str,
    runtime: PassiveRuntime,
    sink: Callable[[PassiveObservation], Awaitable[None]],
    runner: CommandRunner = _run_bounded_command,
    interval_seconds: float = KERNEL_POLL_INTERVAL_SECONDS,
) -> int:
    """Run bounded passive maintenance until shutdown, without active probes."""
    total = 0
    while not stop_event.is_set():
        total += await maintenance_once(
            interface=interface,
            runtime=runtime,
            sink=sink,
            observed_at=datetime.now(UTC),
            runner=runner,
        )
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
        except TimeoutError:
            continue
    return total


async def observe(
    source: FrameSource,
    pipeline: PassiveEventPipeline,
    stop_event: asyncio.Event,
    *,
    interface: str,
) -> None:
    """Receive until signalled, then drain the pipeline and release capture."""
    await pipeline.start()
    try:
        while not stop_event.is_set():
            receive = asyncio.create_task(source.receive())
            stopped = asyncio.create_task(stop_event.wait())
            done, pending = await asyncio.wait(
                {receive, stopped}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            if stopped in done and stopped.result():
                continue
            packet = receive.result()
            decoded = decode_ethernet(packet)
            if decoded is not None:
                protocol, payload = decoded
                await pipeline.submit(
                    protocol, payload, observed_at=datetime.now(UTC), interface=interface
                )
    finally:
        source.close()
        await pipeline.stop(drain_timeout=20)


def _repository_sink(
    repository: Repository, deployment_id: int
) -> Callable[[PassiveObservation], Awaitable[None]]:
    async def persist(observation: PassiveObservation) -> None:
        value = dict(observation.fields)
        if observation.expires_at is not None:
            value["valid_until"] = observation.expires_at.isoformat()
        assert observation.observed_at is not None
        repository.record_observation(
            deployment_id,
            subject_type="passive_evidence",
            subject_id=None,
            fact_type=observation.kind,
            fact_value=value,
            confidence=1.0,
            inferred=False,
            source=observation.source,
            observed_at=observation.observed_at.isoformat(),
        )

    return persist


async def run_service(
    configuration: Mapping[str, Any],
    *,
    source_factory: Callable[[str], FrameSource] = PacketSocketSource,
    neighbor_runner: CommandRunner = _run_bounded_command,
    stop_event: asyncio.Event | None = None,
) -> None:
    """Run the observer with repository ownership and signal-aware shutdown."""
    interface = str(configuration["interface"]["name"])
    paths = configuration["paths"]
    repository = Repository.open(Path(paths["database"]), data_root=Path(paths["data_root"]))
    timestamp = datetime.now(UTC)
    deployment_id = repository.upsert_deployment(
        "default", "Default deployment", timestamp.isoformat()
    )
    run_id = repository.start_run(
        deployment_id, "passive", timestamp.isoformat(), interface_name=interface
    )
    stopping = stop_event or asyncio.Event()
    if stop_event is None:
        loop = asyncio.get_running_loop()
        for selected_signal in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(selected_signal, stopping.set)
    try:
        sink = _repository_sink(repository, deployment_id)
        runtime = build_runtime(sink)
        source = source_factory(interface)
        maintenance = asyncio.create_task(
            maintenance_loop(
                stopping,
                interface=interface,
                runtime=runtime,
                sink=sink,
                runner=neighbor_runner,
            )
        )
        maintenance_count = 0
        try:
            await observe(source, runtime.pipeline, stopping, interface=interface)
        finally:
            stopping.set()
            maintenance_count = await maintenance
        repository.finish_run(
            run_id,
            "succeeded",
            datetime.now(UTC).isoformat(),
            runtime.pipeline.metrics().emitted_observations + maintenance_count,
        )
    except BaseException:
        repository.finish_run(run_id, "failed", datetime.now(UTC).isoformat(), 0)
        raise
    finally:
        repository.close()


def main(argv: Sequence[str] | None = None) -> int:
    """Run the dedicated service process; systemd handles restart policy."""
    parser = argparse.ArgumentParser(prog="field-discovery-passive")
    parser.add_argument("--config", type=Path, default=Path("/etc/field-discovery/config.yaml"))
    arguments = parser.parse_args(argv)
    logger = configure_logging(json_mode=True, run_id=str(uuid.uuid4()))
    try:
        configuration = load_config(arguments.config)
        asyncio.run(run_service(configuration.data))
    except (ConfigurationError, OSError, RuntimeError) as exc:
        logger.error("passive_service_failed", extra={"reason": str(exc)})
        return 1
    logger.info("passive_service_stopped")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
