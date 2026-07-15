"""Bounded system service for configured read-only collector cycles."""

from __future__ import annotations

import argparse
import asyncio
import logging
import random
import signal
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from field_discovery.config import ConfigurationError, load_config
from field_discovery.logging import configure_logging


@dataclass(frozen=True)
class ScheduledInvocation:
    """One secret-free CLI invocation in an independently isolated process."""

    collector: str
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class ScheduledOutcome:
    """Bounded result metadata; child output and credentials are never retained."""

    collector: str
    returncode: int
    timed_out: bool = False


class InvocationRunner(Protocol):
    async def __call__(  # pragma: no cover - structural typing declaration
        self, arguments: Sequence[str], timeout: float
    ) -> tuple[int, bool]: ...


def build_invocations(configuration: Mapping[str, Any]) -> tuple[ScheduledInvocation, ...]:
    """Build deterministic commands only for explicitly enabled configured collectors."""
    collectors = cast(Mapping[str, Mapping[str, Any]], configuration["collectors"])
    invocations: list[ScheduledInvocation] = []

    snmp = collectors["snmp"]
    snmp_targets = cast(Sequence[str], snmp["targets"])
    if snmp["enabled"] and snmp_targets:
        arguments = ["collect", "snmp"]
        for target in sorted(set(snmp_targets)):
            arguments.extend(("--target", target))
        invocations.append(ScheduledInvocation("snmp", tuple(arguments)))

    unifi = collectors["unifi"]
    if unifi["enabled"]:
        endpoints = cast(Sequence[Mapping[str, object]], unifi["endpoints"])
        for endpoint in sorted(endpoints, key=lambda item: str(item["url"])):
            invocations.append(
                ScheduledInvocation(
                    "unifi", ("collect", "unifi", "--controller", str(endpoint["url"]))
                )
            )

    ad = collectors["ad"]
    if ad["enabled"]:
        arguments = ["collect", "ad", "--target", str(ad["target"])]
        if ad["domain"] is not None:
            arguments.extend(("--domain", str(ad["domain"])))
        if ad["server_name"] is not None:
            arguments.extend(("--server-name", str(ad["server_name"])))
        invocations.append(ScheduledInvocation("ad", tuple(arguments)))

    ssh = collectors["ssh"]
    if ssh["enabled"]:
        by_platform: dict[str, set[str]] = {}
        for ssh_target in cast(Sequence[Mapping[str, str]], ssh["targets"]):
            by_platform.setdefault(ssh_target["platform"], set()).add(ssh_target["address"])
        for platform in sorted(by_platform):
            arguments = ["collect", "ssh", "--platform", platform]
            for address in sorted(by_platform[platform]):
                arguments.extend(("--target", address))
            invocations.append(ScheduledInvocation("ssh", tuple(arguments)))
    return tuple(invocations)


async def _run_process(arguments: Sequence[str], timeout: float) -> tuple[int, bool]:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    async def stop_process() -> None:
        if process.returncode is not None:  # pragma: no cover - defensive child-exit race
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.kill()
            await process.wait()

    try:
        return await asyncio.wait_for(process.wait(), timeout=timeout), False
    except TimeoutError:
        await stop_process()
        return 124, True
    except asyncio.CancelledError:
        await stop_process()
        raise


async def run_cycle(
    invocations: Sequence[ScheduledInvocation],
    *,
    executable: Path,
    config_path: Path,
    concurrency: int,
    timeout: float,
    runner: InvocationRunner = _run_process,
) -> tuple[ScheduledOutcome, ...]:
    """Run one bounded cycle while isolating every collector process and result."""
    semaphore = asyncio.Semaphore(concurrency)

    async def run_one(invocation: ScheduledInvocation) -> ScheduledOutcome:
        async with semaphore:
            returncode, timed_out = await runner(
                (
                    str(executable),
                    "--json",
                    "--config",
                    str(config_path),
                    *invocation.arguments,
                ),
                timeout,
            )
        return ScheduledOutcome(invocation.collector, returncode, timed_out)

    return tuple(await asyncio.gather(*(run_one(invocation) for invocation in invocations)))


async def serve(
    configuration: Mapping[str, Any],
    *,
    config_path: Path,
    stop: asyncio.Event,
    executable: Path,
    runner: InvocationRunner = _run_process,
    random_source: random.Random | None = None,
    logger: logging.Logger | None = None,
) -> None:
    """Run configured cycles until stopped; failures never suppress later cycles."""
    scheduler = cast(Mapping[str, int], configuration["scheduler"])
    interval = scheduler["interval_seconds"]
    jitter = scheduler["jitter_seconds"]
    timeout = max(60, scheduler["timeout_seconds"] * (scheduler["retries"] + 1) * 4)
    actual_random = random_source or random.SystemRandom()
    actual_logger = logger or logging.getLogger("field_discovery")
    while not stop.is_set():
        invocations = build_invocations(configuration)
        outcomes = await run_cycle(
            invocations,
            executable=executable,
            config_path=config_path,
            concurrency=scheduler["concurrency"],
            timeout=timeout,
            runner=runner,
        )
        actual_logger.info(
            "scheduler_cycle_finished",
            extra={
                "collectors": len(outcomes),
                "failed": sum(item.returncode != 0 for item in outcomes),
                "timed_out": sum(item.timed_out for item in outcomes),
            },
        )
        if stop.is_set():
            break
        delay = interval + actual_random.uniform(0, jitter)
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except TimeoutError:
            continue


def main(argv: Sequence[str] | None = None) -> int:
    """Run the collector scheduler under systemd."""
    parser = argparse.ArgumentParser(prog="field-discovery-scheduler")
    parser.add_argument("--config", type=Path, default=Path("/etc/field-discovery/config.yaml"))
    arguments = parser.parse_args(argv)
    logger = configure_logging(json_mode=True, run_id=str(uuid.uuid4()))
    try:
        configuration = load_config(arguments.config)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        stop = asyncio.Event()
        for selected_signal in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(selected_signal, stop.set)
        executable = Path(sys.executable).with_name("field-discovery")
        try:
            loop.run_until_complete(
                serve(
                    configuration.data,
                    config_path=arguments.config,
                    stop=stop,
                    executable=executable,
                )
            )
        finally:
            loop.close()
    except (ConfigurationError, OSError, RuntimeError) as exc:
        logger.error("scheduler_service_failed", extra={"reason": str(exc)})
        return 1
    logger.info("scheduler_service_stopped")
    return 0


if __name__ == "__main__":  # pragma: no cover - console script is the production entry point
    raise SystemExit(main())
