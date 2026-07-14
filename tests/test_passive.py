"""Synthetic replay tests for the bounded passive ingestion framework."""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta, timezone

import pytest

from field_discovery.passive import (
    PassiveEventPipeline,
    PassiveFrame,
    PassiveObservation,
    PassivePipelineError,
)

NOW = datetime(2026, 1, 2, 3, 4, tzinfo=UTC)


def observation_parser(frame: PassiveFrame) -> Iterable[PassiveObservation]:
    yield PassiveObservation("neighbor", {"value": frame.payload.decode()}, "synthetic")


async def _append_to(target: list[PassiveObservation], item: PassiveObservation) -> None:
    target.append(item)


def test_constructor_rejects_invalid_bounds_and_parser_sets() -> None:
    async def sink(_item: PassiveObservation) -> None:
        return None

    for keyword in ("queue_size", "worker_count", "max_frame_bytes"):
        with pytest.raises(ValueError, match="bounds"):
            PassiveEventPipeline(parsers={"test": (observation_parser,)}, sink=sink, **{keyword: 0})
    with pytest.raises(ValueError, match="dedupe"):
        PassiveEventPipeline(
            parsers={"test": (observation_parser,)}, sink=sink, dedupe_window_seconds=-1
        )
    with pytest.raises(ValueError, match="dedupe"):
        PassiveEventPipeline(parsers={"test": (observation_parser,)}, sink=sink, dedupe_capacity=0)
    with pytest.raises(ValueError, match="parser"):
        PassiveEventPipeline(parsers={"test": ()}, sink=sink)
    with pytest.raises(ValueError, match="parser"):
        PassiveEventPipeline(parsers={"": (observation_parser,)}, sink=sink)


def test_lifecycle_rejects_input_outside_running_period() -> None:
    async def scenario() -> None:
        pipeline = PassiveEventPipeline(parsers={"test": (observation_parser,)}, sink=_discard)
        with pytest.raises(PassivePipelineError, match="not accepting"):
            await pipeline.submit("test", b"before")
        await pipeline.start()
        await pipeline.start()
        first = await pipeline.stop()
        second = await pipeline.stop()
        assert first == second
        with pytest.raises(PassivePipelineError, match="not accepting"):
            pipeline.submit_nowait("test", b"after")
        with pytest.raises(PassivePipelineError, match="restarted"):
            await pipeline.start()
        with pytest.raises(ValueError, match="timeout"):
            await PassiveEventPipeline(parsers={"test": (observation_parser,)}, sink=_discard).stop(
                drain_timeout=-1
            )

    asyncio.run(scenario())


async def _discard(_item: PassiveObservation) -> None:
    return None


def test_synthetic_frames_are_timestamped_utc_and_payload_is_not_retained() -> None:
    async def scenario() -> None:
        output: list[PassiveObservation] = []
        local_time = datetime(2026, 1, 2, 13, 34, tzinfo=timezone(timedelta(hours=10, minutes=30)))
        pipeline = PassiveEventPipeline(
            parsers={"TEST": (observation_parser,)},
            sink=lambda item: _append_to(output, item),
            queue_size=3,
            max_frame_bytes=10,
        )
        assert pipeline.retained_payload_capacity == 30
        await pipeline.start()
        payload = b"fact"
        assert await pipeline.submit(
            " test ", payload, observed_at=local_time, interface="eth-test"
        )
        metrics = await pipeline.stop()
        assert len(output) == 1
        assert output[0].fields == {"value": "fact"}
        assert output[0].observed_at == datetime(2026, 1, 2, 3, 4, tzinfo=UTC)
        assert not hasattr(output[0], "payload")
        assert metrics.submitted_frames == metrics.processed_frames == 1
        assert metrics.emitted_observations == 1
        assert metrics.queue_depth == metrics.in_flight == metrics.incomplete_frames == 0

    asyncio.run(scenario())


def test_malformed_parser_and_sink_failures_are_isolated() -> None:
    def broken_parser(_frame: PassiveFrame) -> Iterable[PassiveObservation]:
        raise ValueError("synthetic malformed frame")

    def invalid_output(_frame: PassiveFrame) -> Iterable[PassiveObservation]:
        yield PassiveObservation("unsafe", {"raw": b"not retained"}, "synthetic")  # type: ignore[dict-item]

    def wrong_output(_frame: PassiveFrame) -> Iterable[PassiveObservation]:
        yield "wrong"  # type: ignore[misc]

    def empty_identity(_frame: PassiveFrame) -> Iterable[PassiveObservation]:
        yield PassiveObservation("", {}, "synthetic")

    def cancelled_parser(_frame: PassiveFrame) -> Iterable[PassiveObservation]:
        raise asyncio.CancelledError

    async def scenario() -> None:
        output: list[PassiveObservation] = []

        async def selective_sink(item: PassiveObservation) -> None:
            if item.fields.get("value") == "sink-fail":
                raise RuntimeError("synthetic sink failure")
            output.append(item)

        pipeline = PassiveEventPipeline(
            parsers={
                "test": (
                    broken_parser,
                    cancelled_parser,
                    invalid_output,
                    wrong_output,
                    empty_identity,
                    observation_parser,
                )
            },
            sink=selective_sink,
        )
        await pipeline.start()
        for payload in (b"first", b"sink-fail", b"last"):
            assert await pipeline.submit("test", payload, observed_at=NOW)
        metrics = await pipeline.stop()
        assert [item.fields["value"] for item in output] == ["first", "last"]
        assert metrics.parser_failures == 15
        assert metrics.sink_failures == 1
        assert metrics.processed_frames == 3
        assert metrics.emitted_observations == 2

    asyncio.run(scenario())


def test_duplicate_expiry_and_cache_capacity_are_deterministic() -> None:
    async def scenario() -> None:
        output: list[PassiveObservation] = []
        clock = [100.0]
        pipeline = PassiveEventPipeline(
            parsers={"test": (observation_parser,)},
            sink=lambda item: _append_to(output, item),
            dedupe_window_seconds=5,
            dedupe_capacity=2,
            monotonic=lambda: clock[0],
        )
        await pipeline.start()
        assert await pipeline.submit("test", b"a", observed_at=NOW)
        assert await pipeline.submit("test", b"a", observed_at=NOW + timedelta(seconds=1))
        await asyncio.sleep(0)
        clock[0] = 106.0
        assert await pipeline.submit("test", b"a", observed_at=NOW + timedelta(seconds=6))
        assert await pipeline.submit("test", b"b", observed_at=NOW)
        assert await pipeline.submit("test", b"c", observed_at=NOW)
        metrics = await pipeline.stop()
        assert [item.fields["value"] for item in output] == ["a", "a", "b", "c"]
        assert metrics.duplicate_observations == 1
        assert metrics.dedupe_evictions == 1

        no_dedupe: list[PassiveObservation] = []
        pipeline = PassiveEventPipeline(
            parsers={"test": (observation_parser,)},
            sink=lambda item: _append_to(no_dedupe, item),
            dedupe_window_seconds=0,
        )
        await pipeline.start()
        await pipeline.submit("test", b"same", observed_at=NOW)
        await pipeline.submit("test", b"same", observed_at=NOW)
        await pipeline.stop()
        assert len(no_dedupe) == 2

    asyncio.run(scenario())


def test_queue_and_frame_bounds_apply_backpressure_under_load() -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocking_sink(_item: PassiveObservation) -> None:
            entered.set()
            await release.wait()

        pipeline = PassiveEventPipeline(
            parsers={"test": (observation_parser,)},
            sink=blocking_sink,
            queue_size=1,
            worker_count=1,
            max_frame_bytes=4,
            dedupe_window_seconds=0,
        )
        await pipeline.start()
        assert await pipeline.submit("test", b"one", observed_at=NOW)
        await entered.wait()
        assert pipeline.submit_nowait("test", b"two", observed_at=NOW)
        assert not pipeline.submit_nowait("test", b"full", observed_at=NOW)
        assert not pipeline.submit_nowait("test", b"large", observed_at=NOW)
        assert not pipeline.submit_nowait("unknown", b"x", observed_at=NOW)
        release.set()
        metrics = await pipeline.stop()
        assert pipeline.retained_payload_capacity == 4
        assert metrics.queue_peak == 1
        assert metrics.submitted_frames == metrics.processed_frames == 2
        assert metrics.backpressure_rejections == 1
        assert metrics.oversized_frames == 1
        assert metrics.unsupported_frames == 1

    asyncio.run(scenario())


def test_awaited_submission_backpressure_settles_before_shutdown() -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        release = asyncio.Event()

        async def blocking_sink(_item: PassiveObservation) -> None:
            entered.set()
            await release.wait()

        pipeline = PassiveEventPipeline(
            parsers={"test": (observation_parser,)},
            sink=blocking_sink,
            queue_size=1,
            worker_count=1,
            dedupe_window_seconds=0,
        )
        await pipeline.start()
        await pipeline.submit("test", b"one", observed_at=NOW)
        await entered.wait()
        await pipeline.submit("test", b"two", observed_at=NOW)
        waiting = asyncio.create_task(pipeline.submit("test", b"three", observed_at=NOW))
        await asyncio.sleep(0)
        assert not waiting.done()
        stop = asyncio.create_task(pipeline.stop(drain_timeout=1))
        release.set()
        assert await waiting
        metrics = await stop
        assert metrics.processed_frames == 3
        assert metrics.incomplete_frames == 0

    asyncio.run(scenario())


def test_shutdown_timeout_cancels_and_marks_incomplete_work() -> None:
    async def scenario() -> None:
        entered = asyncio.Event()
        cancelled = asyncio.Event()

        async def stuck_sink(_item: PassiveObservation) -> None:
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        pipeline = PassiveEventPipeline(
            parsers={"test": (observation_parser,)},
            sink=stuck_sink,
            queue_size=2,
            worker_count=1,
            dedupe_window_seconds=0,
        )
        await pipeline.start()
        await pipeline.submit("test", b"one", observed_at=NOW)
        await entered.wait()
        await pipeline.submit("test", b"two", observed_at=NOW)
        metrics = await pipeline.stop(drain_timeout=0)
        assert cancelled.is_set()
        assert metrics.incomplete_frames == 2
        assert metrics.queue_depth == metrics.in_flight == 0
        assert metrics.processed_frames == 0

    asyncio.run(scenario())


def test_timestamp_and_payload_contracts_reject_unsafe_input() -> None:
    async def scenario() -> None:
        pipeline = PassiveEventPipeline(parsers={"test": (observation_parser,)}, sink=_discard)
        await pipeline.start()
        assert not await pipeline.submit("unknown", b"x", observed_at=NOW)
        with pytest.raises(ValueError, match="timezone-aware"):
            await pipeline.submit("test", b"x", observed_at=datetime(2026, 1, 1))
        with pytest.raises(TypeError, match="bytes"):
            await pipeline.submit("test", bytearray(b"x"), observed_at=NOW)  # type: ignore[arg-type]
        await pipeline.stop()

    asyncio.run(scenario())
