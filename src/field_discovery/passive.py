"""Bounded, protocol-neutral passive observation ingestion.

Capture adapters submit transient frames to this module.  Protocol parsers emit
structured observations, and only those observations are passed to persistence.
The framework deliberately has no packet-capture or raw-payload storage API.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Protocol, TypeAlias

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class PassivePipelineError(RuntimeError):
    """The passive pipeline cannot perform the requested lifecycle operation."""


class PassiveParseError(ValueError):
    """A parser rejected a malformed or unsupported frame."""


@dataclass(frozen=True)
class PassiveFrame:
    """One bounded, transient input frame supplied by a capture adapter."""

    protocol: str
    payload: bytes
    observed_at: datetime
    interface: str | None = None


@dataclass(frozen=True)
class PassiveObservation:
    """A structured passive fact safe to send to a persistence adapter."""

    kind: str
    fields: Mapping[str, JsonValue]
    source: str
    observed_at: datetime | None = None
    expires_at: datetime | None = None


class PassiveParser(Protocol):
    """Synchronous parser contract; parsers must not perform network I/O."""

    def __call__(self, frame: PassiveFrame) -> Iterable[PassiveObservation]: ...  # pragma: no cover


ObservationSink: TypeAlias = Callable[[PassiveObservation], Awaitable[None]]


@dataclass(frozen=True)
class PipelineMetrics:
    """Point-in-time counters and bounded-queue gauges."""

    submitted_frames: int
    processed_frames: int
    emitted_observations: int
    duplicate_observations: int
    parser_failures: int
    sink_failures: int
    oversized_frames: int
    unsupported_frames: int
    backpressure_rejections: int
    dedupe_evictions: int
    incomplete_frames: int
    queue_depth: int
    queue_peak: int
    in_flight: int


@dataclass
class _Counters:
    submitted_frames: int = 0
    processed_frames: int = 0
    emitted_observations: int = 0
    duplicate_observations: int = 0
    parser_failures: int = 0
    sink_failures: int = 0
    oversized_frames: int = 0
    unsupported_frames: int = 0
    backpressure_rejections: int = 0
    dedupe_evictions: int = 0
    incomplete_frames: int = 0
    queue_peak: int = 0


class PassiveEventPipeline:
    """Bounded asynchronous fan-in with isolated parsers and graceful draining."""

    def __init__(
        self,
        *,
        parsers: Mapping[str, Sequence[PassiveParser]],
        sink: ObservationSink,
        queue_size: int = 256,
        worker_count: int = 2,
        max_frame_bytes: int = 65_535,
        dedupe_window_seconds: float = 30.0,
        dedupe_capacity: int = 4_096,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        if queue_size < 1 or worker_count < 1 or max_frame_bytes < 1:
            raise ValueError("queue, worker, and frame bounds must be positive")
        if dedupe_window_seconds < 0 or dedupe_capacity < 1:
            raise ValueError("dedupe window must be non-negative and capacity positive")
        normalized = {name.casefold(): tuple(items) for name, items in parsers.items()}
        if any(not name or not items for name, items in normalized.items()):
            raise ValueError("parser protocol names and parser lists must not be empty")
        self._parsers = normalized
        self._sink = sink
        self._queue: asyncio.Queue[PassiveFrame] = asyncio.Queue(maxsize=queue_size)
        self._worker_count = worker_count
        self._max_frame_bytes = max_frame_bytes
        self._dedupe_window = dedupe_window_seconds
        self._dedupe_capacity = dedupe_capacity
        self._monotonic = monotonic
        self._dedupe: OrderedDict[str, float] = OrderedDict()
        self._workers: list[asyncio.Task[None]] = []
        self._counters = _Counters()
        self._in_flight = 0
        self._accepting = False
        self._stopped = False
        self._active_submitters = 0
        self._submissions_done = asyncio.Event()
        self._submissions_done.set()

    @property
    def retained_payload_capacity(self) -> int:
        """Maximum queued transient payload bytes (excluding in-flight workers)."""
        return self._queue.maxsize * self._max_frame_bytes

    async def start(self) -> None:
        """Start workers exactly once."""
        if self._stopped:
            raise PassivePipelineError("a stopped pipeline cannot be restarted")
        if self._workers:
            return
        self._accepting = True
        self._workers = [
            asyncio.create_task(self._worker(), name=f"passive-ingest-{index}")
            for index in range(self._worker_count)
        ]

    async def submit(
        self,
        protocol: str,
        payload: bytes,
        *,
        observed_at: datetime | None = None,
        interface: str | None = None,
    ) -> bool:
        """Submit with backpressure, waiting for bounded queue space."""
        frame = self._prepare_frame(protocol, payload, observed_at, interface)
        if frame is None:
            return False
        self._active_submitters += 1
        self._submissions_done.clear()
        try:
            await self._queue.put(frame)
            self._record_submission()
            return True
        finally:
            self._active_submitters -= 1
            if self._active_submitters == 0:
                self._submissions_done.set()

    def submit_nowait(
        self,
        protocol: str,
        payload: bytes,
        *,
        observed_at: datetime | None = None,
        interface: str | None = None,
    ) -> bool:
        """Submit without waiting, reporting a backpressure rejection when full."""
        frame = self._prepare_frame(protocol, payload, observed_at, interface)
        if frame is None:
            return False
        try:
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            self._counters.backpressure_rejections += 1
            return False
        self._record_submission()
        return True

    async def stop(self, *, drain_timeout: float = 10.0) -> PipelineMetrics:
        """Stop accepting input and drain, marking unfinished frames on timeout."""
        if drain_timeout < 0:
            raise ValueError("drain timeout must not be negative")
        if self._stopped:
            return self.metrics()
        self._accepting = False
        await self._submissions_done.wait()
        try:
            await asyncio.wait_for(self._queue.join(), timeout=drain_timeout)
        except TimeoutError:
            self._counters.incomplete_frames += self._queue.qsize() + self._in_flight
        finally:
            for worker in self._workers:
                worker.cancel()
            await asyncio.gather(*self._workers, return_exceptions=True)
            while True:
                try:
                    self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                self._queue.task_done()
            self._workers.clear()
            self._stopped = True
        return self.metrics()

    def metrics(self) -> PipelineMetrics:
        """Return immutable counters without exposing frames or payloads."""
        counters = self._counters
        return PipelineMetrics(
            submitted_frames=counters.submitted_frames,
            processed_frames=counters.processed_frames,
            emitted_observations=counters.emitted_observations,
            duplicate_observations=counters.duplicate_observations,
            parser_failures=counters.parser_failures,
            sink_failures=counters.sink_failures,
            oversized_frames=counters.oversized_frames,
            unsupported_frames=counters.unsupported_frames,
            backpressure_rejections=counters.backpressure_rejections,
            dedupe_evictions=counters.dedupe_evictions,
            incomplete_frames=counters.incomplete_frames,
            queue_depth=self._queue.qsize(),
            queue_peak=counters.queue_peak,
            in_flight=self._in_flight,
        )

    def _prepare_frame(
        self,
        protocol: str,
        payload: bytes,
        observed_at: datetime | None,
        interface: str | None,
    ) -> PassiveFrame | None:
        if not self._workers or not self._accepting:
            raise PassivePipelineError("pipeline is not accepting frames")
        name = protocol.casefold().strip()
        if name not in self._parsers:
            self._counters.unsupported_frames += 1
            return None
        if not isinstance(payload, bytes):
            raise TypeError("passive payload must be bytes")
        if len(payload) > self._max_frame_bytes:
            self._counters.oversized_frames += 1
            return None
        timestamp = _utc(observed_at or datetime.now(UTC))
        return PassiveFrame(name, bytes(payload), timestamp, interface)

    def _record_submission(self) -> None:
        self._counters.submitted_frames += 1
        self._counters.queue_peak = max(self._counters.queue_peak, self._queue.qsize())

    async def _worker(self) -> None:
        while True:
            frame = await self._queue.get()
            self._in_flight += 1
            try:
                await self._handle_frame(frame)
            finally:
                self._in_flight -= 1
                self._queue.task_done()

    async def _handle_frame(self, frame: PassiveFrame) -> None:
        for parser in self._parsers[frame.protocol]:
            try:
                observations = tuple(parser(frame))
            except asyncio.CancelledError:
                # Parsers are synchronous: this is parser output, not task
                # cancellation delivered at an await point.
                self._counters.parser_failures += 1
                continue
            except Exception:
                self._counters.parser_failures += 1
                continue
            for observation in observations:
                try:
                    normalized = _normalize_observation(observation, frame.observed_at)
                except Exception:
                    self._counters.parser_failures += 1
                    continue
                if self._is_duplicate(normalized):
                    self._counters.duplicate_observations += 1
                    continue
                try:
                    await self._sink(normalized)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._counters.sink_failures += 1
                    continue
                self._counters.emitted_observations += 1
        self._counters.processed_frames += 1

    def _is_duplicate(self, observation: PassiveObservation) -> bool:
        if self._dedupe_window == 0:
            return False
        now = (
            self._monotonic() if self._monotonic is not None else asyncio.get_running_loop().time()
        )
        while self._dedupe and next(iter(self._dedupe.values())) <= now:
            self._dedupe.popitem(last=False)
        fingerprint = _fingerprint(observation)
        expiry = self._dedupe.get(fingerprint)
        if expiry is not None and expiry > now:
            self._dedupe.move_to_end(fingerprint)
            return True
        self._dedupe[fingerprint] = now + self._dedupe_window
        self._dedupe.move_to_end(fingerprint)
        if len(self._dedupe) > self._dedupe_capacity:
            self._dedupe.popitem(last=False)
            self._counters.dedupe_evictions += 1
        return False


def _normalize_observation(
    observation: PassiveObservation, frame_time: datetime
) -> PassiveObservation:
    if not isinstance(observation, PassiveObservation):
        raise TypeError("parser output must be PassiveObservation")
    if not observation.kind or not observation.source:
        raise ValueError("observation kind and source must not be empty")
    fields = dict(observation.fields)
    # Serialization both validates structured JSON values and ensures raw bytes
    # cannot accidentally pass through to persistence.
    json.dumps(fields, allow_nan=False, sort_keys=True, separators=(",", ":"))
    observed_at = _utc(observation.observed_at or frame_time)
    expires_at = None if observation.expires_at is None else _utc(observation.expires_at)
    return replace(observation, fields=fields, observed_at=observed_at, expires_at=expires_at)


def _fingerprint(observation: PassiveObservation) -> str:
    canonical = json.dumps(
        {"fields": observation.fields, "kind": observation.kind, "source": observation.source},
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("passive event timestamps must be timezone-aware")
    return value.astimezone(UTC)
