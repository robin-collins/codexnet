"""Protocol-neutral, target-scoped collector lifecycle and scheduler."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import random
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol, cast

from field_discovery.repository import Repository


class CollectorError(RuntimeError):
    """Base class for safe collector lifecycle failures."""


class TargetApprovalError(CollectorError):
    """A requested target is not an approved IPv4 host or subnet."""


class UnknownCollectorError(CollectorError):
    """No registered collector matches a request."""


class CollectorAuthenticationError(CollectorError):
    """The target rejected the referenced credential; never include its value."""


class RetryableCollectorError(CollectorError):
    """A temporary transport or target failure may be retried."""


@dataclass(frozen=True)
class CredentialReference:
    """An opaque lookup reference, never credential material."""

    provider: str
    key: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, object] | None) -> CredentialReference | None:
        if value is None:
            return None
        provider = value.get("provider")
        key = value.get("key")
        if (
            set(value) != {"provider", "key"}
            or not isinstance(provider, str)
            or not isinstance(key, str)
        ):
            raise CollectorError("credential reference must contain provider and key")
        return cls(provider=provider, key=key)


@dataclass(frozen=True)
class CollectorIssue:
    """A secret-free problem returned alongside partial data."""

    category: str
    detail: str
    retryable: bool = False


@dataclass(frozen=True)
class CollectorResult:
    """Bounded summary after a collector has persisted normalized observations."""

    item_count: int = 0
    issues: tuple[CollectorIssue, ...] = ()

    def __post_init__(self) -> None:
        if self.item_count < 0:
            raise ValueError("collector item count cannot be negative")


@dataclass(frozen=True)
class CollectorContext:
    """Approved context passed to exactly one independent collector invocation."""

    target: str
    credential_ref: CredentialReference | None
    cancellation: asyncio.Event


class Collector(Protocol):
    """Common asynchronous collector contract used by protocol adapters."""

    name: str

    async def collect(self, context: CollectorContext) -> CollectorResult:
        """Collect from one approved target and return a secret-free summary."""


@dataclass(frozen=True)
class CollectorRequest:
    """One collector/target/reference lifecycle request."""

    collector: str
    target: str
    credential_ref: CredentialReference | None = None


@dataclass(frozen=True)
class CollectorRunSummary:
    """Final persisted state for one request."""

    run_id: int
    collector: str
    target: str
    status: str
    attempts: int
    item_count: int
    error_count: int


def approve_target(target: str, approved_ranges: Sequence[str]) -> str:
    """Return a canonical approved IPv4 host/CIDR or refuse before collection."""
    try:
        requested = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise TargetApprovalError("collector target must be an IPv4 address or CIDR") from exc
    if requested.version != 4:
        raise TargetApprovalError("collector target must be IPv4")
    approved = tuple(
        cast(ipaddress.IPv4Network, ipaddress.ip_network(value, strict=True))
        for value in approved_ranges
    )
    if not any(requested.subnet_of(network) for network in approved):
        raise TargetApprovalError(f"collector target {requested} is outside approved ranges")
    if "/" not in target:
        return str(requested.network_address)
    return str(requested)


@dataclass
class CollectorOrchestrator:
    """Run independent collectors with bounded resources and durable state."""

    repository: Repository
    deployment_id: int
    approved_ranges: Sequence[str]
    collectors: Mapping[str, Collector]
    concurrency: int
    timeout_seconds: float
    retries: int
    interface_name: str | None = None
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("field_discovery"))
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    retry_sleep: Callable[[float], Awaitable[None]] = asyncio.sleep

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError("collector concurrency must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("collector timeout must be positive")
        if self.retries < 0:
            raise ValueError("collector retries cannot be negative")

    async def run(
        self, requests: Sequence[CollectorRequest], *, cancellation: asyncio.Event | None = None
    ) -> tuple[CollectorRunSummary, ...]:
        """Run a cycle; invalid targets are refused before any run is started."""
        approved_requests = tuple(
            CollectorRequest(
                collector=request.collector,
                target=approve_target(request.target, self.approved_ranges),
                credential_ref=request.credential_ref,
            )
            for request in requests
        )
        for request in approved_requests:
            if request.collector not in self.collectors:
                raise UnknownCollectorError(f"collector is not registered: {request.collector}")
        stop = cancellation or asyncio.Event()
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = [
            asyncio.create_task(self._run_one(request, semaphore, stop))
            for request in approved_requests
        ]
        if not tasks:
            return ()
        cancel_waiter = asyncio.create_task(stop.wait())
        gatherer = asyncio.gather(*tasks)
        try:
            waiters = {
                cast(asyncio.Future[object], gatherer),
                cast(asyncio.Future[object], cancel_waiter),
            }
            done, _ = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            if cancel_waiter in done and stop.is_set() and not gatherer.done():
                for task in tasks:
                    task.cancel()
            return tuple(await gatherer)
        except asyncio.CancelledError:
            stop.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        finally:
            cancel_waiter.cancel()
            await asyncio.gather(cancel_waiter, return_exceptions=True)

    async def _run_one(
        self,
        request: CollectorRequest,
        semaphore: asyncio.Semaphore,
        cancellation: asyncio.Event,
    ) -> CollectorRunSummary:
        started = self.clock().isoformat()
        run_id = self.repository.start_run(
            self.deployment_id,
            request.collector,
            started,
            interface_name=self.interface_name,
            target_cidr=request.target,
        )
        attempts = 0
        errors = 0
        item_count = 0
        status = "failed"
        collector = self.collectors[request.collector]
        try:
            async with semaphore:
                for attempt in range(self.retries + 1):  # pragma: no branch - every path breaks
                    if cancellation.is_set():
                        raise asyncio.CancelledError
                    attempts = attempt + 1
                    try:
                        result = await asyncio.wait_for(
                            collector.collect(
                                CollectorContext(
                                    target=request.target,
                                    credential_ref=request.credential_ref,
                                    cancellation=cancellation,
                                )
                            ),
                            timeout=self.timeout_seconds,
                        )
                    except TimeoutError:
                        errors += 1
                        self._record_issue(
                            run_id, request.collector, "timeout", "collector timed out", True
                        )
                        if attempt < self.retries:
                            await self.retry_sleep(0)
                            continue
                    except CollectorAuthenticationError:
                        errors += 1
                        self._record_issue(
                            run_id,
                            request.collector,
                            "authentication",
                            "referenced credential was rejected",
                            False,
                        )
                    except RetryableCollectorError as exc:
                        errors += 1
                        self._record_issue(run_id, request.collector, "transport", str(exc), True)
                        if attempt < self.retries:
                            await self.retry_sleep(0)
                            continue
                    except CollectorError as exc:
                        errors += 1
                        self._record_issue(run_id, request.collector, "collector", str(exc), False)
                    except Exception as exc:
                        errors += 1
                        self._record_issue(
                            run_id,
                            request.collector,
                            "collector_failure",
                            self.repository.redactor.exception(exc),
                            False,
                        )
                    else:
                        item_count = result.item_count
                        for issue in result.issues:
                            errors += 1
                            self._record_issue(
                                run_id,
                                request.collector,
                                issue.category,
                                issue.detail,
                                issue.retryable,
                            )
                        status = "partial" if result.issues else "succeeded"
                    break
        except asyncio.CancelledError:
            cancellation.set()
            status = "cancelled"
        self.repository.finish_run(run_id, status, self.clock().isoformat(), item_count)
        self.logger.info(
            "collector_finished",
            extra={
                "collector": request.collector,
                "target": request.target,
                "status": status,
                "attempts": attempts,
                "item_count": item_count,
                "error_count": errors,
            },
        )
        return CollectorRunSummary(
            run_id, request.collector, request.target, status, attempts, item_count, errors
        )

    def _record_issue(
        self,
        run_id: int,
        collector: str,
        category: str,
        detail: str,
        retryable: bool,
    ) -> None:
        self.repository.record_collector_error(
            run_id,
            category=category,
            detail=detail,
            retryable=retryable,
            source=collector,
            observed_at=self.clock().isoformat(),
        )


@dataclass
class CollectorScheduler:
    """Repeat orchestration cycles with positive bounded jitter."""

    orchestrator: CollectorOrchestrator
    interval_seconds: float
    jitter_seconds: float
    random_source: random.Random = field(default_factory=random.Random)

    def __post_init__(self) -> None:
        if self.interval_seconds <= 0 or not 0 <= self.jitter_seconds < self.interval_seconds:
            raise ValueError("scheduler interval/jitter bounds are invalid")

    def next_delay(self) -> float:
        """Return interval plus uniformly distributed configured jitter."""
        return self.interval_seconds + self.random_source.uniform(0, self.jitter_seconds)

    async def serve(
        self,
        request_factory: Callable[[], Sequence[CollectorRequest]],
        stop: asyncio.Event,
    ) -> None:
        """Run cycles until stopped; stopping cancels an in-flight cycle safely."""
        while not stop.is_set():
            await self.orchestrator.run(request_factory(), cancellation=stop)
            if stop.is_set():
                break
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.next_delay())
            except TimeoutError:
                continue
