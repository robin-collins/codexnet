# Passive ingestion framework

`field_discovery.passive.PassiveEventPipeline` is the bounded hand-off between future packet or
kernel-neighbour adapters and protocol parsers. T300 intentionally provides no live-capture adapter:
verification uses synthetic frames only.

The configured frame-size limit and queue length bound transient queued payload memory. A small fixed
worker pool consumes the queue. Awaited submission applies backpressure; capture adapters that cannot
wait can use `submit_nowait` and count a rejection. Oversized and unknown-protocol frames are rejected
before queueing.

Each parser runs independently for a frame. Parser exceptions, malformed structured output, and sink
failures increment metrics and do not stop other parsers or later frames. Parsers emit only JSON-safe
`PassiveObservation` values. Raw bytes are never supplied to the sink and the framework has no capture
or payload-artifact writer.

Deduplication uses a bounded, expiring fingerprint cache over observation kind, source, and structured
fields. Event timestamps are deliberately excluded so retransmissions deduplicate; after the configured
window the same fact is emitted as fresh evidence. All accepted timestamps are timezone-aware and
normalized to UTC.

On shutdown, new input is refused and active submitters settle before the queue drains. If the drain
deadline expires, queued and in-flight frames are counted as incomplete, workers are cancelled, and the
queue is released. Metrics expose counts and queue gauges but never frame content.
