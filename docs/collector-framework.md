# Collector framework and scheduler

The protocol-neutral framework in `field_discovery.collectors` is the safety boundary shared by
SNMP, SSH, UniFi, and AD adapters. Protocol adapters are added by later tasks; T400 itself never
opens a socket and its tests use asynchronous fakes only.

Each request names a registered collector, an IPv4 host or CIDR, and an optional opaque
`CredentialReference(provider, key)`. The scheduler never resolves or receives credential values.
Targets are canonicalized and must be wholly contained by one of `active.approved_ranges` before
any database run is created or collector code is called. Hostnames are deliberately not accepted
at this boundary: a future detector must first resolve and approve each concrete address.

The orchestrator starts a durable `collector_runs` record, limits simultaneous invocations with an
async semaphore, applies a per-attempt wall-clock timeout, and permits only the configured bounded
retry count. Authentication failures and permanent collector errors are not retried. A partial
result retains its item count and issues; unexpected exceptions are redacted and isolated to that
run. Other requests in the cycle continue.

Cancellation propagates through a shared event and task cancellation. Both active and queued runs
are finalized as `cancelled`, so restart/status logic never mistakes them for active work. An
interrupted process is still covered by the repository's startup recovery for unfinished runs.

`CollectorScheduler` repeats complete cycles after the configured interval plus uniformly bounded
positive jitter. A stop request cancels an in-flight cycle and prevents another. The CLI `status`
command exposes the newest 20 durable run summaries and aggregate error counts; T602 will add the
remaining appliance and service diagnostics.

The production `field-discovery-scheduler.service` connects that lifecycle to systemd. Its
unprivileged process builds secret-free child command vectors only for collectors explicitly
enabled in configuration: per-host `snmp.targets`, a concrete approved address for every UniFi
endpoint, one `ad.target`, and per-host/platform `ssh.targets`. Empty or disabled profiles are idle.
Each collector family runs in an independently bounded child process, so one timeout or failure is
reported without suppressing later collectors or cycles. Configuration changes take effect after
the service is restarted; credential values remain in the configured providers and never enter
process arguments.

Verification is offline:

```bash
python -m pytest tests/test_collectors.py tests/test_cli.py
```

The fake matrix covers success, partial data, authentication rejection, timeout, retry recovery,
retry exhaustion, unexpected failure isolation, concurrency, target refusal, cancellation, jitter,
status persistence, and known-secret removal from logs/database content.
