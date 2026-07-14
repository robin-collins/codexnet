# Network-device SSH collection

`field_discovery.ssh_collection` is the read-only SSH boundary for Cisco IOS, HP/HPE Comware,
and ArubaOS-Switch devices. A target must first pass the shared collector framework's IPv4
approval check, and collection requires an opaque credential reference. Passwords and private-key
passphrases are resolved in memory from a restricted environment file or a helper invoked with the
reference key on standard input. They are never accepted as CLI options.

Platform selection is deliberately conservative. An operator can explicitly select a supported
platform, or an adapter can supply existing banner/SNMP/inventory evidence. Evidence must identify
exactly one family; missing, generic, conflicting, and unknown evidence is rejected. SSH itself is
not used to cycle through platform drivers or credentials.

## Command boundary

Each platform has an exact, reviewable allowlist in `COMMAND_PROFILES`. It contains one
session-local paging command and operational display/show commands for identity, inventory,
firmware, interfaces, VLANs, MAC/ARP tables, neighbors, PoE, and environment. The executor checks
exact string membership immediately before every call. Abbreviations, extra arguments,
configuration display, configuration mode, copy/save/write, reload, and arbitrary operator input
are rejected. The collector never enters enable or configuration mode.

The paging commands (`terminal length 0`, `screen-length disable`, and `no page`) affect only the
interactive session. A paging marker that remains in output is sanitized and disclosed as a
partial-result issue.

## Sessions, parsing, and artifacts

The collector uses a small asynchronous session protocol. `NetmikoSessionFactory` is the live
adapter and imports Netmiko only when an actual SSH connection is requested, allowing the core and
offline test environment to remain dependency-safe. A deployed SSH-enabled appliance must install
Netmiko and its TextFSM/NTC template support. Session fakes implement the same boundary for tests;
tests never contact a live device.

Netmiko structured output is stored as provenance-aware observations. When no TextFSM template
matches, the raw text is retained and the observation is explicitly marked as a parse fallback,
not presented as fully parsed data. Each command's bounded output is centrally redacted before it
is atomically written under the CodexNet artifact root with mode `0600`, a digest, and retention
metadata. Artifacts and SQLite values are scanned in tests for credential patterns.

Authentication errors and timeouts are mapped to the shared collector lifecycle without their
underlying exception text. A command-level parse or bounded-output failure produces a partial run
and does not discard successful commands. Transport authentication/timeout failures stop that
target, close the session, and remain isolated from other collector requests.

## Verification

The offline matrix covers all three vendor families, explicit and evidence-based platform
selection, unknown/ambiguous evidence, every exact allowlist, common write/configuration command
rejection, paging, authentication and timeout mapping, parse fallback, partial/oversized output,
cancellation, credential-provider restrictions, Netmiko adapter mapping, artifact redaction, and
repository provenance:

```bash
python -m pytest tests/test_ssh_collection.py
```

No fixture contains a real customer identifier or usable credential.
