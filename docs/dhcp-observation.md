# Passive DHCP observation

`field_discovery.dhcp.DhcpParser` is a synchronous parser for DHCPv4 payloads already captured by
the bounded passive ingestion framework. It creates no sockets, sends no packets, and cannot act as
a DHCP client, relay, or server. The parser has no artifact writer and never places the input payload
in a `PassiveObservation`.

Frames have an independent 4096-byte parser ceiling in addition to the pipeline limit. BOOTP header
fields and DHCP TLVs are bounds-checked; malformed lengths, duplicate options, missing end markers,
invalid message/operation combinations, and invalid fixed-width options reject only that frame.
Unknown options are ignored.

The normalized observation retains the message type and transaction ID, visible client MAC/client
identifier, client/requested/assigned address, server and relay identity, lease/renewal/rebinding
times, hostname, vendor class, router and DNS lists, domain, interface, and an explicit renewal flag.
Text fields pass through the central redactor before reaching the pipeline. Lease expiry is derived
from the observation timestamp.

The optional stateful wrapper tracks only a bounded address-to-client mapping. A later ACK assigning
the same address to a different visible client emits a structured `dhcp_address_reuse` conflict while
preserving both identities. Eviction is deterministic and no packet bytes are retained.
