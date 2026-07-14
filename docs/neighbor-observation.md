# Passive ARP and kernel-neighbor observation

`field_discovery.neighbor` normalizes two read-only evidence sources: bounded ARP payloads already
received by the passive pipeline and synthetic/already-decoded records shaped like `ip -j neighbour`
output. The module does not execute `ip`, open packet sockets, transmit ARP, or provide sweep logic.

ARP parsing accepts only Ethernet/IPv4 request and reply payloads, validates address lengths and an
independent size ceiling, and retains only the sender mapping and operation. Kernel records normalize
the destination, optional link-layer address, interface, and neighbour state; `INCOMPLETE` and
`FAILED` records remain visible without inventing a MAC address.

The tracker is bounded by entry count, observation age, and a deduplication interval. It records UTC
first/last-seen and validity times. Repeated evidence inside the dedupe window updates last-seen state
without emitting another record; later evidence emits the updated interval. Expiry produces a
structured tombstone and deletes the mapping.

An address observed with a different MAC emits `neighbor_ip_reuse`; a MAC observed at a different
address emits `neighbor_mac_movement`. The old and new evidence remain separate. These events are
conflicts for later correlation and never instruct it to merge devices by IP address.
