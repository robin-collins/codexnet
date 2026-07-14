# Identity normalization and correlation

CodexNet correlates observations conservatively and retains the evidence behind every decision.
Canonical identity values are normalized before lookup: MAC addresses use lower-case colon notation,
IPv4 addresses use canonical dotted decimal, hostnames use lower-case IDNA form, serials use
case-folded bounded text, and source IDs are scoped to the controller or authority that issued them.

Only a high-confidence MAC address, serial number, or scoped source ID can join observations into a
canonical device. Hostnames and IPv4 addresses are intentionally excluded from merge evidence
because DHCP, cloned systems, and reused names make them unsafe identity keys. Interface MACs are
stable evidence for the owning device, allowing observations of different interfaces to correlate
without losing the interface records.

Correlation sorts observations and evidence before processing, so input order cannot change the
result. Every join records both observation IDs, the exact typed evidence key, confidence, and a
human-readable reason. Canonical devices retain all aliases, interfaces, facts, sources, timestamps,
and confidence values rather than overwriting older claims.

The result reports reused hostnames and IP addresses across separate devices, conflicting serials
within a device joined by other stable evidence, and differing cross-source facts. These conflicts
remain available to repositories and reports for audit and operator review. Evidence below the
stable-identity confidence threshold remains attached to its observation but cannot cause a merge.
