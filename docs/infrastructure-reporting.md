# Infrastructure reporting

CodexNet correlates SNMP and structured SSH observations to a canonical device only when the
collector target matches exactly one IPv4 device alias. Unmatched and reused-address targets remain
unattached and are disclosed under infrastructure data quality; hostnames are never used for this
join.

The deterministic JSON and self-contained DOCX contain switch-port maps, VLANs, neighbors, learned
MAC addresses, PoE observations, printer inventory and consumables, UPS metrics, environmental
readings, and firmware-version inventory. Each field retains all evidence with its source,
observation time, age, staleness, confidence, and native unit. Disagreeing values are shown as
alternatives and marked as conflicts instead of being silently overwritten. The default stale
threshold is seven days.

Bridge and PoE indexes are not assumed to be physical interface indexes. Without an explicit
mapping, the report labels them as unresolved. Unknown printer sentinel values are preserved as
status observations rather than converted to invented numeric readings.

Firmware and software versions are inventory facts only. CodexNet does not infer vulnerability or
support status from a version string. Reports remain local artifacts for manual upload; the
framework does not transmit them to external platforms.
