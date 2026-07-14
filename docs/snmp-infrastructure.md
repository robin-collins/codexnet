# SNMP infrastructure domains

The default SNMP registry extends the base system/interface/address/LLDP profile with numeric OIDs
from BRIDGE-MIB, IP-MIB's legacy neighbor table, Q-BRIDGE-MIB, POWER-ETHERNET-MIB,
ENTITY-SENSOR-MIB, UPS-MIB, Printer-MIB, and ENTITY-MIB. Numeric OIDs keep collection offline and
avoid runtime MIB downloads or compilation.

The normalized domains cover:

- bridge learned MAC, bridge port, and learning status;
- ARP/neighbor interface, MAC, IPv4 address, and dynamic/static status;
- VLAN name, egress/forbidden/untagged port bitmaps, and row status;
- PoE administrative/detection/priority/class state plus power budget and consumption;
- physical sensor type, scale, precision, raw value, state, displayed unit, and timestamp;
- UPS battery state, time on battery, remaining runtime/charge, voltage, current, and temperature;
- printer serial, marker counters, supply metadata, maximum capacity, and current level;
- hardware firmware/software revision, model, and serial inventory.

Values stay in their MIB-native units. For example, UPS voltage is retained as `0.1 V DC`, UPS
current as `0.1 A DC`, and ENTITY-SENSOR values retain separate scale, precision, displayed unit,
and centisecond timestamp facts. Enumeration codes are preserved alongside a known label. Unknown
enumeration codes retain the numeric value without inventing a label. Printer sentinel values such
as `unknown` and `some_remaining` retain the raw code, a status, and `null` value rather than being
misreported as a measured negative quantity.

Every fact is stored with the SNMP source, collection timestamp, target, and table index. Missing
columns produce no synthetic fact. Invalid values become explicit partial-collection issues. Table
and unknown-OID limits from the T401 collector still apply to all infrastructure profiles.

Firmware collection is inventory only. It records the agent-provided version string and collection
age; it never claims a version is vulnerable, secure, supported, or current without a separately
maintained advisory source outside this task.

Verification uses only the sanitized synthetic fixtures under `tests/fixtures/snmp/`. They model
standard-MIB responses commonly exposed by Cisco-compatible and Aruba-compatible switches, a UPS,
a printer, and an environmental sensor. No test opens an SNMP socket or includes customer data.
