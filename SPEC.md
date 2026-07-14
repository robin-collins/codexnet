# Field Network Discovery Appliance Specification

## 1. Purpose

Build the Raspberry Pi into a self-contained, portable network discovery and documentation appliance for authorised customer-site assessments.

The appliance must gather network observations over several days, correlate them into a durable local inventory, and produce useful documentation without requiring continuous operator attention or Internet access.

This specification covers the discovery framework described in the chat log through and including **“What I'd add beyond the initial list.”**

## 2. Current State

The following are already complete and must not be rebuilt unless integration requires a small, documented change:

- Raspberry Pi base/headless setup.
- Scanopy installation and operation.
- `/usr/local/sbin/network-discovery-scan.sh` active nmap discovery script.
- Root cron schedule for the nmap script.
- Automatic subnet selection from the customer-facing interface.

The new framework must coexist with Scanopy and treat the existing nmap process as an input/integration point rather than silently creating a competing scan schedule.

## 3. Goals

The finished appliance must:

1. Learn the IPv4 subnet attached to the configured customer-facing interface.
2. Observe passive discovery traffic continuously while deployed.
3. Ingest active nmap scan results produced by the existing scheduled script.
4. Poll authorised devices using SNMP.
5. Detect UniFi controllers and collect data when credentials are supplied.
6. Detect Active Directory and collect directory data when credentials are supplied.
7. Collect operational data from supported Cisco, HP, and Aruba devices over SSH when credentials are supplied.
8. Normalize and retain all observations in a local SQLite database.
9. Correlate devices across IP address, MAC address, hostname, serial number, and source-specific identifiers.
10. Generate topology diagrams, inventories, audits, port maps, and customer-ready reports.
11. Export a polished Microsoft Word `.docx` report suitable for direct upload to IT Glue, Datto RMM, or Autotask.
12. Continue operating through reboots, temporary network loss, missing credentials, and individual collector failures.

## 4. Non-Goals and Safety Boundaries

- The appliance must only be used on networks for which the operator has explicit authorization.
- It will not exploit vulnerabilities, dump credentials, crack passwords, modify customer devices, change configurations, or perform denial-of-service testing.
- AD support is inventory/documentation collection, not offensive enumeration. Do not include `secretsdump`, Kerberoasting, AS-REP roasting, or equivalent credential-access workflows.
- Collectors must be read-only wherever the target API or protocol supports read-only access.
- No customer credentials may be embedded in source code, command-line arguments, reports, logs, or the SQLite database.
- No customer data may be uploaded externally by the framework. Uploading completed reports to IT Glue, Datto RMM, or Autotask is an explicit manual operator action.
- The framework will initially support one directly connected IPv4 subnet. Routed subnet discovery and IPv6 expansion are future work.
- Scanopy remains a separate product. Direct integration with its private database is out of scope unless a supported API is available and deliberately configured.

## 5. Implementation Direction

Use Python 3 with a dedicated virtual environment. Python is preferred because the required protocol, parsing, reporting, and network-automation libraries are mature on ARM64.

Install the application under `/opt/field-discovery` with these operational paths:

| Purpose | Path |
|---|---|
| Application and virtual environment | `/opt/field-discovery` |
| Non-secret configuration | `/etc/field-discovery/config.yaml` |
| Secret environment/config file | `/etc/field-discovery/secrets.env` |
| SQLite database | `/var/lib/field-discovery/discovery.db` |
| Raw collector artifacts | `/var/lib/field-discovery/artifacts` |
| Generated reports | `/var/lib/field-discovery/reports` |
| Logs | systemd journal |

Run under a dedicated unprivileged `field-discovery` service account. Grant only the specific Linux capabilities or group access required for packet capture and discovery. Do not run the entire framework as root.

## 6. Architecture

The framework consists of:

- **Interface/subnet resolver:** selects a configured interface (default `eth0`), reads its assigned address, and normalizes it to the network CIDR.
- **Passive observation service:** continuously records useful LLDP/CDP, mDNS, DHCP, ARP, and neighbor evidence without transmitting probes beyond normal protocol behavior.
- **Artifact importer:** detects completed nmap XML output from the existing scan directory and imports each file exactly once.
- **Collector scheduler:** runs SNMP, controller, directory, and SSH collectors independently at configurable intervals with jitter, timeouts, and retry limits.
- **Collectors:** protocol/vendor adapters returning a common normalized data model.
- **Normalizer/correlator:** merges observations into devices, interfaces, addresses, services, relationships, and time-bounded facts while preserving provenance.
- **SQLite repository:** stores normalized records, observation history, collector runs, and artifact import state.
- **Report engine:** produces a polished Word `.docx` report with embedded diagrams and tables, plus internal machine-readable JSON and diagram source files.
- **CLI:** configuration validation, credentials setup, one-shot collection, status, report generation, database maintenance, and diagnostics.

Every collector must fail independently. A failed or unconfigured collector must not stop passive observation, nmap import, other collectors, or reporting.

## 7. Functional Requirements

### 7.1 Interface and subnet discovery

- Default to `eth0`, configurable in YAML.
- Determine the first global IPv4 address and its normalized network CIDR.
- Ignore Docker, loopback, Tailscale, and Wi-Fi interfaces unless explicitly selected.
- Record interface, address, CIDR, gateway, DNS servers, and DHCP-derived metadata for each deployment.
- Refuse broad or unexpected active targets unless permitted by configured maximum prefix/range safeguards.
- Expose the resolved interface and CIDR in CLI status and collector-run records.

### 7.2 Passive discovery

Continuously collect and timestamp:

- LLDP and CDP neighbor advertisements, including chassis ID, port ID, system name, description, capabilities, management address, VLAN information, and TTL when present.
- mDNS/DNS-SD services, instance names, hostnames, addresses, service types, and TXT metadata.
- DHCP server/offers/acknowledgements visible to the Pi, including client MAC, offered address, hostname, vendor class, lease information, router, DNS, and domain options where observable.
- ARP traffic and Linux neighbor-table changes, including IP-to-MAC mappings and state.

Packet capture must use bounded parsing and must not retain unrestricted full packet captures by default. Store structured observations; permit short diagnostic captures only through an explicit CLI action with retention controls.

### 7.3 Active nmap integration

- Discover XML artifacts under the existing `/var/log/network-discovery` result tree; make the path configurable.
- Import host state, addresses, MAC/vendor, hostnames, OS guesses, ports, protocols, services, versions, scripts, and scan metadata.
- Track artifact path plus cryptographic digest so repeat scans are retained as observations but the same file is never imported twice.
- Preserve raw nmap output according to the existing retention policy; do not alter the cron schedule.
- Provide a safe CLI command to invoke the existing script manually when the operator explicitly requests a scan.

### 7.4 SNMP collection

- Support SNMPv3 as the preferred mode and SNMPv2c when explicitly enabled.
- Never attempt default or guessed community strings.
- Collect, where supported: system identity, uptime, firmware/software version, serial/model, interfaces, addresses, bridge MAC table, ARP/neighbor table, VLANs, LLDP neighbors, PoE status, environmental sensors, UPS state/battery, and printer consumables/page counts.
- Use bounded concurrency, per-host timeout, retry limits, and configurable OID profiles.
- Retain unknown OIDs in raw artifacts when useful, while normalizing known facts.
- Record authentication/authorization failures without exposing secrets.

### 7.5 UniFi collection

- Detect likely UniFi controllers from nmap services, DNS/mDNS, and known controller endpoints without aggressive probing.
- Support explicitly configured UniFi OS and legacy controller endpoints.
- Collect sites, gateways, switches, APs, clients, networks/VLANs, WLANs, port profiles, device/port status, topology/neighbor data, firmware, alarms, and events where the account permits.
- Use a read-only account where available.
- Handle self-signed certificates only through an explicit per-controller setting; verification remains enabled by default.
- Store controller-specific IDs as aliases that correlate with normalized devices.

### 7.6 Active Directory collection

- Detect AD using DNS SRV records, Kerberos/LDAP/LDAPS/SMB services, and RootDSE.
- Allow collection only after credentials and an approved domain/base DN are configured.
- Prefer Kerberos or LDAPS; make plaintext LDAP opt-in and clearly reported.
- Collect domain/forest identity, sites/subnets, domain controllers, DNS names, computers, operating-system attributes, groups and memberships needed for documentation, organizational units, trusts, and relevant server roles when readable.
- Generate an AD infrastructure diagram focused on domains, trusts, sites, subnets, domain controllers, and server/computer placement.
- Do not collect password material, hashes, tickets, secrets, or attack-path data.

### 7.7 Cisco, HP, and Aruba SSH collection

- Use Netmiko with TextFSM/NTC Templates initially; permit NAPALM adapters where they provide reliable normalized getters.
- Require explicit device credentials and target approval. Do not brute-force or cycle credentials across unapproved targets.
- Identify platform conservatively from existing observations, SSH banners, SNMP facts, or explicit configuration.
- Execute read-only commands for facts, inventory, firmware, interfaces/status, VLANs, MAC tables, ARP/neighbor tables, LLDP/CDP neighbors, PoE, environment, and configuration metadata.
- Configuration content is excluded by default; an explicit setting may permit sanitized read-only configuration backup in a later phase.
- Preserve sanitized raw command output for troubleshooting and future parser improvement.

### 7.8 Data model and SQLite

At minimum model:

- deployments/sites;
- subnets and VLANs;
- devices and device aliases;
- interfaces and switch ports;
- MAC and IP address assignments with first/last seen times;
- services and software/firmware observations;
- users/groups/computers and AD relationships where enabled;
- neighbors and topology edges with source, confidence, and validity interval;
- printers, consumables, UPS, PoE, and environmental readings;
- collector runs, errors, raw artifacts, and source provenance;
- report-generation history.

Requirements:

- Enable foreign keys and WAL mode.
- Apply numbered, repeatable schema migrations.
- Preserve observation history rather than overwriting changing facts.
- Make correlation deterministic and explainable. Never merge solely on hostname or a reused DHCP address.
- Support database backup, integrity check, retention pruning, and export to sanitized JSON.

### 7.9 Reporting and diagrams

Generate per-deployment outputs containing:

- Executive summary and collection coverage/limitations.
- Device inventory with identity, role, addresses, vendor/model/serial, OS/firmware, first/last seen, and evidence sources.
- Service inventory.
- Network topology diagram derived from LLDP/CDP, switch MAC tables, UniFi topology, ARP, and observed gateways, with confidence/source represented.
- VLAN and subnet diagram.
- Switch port maps including link state, VLAN, PoE, learned MACs, and neighbors where known.
- AD domain/site/trust/domain-controller diagram when AD collection is configured.
- Firmware audit listing discovered versions and data age. It must not assert vulnerability status without a separately maintained, sourced advisory feed.
- Printer inventory and consumable state.
- UPS and infrastructure health summary.
- Data-quality section listing conflicts, unknowns, stale facts, failed collectors, and missing credentials.

Output formats:

- Microsoft Word `.docx` as the primary customer deliverable.
- Machine-readable JSON containing the normalized report data for troubleshooting and future integrations.
- Mermaid or Graphviz source plus rendered PNG/SVG diagrams used in the Word report.

The Word report must:

- open correctly in current Microsoft Word and LibreOffice;
- use a configurable company/customer template when supplied;
- include customer name, site, assessment dates, author, document version, confidentiality marking, and generation timestamp;
- contain a title page, automatic table of contents, numbered headings, page numbers, headers/footers, and consistent table styling;
- embed topology, VLAN, switch-port, and AD diagrams at readable resolution;
- repeat table headings across pages and use landscape sections for wide inventories where needed;
- include collection coverage, failed collectors, evidence age, assumptions, and limitations;
- avoid external links or resources required to render the document;
- use stable filenames suitable for direct upload, such as `Customer-Site-Network-Discovery-YYYYMMDD.docx`.

Reports must redact credentials, authentication headers, SNMP communities, tokens, and configured sensitive fields.

### 7.10 CLI and operations

Provide a single command, tentatively `field-discovery`, with at least:

- `config validate`
- `status`
- `discover subnet`
- `collect passive status`
- `collect snmp [--target ...]`
- `collect unifi [--controller ...]`
- `collect ad [--domain ...]`
- `collect ssh [--target ...]`
- `import nmap [--path ...]`
- `scan nmap` (explicitly invokes the existing script)
- `report generate --format docx`
- `report validate <report.docx>`
- `db check`, `db backup`, and `db prune`
- `doctor` for dependency, permission, database, interface, clock, and service checks.

Commands must return meaningful exit codes and offer human-readable output plus optional JSON output.

### 7.11 Services and scheduling

Provide systemd units for:

- continuous passive observation;
- scheduled collector orchestration;
- nmap artifact import/report refresh, preferably via path monitoring or a timer that does not conflict with the existing cron job.

Services must:

- start after the selected network interface is usable;
- restart on recoverable failure with rate limits;
- use systemd hardening appropriate to required capabilities;
- write structured, secret-free logs to journald;
- expose last-success, last-failure, duration, and item counts through `field-discovery status`.

## 8. Configuration and Credential Handling

Non-secret configuration belongs in YAML and includes interface, paths, intervals, timeouts, concurrency, enabled collectors, approved target ranges, and report settings.

Secrets must be supplied using a root-readable environment file or a pluggable secret-command mechanism. The initial implementation must:

- create secret files with mode `0600` and a restricted owner/group;
- never accept passwords directly as ordinary command-line flags;
- redact secrets and common encoded forms from logs and exception messages;
- support separate credential profiles for SNMP, UniFi, AD, and SSH;
- permit credential rotation without changing application code;
- avoid storing secrets in SQLite or generated artifacts.

## 9. Reliability, Performance, and Retention

- Target Raspberry Pi 4B with 8 GB RAM and ARM64 Raspberry Pi OS/Debian.
- Limit memory and CPU consumption so Scanopy remains responsive.
- All network calls require explicit timeouts.
- Use bounded worker pools and scheduler jitter to avoid traffic bursts.
- Database writes must be transactional and resilient to duplicate input.
- Resume cleanly after reboot; incomplete runs must be marked, not mistaken for success.
- Default raw artifacts and detailed observations to 30-day retention, configurable per data class.
- Retain normalized device first/last-seen history longer than raw artifacts.
- Provide disk-space thresholds that pause artifact-heavy work before filling the filesystem.

## 10. Testing and Verification

The repository must include:

- Unit tests for subnet selection, parsers, normalization, correlation, redaction, report queries, and Word document generation.
- Fixture-based tests using sanitized nmap XML, SNMP responses, UniFi responses, LDAP records, and vendor CLI output.
- Migration tests from an empty database through the current schema.
- Integration tests using mocks or disposable local services; tests must not scan arbitrary networks.
- Static checks and formatting with documented commands.
- An installation verification script or `doctor` command suitable for the Pi.

## 11. Delivery Phases

### Phase 1: Foundation and existing-scan integration

- Project structure, packaging, configuration, logging, CLI, SQLite schema/migrations.
- Interface/subnet resolver.
- Existing nmap XML importer and normalized inventory.
- Basic Word `.docx` and JSON inventory report.
- Service account, directories, installation script, and systemd integration.

### Phase 2: Passive discovery

- LLDP/CDP, mDNS, DHCP, ARP/neighbor observations.
- Continuous service, retention, and topology-edge normalization.
- Initial Mermaid topology and VLAN/subnet diagrams.

### Phase 3: Infrastructure collectors

- SNMP collector and device profiles.
- Cisco/HP/Aruba SSH collector.
- Switch port maps, printer inventory, UPS/environment data, and firmware report.

### Phase 4: Controller and directory collectors

- UniFi detection and API collection.
- AD detection and credential-gated LDAP/Kerberos collection.
- UniFi topology enrichment and AD diagrams.

### Phase 5: Word reporting and hardening

- Production-quality Word template support, embedded diagram rendering, pagination, and report validation.
- Backup/pruning, disk safeguards, security review, performance tuning, complete operator documentation.

## 12. Definition of Done

The build is complete when, on the target Pi:

1. Installation is repeatable and does not disrupt Scanopy or the existing nmap cron job.
2. Reboot restores all enabled framework services without manual intervention.
3. The framework selects `eth0`, resolves its current CIDR, and visibly reports that decision.
4. Existing nmap XML is imported once and appears as normalized, historical device/service data.
5. Passive observations enrich devices and topology continuously without storing unrestricted packet captures.
6. Each configured SNMP, UniFi, AD, and SSH collector produces normalized records; an unconfigured or failed collector leaves all other functions operational.
7. SQLite integrity and migrations pass, correlation is provenance-aware, and secrets do not appear in the database.
8. A validated, self-contained Word `.docx` report is generated with the required inventories and embedded diagrams; unsupported or missing evidence is reported honestly.
9. The report uses a stable customer/site filename and is ready for manual upload to IT Glue, Datto RMM, or Autotask without conversion.
10. Tests pass on the development host and the `doctor` check passes on the Pi.
11. Logs, reports, artifacts, process arguments, and configuration files have been checked for credential leakage.
12. Operator documentation explains installation, configuration, credential profiles, normal operation, report retrieval, troubleshooting, backup, upgrade, and removal.

## 13. Decisions to Preserve During Implementation

- Integrate the current nmap job; do not create a second hidden active scanner.
- Prefer passive and read-only collection.
- Credentials unlock collectors but are never required for the core appliance to run.
- Preserve raw evidence selectively and always preserve normalized provenance.
- Reports distinguish observed facts, inferred relationships, conflicts, and unknowns.
- Offline-first operation and recoverability take priority over cloud dependencies.
