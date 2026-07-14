-- Canonical inventory and historical network observations.
PRAGMA application_id = 1129203028;

CREATE TABLE deployments (
    id INTEGER PRIMARY KEY,
    site_key TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE TABLE collector_runs (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER REFERENCES deployments(id) ON DELETE CASCADE,
    collector TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('running', 'succeeded', 'partial', 'failed', 'cancelled')),
    interface_name TEXT,
    target_cidr TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    item_count INTEGER NOT NULL DEFAULT 0 CHECK(item_count >= 0),
    CHECK (finished_at IS NULL OR finished_at >= started_at)
);

CREATE INDEX collector_runs_deployment_time
    ON collector_runs(deployment_id, started_at);

CREATE TABLE collector_errors (
    id INTEGER PRIMARY KEY,
    collector_run_id INTEGER NOT NULL REFERENCES collector_runs(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    detail TEXT NOT NULL,
    retryable INTEGER NOT NULL CHECK(retryable IN (0, 1)),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL
);

CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    canonical_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT,
    UNIQUE(deployment_id, canonical_key)
);

CREATE TABLE device_aliases (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    alias_kind TEXT NOT NULL,
    alias_value TEXT NOT NULL,
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(device_id, alias_kind, alias_value, source, observed_at)
);

CREATE INDEX device_alias_lookup ON device_aliases(alias_kind, alias_value);

CREATE TABLE interfaces (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_key TEXT NOT NULL,
    name TEXT,
    description TEXT,
    media_type TEXT,
    mac_address TEXT,
    operational_state TEXT,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(device_id, interface_key, source, observed_at)
);

CREATE TABLE subnets (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    cidr TEXT NOT NULL,
    gateway_address TEXT,
    dns_addresses_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(dns_addresses_json)),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(deployment_id, cidr, source, observed_at)
);

CREATE TABLE vlans (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    vlan_number INTEGER NOT NULL CHECK(vlan_number BETWEEN 0 AND 4094),
    name TEXT,
    subnet_id INTEGER REFERENCES subnets(id) ON DELETE SET NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(deployment_id, vlan_number, source, observed_at)
);

CREATE TABLE interface_vlan_observations (
    id INTEGER PRIMARY KEY,
    interface_id INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    vlan_id INTEGER NOT NULL REFERENCES vlans(id) ON DELETE CASCADE,
    mode TEXT,
    tagged INTEGER CHECK(tagged IN (0, 1)),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(interface_id, vlan_id, source, observed_at)
);

CREATE TABLE address_assignments (
    id INTEGER PRIMARY KEY,
    device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    interface_id INTEGER REFERENCES interfaces(id) ON DELETE CASCADE,
    address_kind TEXT NOT NULL CHECK(address_kind IN ('ipv4', 'mac')),
    address TEXT NOT NULL,
    assignment_method TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    CHECK(device_id IS NOT NULL OR interface_id IS NOT NULL),
    CHECK(last_seen_at >= first_seen_at),
    UNIQUE(address_kind, address, device_id, interface_id, source, observed_at)
);

CREATE INDEX address_assignment_lookup ON address_assignments(address_kind, address);

CREATE TABLE services (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_id INTEGER REFERENCES interfaces(id) ON DELETE SET NULL,
    transport TEXT NOT NULL,
    port INTEGER NOT NULL CHECK(port BETWEEN 0 AND 65535),
    service_name TEXT,
    product TEXT,
    version TEXT,
    state TEXT,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(device_id, transport, port, source, observed_at)
);

CREATE TABLE software_observations (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    software_kind TEXT NOT NULL,
    product TEXT,
    vendor TEXT,
    version TEXT,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL
);

CREATE TABLE observations (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject_id INTEGER,
    fact_type TEXT NOT NULL,
    fact_value_json TEXT NOT NULL CHECK(json_valid(fact_value_json)),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    inferred INTEGER NOT NULL DEFAULT 0 CHECK(inferred IN (0, 1)),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL
);

CREATE INDEX observations_subject_time
    ON observations(subject_type, subject_id, observed_at);

CREATE TABLE topology_edges (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    local_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    remote_device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    local_interface_id INTEGER REFERENCES interfaces(id) ON DELETE SET NULL,
    remote_interface_id INTEGER REFERENCES interfaces(id) ON DELETE SET NULL,
    remote_identifier TEXT,
    edge_kind TEXT NOT NULL,
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    valid_from TEXT NOT NULL,
    valid_until TEXT,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    CHECK(remote_device_id IS NOT NULL OR remote_identifier IS NOT NULL),
    CHECK(valid_until IS NULL OR valid_until >= valid_from)
);

CREATE TABLE artifacts (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER REFERENCES deployments(id) ON DELETE CASCADE,
    collector_run_id INTEGER REFERENCES collector_runs(id) ON DELETE SET NULL,
    relative_path TEXT NOT NULL,
    sha256_digest TEXT NOT NULL CHECK(length(sha256_digest) = 64),
    media_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
    collected_at TEXT NOT NULL,
    imported_at TEXT,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(relative_path, sha256_digest)
);
