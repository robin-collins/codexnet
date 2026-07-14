-- Directory, infrastructure, correlation-audit, and report history domains.
CREATE TABLE ad_domains (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    domain_key TEXT NOT NULL,
    dns_name TEXT NOT NULL,
    forest_name TEXT,
    functional_level TEXT,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(deployment_id, domain_key, source, observed_at)
);

CREATE TABLE ad_entities (
    id INTEGER PRIMARY KEY,
    ad_domain_id INTEGER NOT NULL REFERENCES ad_domains(id) ON DELETE CASCADE,
    entity_key TEXT NOT NULL,
    entity_kind TEXT NOT NULL CHECK(entity_kind IN (
        'site', 'subnet', 'domain_controller', 'computer', 'group', 'user',
        'organizational_unit', 'server_role'
    )),
    display_name TEXT,
    dns_name TEXT,
    operating_system TEXT,
    attributes_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(attributes_json)),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(ad_domain_id, entity_key, source, observed_at)
);

CREATE TABLE ad_relationships (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    source_domain_id INTEGER REFERENCES ad_domains(id) ON DELETE CASCADE,
    target_domain_id INTEGER REFERENCES ad_domains(id) ON DELETE CASCADE,
    source_entity_id INTEGER REFERENCES ad_entities(id) ON DELETE CASCADE,
    target_entity_id INTEGER REFERENCES ad_entities(id) ON DELETE CASCADE,
    relationship_kind TEXT NOT NULL,
    attributes_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(attributes_json)),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    CHECK(source_domain_id IS NOT NULL OR source_entity_id IS NOT NULL),
    CHECK(target_domain_id IS NOT NULL OR target_entity_id IS NOT NULL)
);

CREATE TABLE infrastructure_readings (
    id INTEGER PRIMARY KEY,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_id INTEGER REFERENCES interfaces(id) ON DELETE SET NULL,
    asset_kind TEXT NOT NULL CHECK(asset_kind IN ('printer', 'ups', 'poe', 'environment')),
    metric TEXT NOT NULL,
    value_json TEXT NOT NULL CHECK(json_valid(value_json)),
    unit TEXT,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL
);

CREATE INDEX infrastructure_device_time
    ON infrastructure_readings(device_id, observed_at);

CREATE TABLE correlation_decisions (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    left_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    right_device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    decision TEXT NOT NULL CHECK(decision IN ('merge', 'keep_separate', 'conflict')),
    reason_json TEXT NOT NULL CHECK(json_valid(reason_json)),
    confidence REAL NOT NULL CHECK(confidence >= 0.0 AND confidence <= 1.0),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    CHECK(left_device_id <> right_device_id)
);

CREATE TABLE report_history (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    format TEXT NOT NULL CHECK(format IN ('docx', 'json')),
    relative_path TEXT NOT NULL,
    sha256_digest TEXT NOT NULL CHECK(length(sha256_digest) = 64),
    document_version TEXT NOT NULL,
    generated_at TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(relative_path, sha256_digest)
);
