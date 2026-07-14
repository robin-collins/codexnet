-- Historical UniFi controller entities linked to canonical device inventory.
CREATE TABLE unifi_sites (
    id INTEGER PRIMARY KEY,
    deployment_id INTEGER NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    controller_key TEXT NOT NULL,
    site_key TEXT NOT NULL,
    display_name TEXT,
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(deployment_id, controller_key, site_key, source, observed_at)
);

CREATE TABLE unifi_entities (
    id INTEGER PRIMARY KEY,
    unifi_site_id INTEGER NOT NULL REFERENCES unifi_sites(id) ON DELETE CASCADE,
    canonical_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    entity_kind TEXT NOT NULL CHECK(entity_kind IN (
        'gateway', 'switch', 'access_point', 'client', 'network', 'wlan',
        'port_profile', 'port', 'alarm', 'event'
    )),
    controller_entity_id TEXT NOT NULL,
    display_name TEXT,
    state TEXT,
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    last_seen_at TEXT,
    attributes_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(attributes_json)),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE(unifi_site_id, entity_kind, controller_entity_id, source, observed_at)
);

CREATE INDEX unifi_entity_controller_lookup
    ON unifi_entities(unifi_site_id, entity_kind, controller_entity_id);

CREATE TABLE unifi_relationships (
    id INTEGER PRIMARY KEY,
    unifi_site_id INTEGER NOT NULL REFERENCES unifi_sites(id) ON DELETE CASCADE,
    local_entity_id INTEGER NOT NULL REFERENCES unifi_entities(id) ON DELETE CASCADE,
    remote_entity_id INTEGER REFERENCES unifi_entities(id) ON DELETE CASCADE,
    remote_identifier TEXT,
    relationship_kind TEXT NOT NULL,
    attributes_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(attributes_json)),
    source TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    CHECK(remote_entity_id IS NOT NULL OR remote_identifier IS NOT NULL)
);

CREATE UNIQUE INDEX unifi_relationship_exact
    ON unifi_relationships(
        local_entity_id,
        ifnull(remote_entity_id, -1),
        ifnull(remote_identifier, ''),
        relationship_kind,
        source,
        observed_at
    );
