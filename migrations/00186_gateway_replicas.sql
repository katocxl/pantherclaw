-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Gateway status reports (G0 M15 D10/D11, HR-410): one row per gateway
-- process (replica) that reported, with the config version it serves and
-- each connection's serving state (ids, states and times only). A gateway
-- is connected while some replica reported in the last 90 seconds; rows
-- not seen for 24 hours are pruned hourly (gateway_replicas.prune).
-- +goose Up
CREATE TABLE pc.gateway_replicas (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    gateway_id     uuid        NOT NULL,
    replica_id     text        NOT NULL CHECK (replica_id ~ '^[A-Za-z0-9_-]{22}$'),
    version        text        NOT NULL CHECK (char_length(version) <= 64),
    build          text        NOT NULL CHECK (char_length(build) <= 64),
    start_time     timestamptz,
    config_version bigint      NOT NULL CHECK (config_version >= 0),
    connections    jsonb       NOT NULL DEFAULT '[]'
        CHECK (jsonb_typeof(connections) = 'array' AND octet_length(connections::text) <= 262144),
    last_seen      timestamptz NOT NULL,
    PRIMARY KEY (org_id, gateway_id, replica_id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id) ON DELETE CASCADE
);
CREATE INDEX gateway_replicas_seen ON pc.gateway_replicas (org_id, last_seen);

ALTER TABLE pc.gateway_replicas ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.gateway_replicas FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.gateway_replicas
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.gateway_replicas
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT, DELETE ON pc.gateway_replicas TO pc_app;
GRANT UPDATE (version, build, start_time, config_version, connections, last_seen) ON pc.gateway_replicas TO pc_app;
GRANT SELECT ON pc.gateway_replicas TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.gateway_replicas TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.gateway_replicas;
