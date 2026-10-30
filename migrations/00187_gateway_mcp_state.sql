-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Shared MCP state (G0 M15 D12/D13/D16/D39, HR-411..413): a gateway's MCP
-- holds, tasks, sessions and relayed elicitations, so every replica of the
-- gateway sees them and a restart loses nothing. Each entry is bound to
-- (connection, run, instance); a session also to its key thumbprint. key
-- is the SHA-256 of the canonical action (HOLD), of the task id (TASK) or
-- of the session id (SESSION): the ids themselves are never stored. Task
-- and elicitation bodies are sealed to the gateway's broker key and the
-- server never opens them. version moves by one per write
-- (compare-and-set). Expired rows are invisible and purged every minute
-- (gateway_mcp_state.purge).
-- +goose Up
CREATE TABLE pc.gateway_mcp_state (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    gateway_id    uuid        NOT NULL,
    kind          text        NOT NULL CHECK (kind IN ('HOLD', 'TASK', 'SESSION', 'ELICITATION')),
    key           bytea       NOT NULL CHECK (octet_length(key) = 32),
    connection_id uuid        NOT NULL,
    run_id        uuid,
    instance_id   uuid,
    jkt           text        CHECK (jkt IS NULL OR char_length(jkt) BETWEEN 1 AND 64),
    action_id     text        CHECK (action_id IS NULL OR char_length(action_id) BETWEEN 1 AND 64),
    status        text        CHECK (status IS NULL OR status IN ('working', 'completed', 'failed', 'cancelled')),
    busy          boolean     NOT NULL DEFAULT false,
    sealed_body   bytea       CHECK (sealed_body IS NULL OR octet_length(sealed_body) <= 4194304),
    version       bigint      NOT NULL CHECK (version > 0),
    expire_time   timestamptz NOT NULL,
    update_time   timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, gateway_id, kind, key),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id) ON DELETE CASCADE,
    CHECK (kind = 'SESSION' OR jkt IS NULL),
    CHECK (kind IN ('TASK', 'ELICITATION') OR (sealed_body IS NULL AND status IS NULL AND NOT busy)),
    CHECK (kind <> 'SESSION' OR action_id IS NULL),
    -- An elicitation (D39) carries a body and nothing of a task's.
    CHECK (kind <> 'ELICITATION' OR (sealed_body IS NOT NULL AND action_id IS NULL AND status IS NULL AND NOT busy)),
    -- Lifetimes (D42): a hold or task one hour, a session eight hours, an
    -- elicitation ten minutes, each with a minute for clock skew.
    CHECK (expire_time <= update_time + CASE kind WHEN 'SESSION' THEN interval '481 minutes'
        WHEN 'ELICITATION' THEN interval '11 minutes' ELSE interval '61 minutes' END)
);
CREATE INDEX gateway_mcp_state_instance ON pc.gateway_mcp_state (org_id, gateway_id, instance_id, kind);
CREATE INDEX gateway_mcp_state_expiry ON pc.gateway_mcp_state (org_id, expire_time);

ALTER TABLE pc.gateway_mcp_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.gateway_mcp_state FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.gateway_mcp_state
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.gateway_mcp_state
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT, DELETE ON pc.gateway_mcp_state TO pc_app;
-- The binding (connection, run, instance, key thumbprint) never changes
-- once written (D42).
GRANT UPDATE (action_id, status, busy, sealed_body, version, expire_time, update_time) ON pc.gateway_mcp_state TO pc_app;
GRANT SELECT (org_id, gateway_id, kind, connection_id, run_id, instance_id, action_id, status, busy, version, expire_time,
              update_time, created_at)
    ON pc.gateway_mcp_state TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.gateway_mcp_state TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.gateway_mcp_state;
