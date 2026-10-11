-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Sandbox sessions (G0 M9 track B slice B4; PN-008.2, F454, F457; HR-121,
-- HR-215; T-087). A person or service account holding sandbox.run opens a
-- session for an agent and the connections it maps: the server records the
-- images and configuration digest the sandbox runs, the engine, and the
-- public half of the probe key pclaw created outside every container, and
-- mints the enrollment of a new sandbox instance of the agent. That
-- instance, once the launcher admitted it, is the only identity the edge
-- signs with; it can act only inside the session, which ends at its expiry
-- (at most 24 hours, design decision 9).
--
-- sandbox_session_connections are the connections a session maps; each
-- gets its own closure (coverage_closures, recorded through the closure
-- contract once the session's reports verified).
--
-- coverage_closures.sandbox_session_id gains its foreign key (the closure
-- contract), agent_instances gains the session of a sandbox instance (the
-- coverage calculus counts every active instance, design decision 2), and
-- connections gain agent_hosts: at most 16 host names agents use for the
-- connection's API, distinct from its dispatch base URL. The edge maps them
-- to the connection; changing them is a weakening change (HR-183).

-- +goose Up
CREATE TABLE pc.sandbox_sessions (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    agent_id            uuid        NOT NULL,
    -- The person or service account that opened the session.
    launcher            text        NOT NULL CHECK (char_length(launcher) BETWEEN 1 AND 100),
    enrollment_token_id uuid        NOT NULL,
    instance_id         uuid,
    run_id              uuid,
    agent_image         text        NOT NULL CHECK (agent_image ~ '^sha256:[0-9a-f]{64}$'),
    edge_image          text        NOT NULL CHECK (edge_image ~ '^sha256:[0-9a-f]{64}$'),
    probe_image         text        NOT NULL CHECK (probe_image ~ '^sha256:[0-9a-f]{64}$'),
    config_digest       text        NOT NULL CHECK (config_digest ~ '^sha256:[0-9a-f]{64}$'),
    -- The probe key: its RFC 7638 thumbprint and the raw Ed25519 key.
    probe_jkt           text        NOT NULL CHECK (probe_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    probe_public_key    bytea       NOT NULL CHECK (octet_length(probe_public_key) = 32),
    engine_version      text        NOT NULL CHECK (engine_version ~ '^[0-9A-Za-z.+_-]{1,64}$'),
    api_version         text        NOT NULL CHECK (api_version ~ '^[0-9]{1,3}\.[0-9]{1,3}$'),
    runtime             text        NOT NULL CHECK (runtime IN ('runc', 'runsc')),
    state               text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'ENDED', 'EXPIRED')),
    opened_at           timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    ended_at            timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, enrollment_token_id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, enrollment_token_id) REFERENCES pc.enrollment_tokens (org_id, id),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id),
    CONSTRAINT sandbox_sessions_lifetime CHECK (expires_at > opened_at AND expires_at <= opened_at + interval '24 hours'),
    CONSTRAINT sandbox_sessions_ended CHECK ((state = 'OPEN') = (ended_at IS NULL))
);
CREATE INDEX sandbox_sessions_agent ON pc.sandbox_sessions (org_id, agent_id, id DESC);
CREATE INDEX sandbox_sessions_open ON pc.sandbox_sessions (org_id, expires_at) WHERE state = 'OPEN';

CREATE TABLE pc.sandbox_session_connections (
    org_id        uuid NOT NULL REFERENCES pc.orgs (id),
    session_id    uuid NOT NULL,
    connection_id uuid NOT NULL,
    PRIMARY KEY (org_id, session_id, connection_id),
    FOREIGN KEY (org_id, session_id) REFERENCES pc.sandbox_sessions (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id)
);

ALTER TABLE pc.coverage_closures
    ADD CONSTRAINT coverage_closures_session_fk FOREIGN KEY (org_id, sandbox_session_id) REFERENCES pc.sandbox_sessions (org_id, id);

ALTER TABLE pc.agent_instances ADD COLUMN sandbox_session_id uuid;
ALTER TABLE pc.agent_instances
    ADD CONSTRAINT agent_instances_sandbox_session_fk FOREIGN KEY (org_id, sandbox_session_id) REFERENCES pc.sandbox_sessions (org_id, id);

ALTER TABLE pc.connections ADD COLUMN agent_hosts text[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(agent_hosts) <= 16 AND array_to_string(agent_hosts, ',') ~ '^([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(,|$))*$');

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['sandbox_sessions', 'sandbox_session_connections']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.sandbox_sessions, pc.sandbox_session_connections TO pc_app;
GRANT UPDATE (instance_id, run_id, state, ended_at) ON pc.sandbox_sessions TO pc_app;
GRANT UPDATE (sandbox_session_id) ON pc.agent_instances TO pc_app;
GRANT UPDATE (agent_hosts) ON pc.connections TO pc_app;
GRANT SELECT ON pc.sandbox_sessions, pc.sandbox_session_connections TO pc_audit_ro;

-- +goose Down
REVOKE UPDATE (agent_hosts) ON pc.connections FROM pc_app;
ALTER TABLE pc.connections DROP COLUMN agent_hosts;
ALTER TABLE pc.agent_instances DROP CONSTRAINT agent_instances_sandbox_session_fk;
ALTER TABLE pc.agent_instances DROP COLUMN sandbox_session_id;
ALTER TABLE pc.coverage_closures DROP CONSTRAINT coverage_closures_session_fk;
DROP TABLE pc.sandbox_session_connections;
DROP TABLE pc.sandbox_sessions;
