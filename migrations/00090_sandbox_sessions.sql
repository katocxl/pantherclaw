-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Sandbox sessions (G0 M9 track B slice B4; PN-008.2, F454, F457; HR-121,
-- HR-215; T-087). A person or service account holding sandbox.run opens a
-- session for an agent and the connections it maps: the server records the
-- images and configuration digest the sandbox runs, the engine, and the
-- public halves of the two keys pclaw created outside every container:
-- the probe key, which signs only the sandbox report, and the host key,
-- which never enters a container and signs the control and canary
-- reports (HR-215). It then mints the enrollment of a new sandbox instance
-- of the agent. That instance, once the launcher admitted it, is the only
-- identity the edge signs with; it can act only inside the session, which
-- ends at its expiry (at most 24 hours, design decision 9).
--
-- sandbox_session_connections are the connections a session maps, with
-- their bindings when it opened; each gets its own closure
-- (coverage_closures, recorded through the closure contract once the
-- session's reports verified, while those bindings still hold).
--
-- coverage_closures.sandbox_session_id gains its foreign key (the closure
-- contract), agent_instances gains the session of a sandbox instance, set
-- from its enrollment token when it enrols (the coverage calculus counts
-- every active instance, design decision 2), and connections gain
-- agent_hosts: at most 16 host names agents use for the connection's API,
-- distinct from its dispatch base URL. The edge maps them to the
-- connection; changing them is a weakening change (HR-183).

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
    -- The probe and host keys: RFC 7638 thumbprints and raw Ed25519 keys.
    probe_jkt           text        NOT NULL CHECK (probe_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    probe_public_key    bytea       NOT NULL CHECK (octet_length(probe_public_key) = 32),
    host_jkt            text        NOT NULL CHECK (host_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    host_public_key     bytea       NOT NULL CHECK (octet_length(host_public_key) = 32),
    engine_version      text        NOT NULL CHECK (engine_version ~ '^[0-9A-Za-z.+_-]{1,64}$'),
    api_version         text        NOT NULL CHECK (api_version ~ '^[0-9]{1,3}\.[0-9]{1,3}$'),
    runtime             text        NOT NULL CHECK (runtime IN ('runc', 'runsc')),
    state               text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'ENDED', 'EXPIRED')),
    -- The insert's own time, not the transaction's: what the opening
    -- transaction itself invalidates (the last closure's images or
    -- configuration) comes before it, so it never makes the session's own
    -- closure stale.
    opened_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at          timestamptz NOT NULL,
    ended_at            timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, enrollment_token_id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, enrollment_token_id) REFERENCES pc.enrollment_tokens (org_id, id),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id),
    CONSTRAINT sandbox_sessions_lifetime CHECK (expires_at > opened_at AND expires_at <= opened_at + interval '24 hours'),
    CONSTRAINT sandbox_sessions_ended CHECK ((state = 'OPEN') = (ended_at IS NULL)),
    CONSTRAINT sandbox_sessions_two_keys CHECK (host_public_key <> probe_public_key)
);
CREATE INDEX sandbox_sessions_agent ON pc.sandbox_sessions (org_id, agent_id, id DESC);
CREATE INDEX sandbox_sessions_open ON pc.sandbox_sessions (org_id, expires_at) WHERE state = 'OPEN';

-- Each connection's bindings when the session opened (the closure
-- contract's Bound): a closure is recorded only while they are still the
-- connection's.
CREATE TABLE pc.sandbox_session_connections (
    org_id              uuid    NOT NULL REFERENCES pc.orgs (id),
    session_id          uuid    NOT NULL,
    connection_id       uuid    NOT NULL,
    connection_revision integer NOT NULL CHECK (connection_revision > 0),
    gateway_id          uuid    NOT NULL,
    package_version_id  uuid    NOT NULL,
    -- The active sealed credential's version; NULL when there was none.
    credential_version  integer CHECK (credential_version > 0),
    PRIMARY KEY (org_id, session_id, connection_id),
    FOREIGN KEY (org_id, session_id) REFERENCES pc.sandbox_sessions (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    FOREIGN KEY (org_id, package_version_id) REFERENCES pc.package_versions (org_id, id)
);

ALTER TABLE pc.coverage_closures
    ADD CONSTRAINT coverage_closures_session_fk FOREIGN KEY (org_id, sandbox_session_id) REFERENCES pc.sandbox_sessions (org_id, id);

ALTER TABLE pc.agent_instances ADD COLUMN sandbox_session_id uuid;
ALTER TABLE pc.agent_instances
    ADD CONSTRAINT agent_instances_sandbox_session_fk FOREIGN KEY (org_id, sandbox_session_id) REFERENCES pc.sandbox_sessions (org_id, id);

-- Agent hosts are checked one by one: lowercase DNS names, no IP literal,
-- no empty or NULL element, none twice, at most 16 (HR-183).
-- +goose StatementBegin
CREATE FUNCTION pc.agent_hosts_valid(hosts text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE AS $$
    SELECT hosts IS NOT NULL AND cardinality(hosts) <= 16 AND array_position(hosts, NULL) IS NULL
        AND cardinality(hosts) = (SELECT count(DISTINCT h) FROM unnest(hosts) h)
        AND NOT EXISTS (SELECT 1 FROM unnest(hosts) h
            WHERE h !~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$' OR h ~ '^[0-9.]+$')
$$;
-- +goose StatementEnd

ALTER TABLE pc.connections ADD COLUMN agent_hosts text[] NOT NULL DEFAULT '{}'
    CONSTRAINT connections_agent_hosts CHECK (pc.agent_hosts_valid(agent_hosts));

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

-- A session changes only forward: OPEN to ENDED or EXPIRED, once, and its
-- instance and run are set once. A sandbox instance is the session's only
-- when the session's enrollment token enrolled it, and only once (design
-- decision 2): the queries hold to this, and the database does too.
-- +goose StatementBegin
CREATE FUNCTION pc.sandbox_session_forward() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state <> 'OPEN' THEN
        RAISE EXCEPTION 'sandbox session % has ended', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state NOT IN ('OPEN', 'ENDED', 'EXPIRED')
        OR (OLD.instance_id IS NOT NULL AND NEW.instance_id IS DISTINCT FROM OLD.instance_id)
        OR (OLD.run_id IS NOT NULL AND NEW.run_id IS DISTINCT FROM OLD.run_id) THEN
        RAISE EXCEPTION 'sandbox session % changes only forward', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER sandbox_sessions_forward BEFORE UPDATE ON pc.sandbox_sessions
    FOR EACH ROW EXECUTE FUNCTION pc.sandbox_session_forward();

-- +goose StatementBegin
CREATE FUNCTION pc.sandbox_instance_session() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    -- An instance enrolled with a session's token is that session's from
    -- its first row, so it is never admitted outside a sandbox (00087's
    -- agent_instances_coverage reads the column after this trigger).
    IF TG_OP = 'INSERT' AND NEW.sandbox_session_id IS NULL AND NEW.enrollment_token_id IS NOT NULL THEN
        SELECT s.id INTO NEW.sandbox_session_id FROM pc.sandbox_sessions s
        WHERE s.org_id = NEW.org_id AND s.enrollment_token_id = NEW.enrollment_token_id;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.sandbox_session_id IS NOT DISTINCT FROM NEW.sandbox_session_id THEN
        RETURN NEW;
    END IF;
    IF (TG_OP = 'UPDATE' AND OLD.sandbox_session_id IS NOT NULL) OR (NEW.sandbox_session_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pc.sandbox_sessions s
        WHERE s.org_id = NEW.org_id AND s.id = NEW.sandbox_session_id AND s.enrollment_token_id = NEW.enrollment_token_id)) THEN
        RAISE EXCEPTION 'instance % is not sandbox session %''s', NEW.id, NEW.sandbox_session_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER agent_instances_sandbox_session BEFORE INSERT OR UPDATE OF sandbox_session_id ON pc.agent_instances
    FOR EACH ROW EXECUTE FUNCTION pc.sandbox_instance_session();

-- pc_app inserts no time: opened_at is the database's, so the lifetime
-- check holds against its clock; a session starts OPEN, unbound.
GRANT SELECT ON pc.sandbox_sessions, pc.sandbox_session_connections TO pc_app;
GRANT INSERT (org_id, id, agent_id, launcher, enrollment_token_id, agent_image, edge_image, probe_image, config_digest, probe_jkt,
    probe_public_key, host_jkt, host_public_key, engine_version, api_version, runtime, expires_at) ON pc.sandbox_sessions TO pc_app;
GRANT INSERT ON pc.sandbox_session_connections TO pc_app;
GRANT UPDATE (instance_id, run_id, state, ended_at) ON pc.sandbox_sessions TO pc_app;
GRANT UPDATE (sandbox_session_id) ON pc.agent_instances TO pc_app;
GRANT UPDATE (agent_hosts) ON pc.connections TO pc_app;
GRANT SELECT ON pc.sandbox_sessions, pc.sandbox_session_connections TO pc_audit_ro;

-- +goose Down
REVOKE UPDATE (agent_hosts) ON pc.connections FROM pc_app;
ALTER TABLE pc.connections DROP COLUMN agent_hosts;
DROP FUNCTION pc.agent_hosts_valid(text[]);
DROP TRIGGER agent_instances_sandbox_session ON pc.agent_instances;
DROP FUNCTION pc.sandbox_instance_session();
ALTER TABLE pc.agent_instances DROP CONSTRAINT agent_instances_sandbox_session_fk;
ALTER TABLE pc.agent_instances DROP COLUMN sandbox_session_id;
ALTER TABLE pc.coverage_closures DROP CONSTRAINT coverage_closures_session_fk;
DROP TABLE pc.sandbox_session_connections;
DROP TABLE pc.sandbox_sessions;
DROP FUNCTION pc.sandbox_session_forward();
