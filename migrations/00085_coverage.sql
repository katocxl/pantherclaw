-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Coverage records (G0 M9 track A slice A1; F433–F460, F021, F048,
-- PN-008.2; HR-210, HR-211, HR-212, HR-217; T-085, T-089). The scope of a
-- coverage claim is agent × connection × operation (decision 6).
--
-- coverage_routes is the route inventory: the ways an agent can produce a
-- connection's effects, as observed in traffic, declared by configuration,
-- found by discovery and scans, or proposed (a hypothesis, never evidence,
-- F455). A route kind with no row is "not observed", never "absent" (F450).
--
-- coverage_closures is sandbox closure evidence (F457, PN-008.2): the
-- signed probe results of one sandbox session for one agent and connection,
-- recorded only by the sandbox module after it verified the signature and
-- the server nonce (HR-215), once per nonce. result is computed from the
-- probes; PASSED needs the positive and negative controls and the canary
-- (HR-121). The connection revision, package version, gateway and
-- credential version it ran against are bound, and it expires (24 hours by
-- default, HR-211). The foreign key to the sandbox session is added by the
-- sandbox migration (00090).
--
-- coverage_invalidations are the changes that drop ENFORCED at once
-- (HR-211); the reassess job marks them reassessed. Track A's triggers
-- (00087) write the connection, credential, package, gateway and agent
-- instance kinds; columns added later to those tables (00090's
-- connections.agent_hosts and agent_instances.sandbox_session_id) are
-- covered by them. Connector spec changes (00093, track C) need a trigger
-- of their own.
--
-- coverage_snapshots are the computed states, append-only evidence: each is
-- also a ledger entry (body_sha256 is the digest of its ledger body), and a
-- decision receipt's coverage claim names one (HR-217). An ENFORCED one
-- rests on a PASSED closure of its own scope and expires no later than it.
-- A downgrade after expiry or invalidation keeps the last valid record
-- (F442).
--
-- coverage_exclusions are weakening changes: only a person creates one,
-- with a written reason and an expiry of at most 90 days, and a revoked one
-- never comes back (HR-212).
--
-- coverage_findings are exposure findings, starting with credential
-- overreach (F048, decision 9); M10 extends the kinds.

-- +goose Up
CREATE TABLE pc.coverage_routes (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    -- NULL: every agent of the connection; operation NULL: every operation.
    agent_id      uuid,
    connection_id uuid        NOT NULL,
    operation     text        CHECK (operation ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$'),
    kind          text        NOT NULL CHECK (kind IN ('channel', 'direct_api', 'host', 'git_ssh', 'credential', 'browser',
                                                       'delegated', 'intermediary', 'target_side')),
    channel       text        CHECK (channel IN ('http', 'mcp', 'sdk', 'hook')),
    -- Where the route goes (a host, a file, an identity); UNTRUSTED text.
    locator       text        CHECK (char_length(locator) BETWEEN 1 AND 512),
    observation   text        NOT NULL CHECK (observation IN ('observed', 'declared', 'proposed')),
    source        text        NOT NULL CHECK (source IN ('gateway', 'connection', 'discovery', 'scan', 'probe', 'person')),
    source_ref    uuid,
    -- The route mode last observed on a channel route.
    mode          text        CHECK (mode IN ('monitor', 'enforce')),
    attributes    jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(attributes) = 'object'
                                                           AND octet_length(attributes::text) <= 4096),
    seen_count    bigint      NOT NULL DEFAULT 1 CHECK (seen_count >= 1),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    CHECK ((kind = 'channel') = (channel IS NOT NULL)),
    CHECK (mode IS NULL OR kind = 'channel'),
    CHECK (last_seen_at >= first_seen_at)
);
CREATE UNIQUE INDEX coverage_routes_key ON pc.coverage_routes (org_id, connection_id, agent_id, operation, kind, channel, locator)
    NULLS NOT DISTINCT;
CREATE INDEX coverage_routes_agent ON pc.coverage_routes (org_id, agent_id);

-- How much a sighting says: observed over declared over proposed. A route
-- seen again keeps what its strongest sighting said.
-- +goose StatementBegin
CREATE FUNCTION pc.coverage_rank(observation text) RETURNS integer
LANGUAGE sql IMMUTABLE
SET search_path = pc, pg_temp
AS $$
    SELECT CASE observation WHEN 'observed' THEN 3 WHEN 'declared' THEN 2 ELSE 1 END
$$;
-- +goose StatementEnd

CREATE TABLE pc.coverage_closures (
    org_id                  uuid        NOT NULL REFERENCES pc.orgs (id),
    id                      uuid        NOT NULL,
    agent_id                uuid        NOT NULL,
    connection_id           uuid        NOT NULL,
    sandbox_session_id      uuid        NOT NULL,
    result                  text        NOT NULL CHECK (result IN ('PASSED', 'FAILED')),
    -- [{"name","role","expect","observed","detail"}], see internal/coverage/domain.
    probes                  jsonb       NOT NULL CHECK (jsonb_typeof(probes) = 'array'
                                                        AND jsonb_array_length(probes) BETWEEN 1 AND 128
                                                        AND octet_length(probes::text) <= 65536),
    positive_controls_passed boolean    NOT NULL,
    negative_controls_passed boolean    NOT NULL,
    canary_passed           boolean     NOT NULL,
    signing_key_jkt         text        NOT NULL CHECK (signing_key_jkt ~ '^[A-Za-z0-9_-]{43}$'),
    server_nonce            text        NOT NULL CHECK (server_nonce ~ '^[A-Za-z0-9_-]{16,128}$'),
    results_sha256          bytea       NOT NULL CHECK (octet_length(results_sha256) = 32),
    engine_version          text        NOT NULL CHECK (engine_version ~ '^[0-9A-Za-z.+_-]{1,64}$'),
    api_version             text        NOT NULL CHECK (api_version ~ '^[0-9]{1,3}\.[0-9]{1,3}$'),
    runtime                 text        NOT NULL CHECK (runtime IN ('runc', 'runsc')),
    image_digests           text[]      NOT NULL CHECK (cardinality(image_digests) BETWEEN 1 AND 16
                                                        AND array_to_string(image_digests, ',') ~ '^sha256:[0-9a-f]{64}(,sha256:[0-9a-f]{64})*$'),
    config_sha256           bytea       NOT NULL CHECK (octet_length(config_sha256) = 32),
    -- pclaw's configuration checks of the agent container ({"id","ok",
    -- "detail"}): the mounts and binds no probe inside the sandbox can see.
    config_checks           jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(config_checks) = 'array'
                                                                    AND jsonb_array_length(config_checks) <= 64
                                                                    AND octet_length(config_checks::text) <= 16384),
    gateway_id              uuid        NOT NULL,
    connection_revision     integer     NOT NULL CHECK (connection_revision > 0),
    package_version_id      uuid        NOT NULL,
    -- The active sealed credential's version when the session opened; NULL
    -- when the connection had none.
    credential_version      integer     CHECK (credential_version > 0),
    session_started_at      timestamptz NOT NULL,
    observed_at             timestamptz NOT NULL,
    expires_at              timestamptz NOT NULL,
    recorded_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    -- A snapshot names its closure with its scope (below).
    UNIQUE (org_id, id, agent_id, connection_id),
    -- A signed result set is recorded once (HR-215: replays are refused).
    UNIQUE (org_id, agent_id, connection_id, server_nonce),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    FOREIGN KEY (org_id, package_version_id) REFERENCES pc.package_versions (org_id, id),
    CHECK (result = 'FAILED' OR (positive_controls_passed AND negative_controls_passed AND canary_passed)),
    CHECK (session_started_at <= observed_at),
    CHECK (observed_at <= recorded_at + interval '1 minute' AND observed_at >= recorded_at - interval '1 hour'),
    CHECK (expires_at > observed_at AND expires_at <= observed_at + interval '7 days')
);
CREATE INDEX coverage_closures_scope ON pc.coverage_closures (org_id, agent_id, connection_id, id DESC);

CREATE TABLE pc.coverage_invalidations (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    kind          text        NOT NULL CHECK (kind IN ('connection', 'package_version', 'route_mode', 'gateway', 'credential',
                                                       'sandbox_image', 'sandbox_config', 'closure_failed', 'exclusion',
                                                       'evidence_expired', 'route', 'instance')),
    -- What it affects; NULL agent_id: every agent of the connection.
    connection_id uuid        NOT NULL,
    agent_id      uuid,
    -- The object that changed (a connection, credential, gateway, package
    -- version, closure or exclusion).
    subject_id    uuid,
    detail        text        CHECK (char_length(detail) BETWEEN 1 AND 200),
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    reassessed_at timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    CHECK (reassessed_at IS NULL OR reassessed_at >= occurred_at)
);
CREATE INDEX coverage_invalidations_scope ON pc.coverage_invalidations (org_id, connection_id, occurred_at);
CREATE INDEX coverage_invalidations_pending ON pc.coverage_invalidations (org_id, id) WHERE reassessed_at IS NULL;

CREATE TABLE pc.coverage_snapshots (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    agent_id        uuid        NOT NULL,
    connection_id   uuid        NOT NULL,
    operation       text        NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$'),
    state           text        NOT NULL CHECK (state IN ('UNKNOWN', 'OBSERVE_ONLY', 'PARTIAL', 'ENFORCED')),
    reasons         text[]      NOT NULL CHECK (cardinality(reasons) <= 32),
    -- The closure an ENFORCED state rests on, the last ENFORCED snapshot a
    -- downgrade follows (F442) and the change that caused the reassessment.
    closure_id      uuid,
    last_valid_id   uuid,
    invalidation_id uuid,
    body            jsonb       NOT NULL CHECK (jsonb_typeof(body) = 'object' AND octet_length(body::text) <= 32768),
    body_sha256     bytea       NOT NULL CHECK (octet_length(body_sha256) = 32),
    ledger_entry_id uuid        NOT NULL,
    computed_at     timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    -- A snapshot rests only on a closure of its own agent and connection.
    FOREIGN KEY (org_id, closure_id, agent_id, connection_id)
        REFERENCES pc.coverage_closures (org_id, id, agent_id, connection_id),
    FOREIGN KEY (org_id, last_valid_id) REFERENCES pc.coverage_snapshots (org_id, id),
    FOREIGN KEY (org_id, invalidation_id) REFERENCES pc.coverage_invalidations (org_id, id),
    FOREIGN KEY (org_id, ledger_entry_id) REFERENCES pc.ledger_entries (org_id, id),
    UNIQUE (org_id, ledger_entry_id),
    -- Only ENFORCED expires, and only on closure evidence (HR-210, HR-211).
    CHECK ((state = 'ENFORCED') = (expires_at IS NOT NULL)),
    CHECK (state <> 'ENFORCED' OR (closure_id IS NOT NULL AND expires_at > computed_at)),
    CHECK (last_valid_id IS NULL OR state <> 'ENFORCED')
);
CREATE INDEX coverage_snapshots_scope ON pc.coverage_snapshots (org_id, agent_id, connection_id, operation, id DESC);
CREATE INDEX coverage_snapshots_connection ON pc.coverage_snapshots (org_id, connection_id, id DESC);

-- An ENFORCED snapshot rests on a PASSED closure and expires no later than
-- it (HR-210, HR-211). The function runs as the inserting role, under its
-- RLS, so it reads only the tenant's own closure.
-- +goose StatementBegin
CREATE FUNCTION pc.coverage_snapshot_closure() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    c pc.coverage_closures;
BEGIN
    IF NEW.closure_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT * INTO c FROM pc.coverage_closures WHERE org_id = NEW.org_id AND id = NEW.closure_id;
    IF NOT FOUND OR c.result <> 'PASSED' THEN
        RAISE EXCEPTION 'a coverage snapshot rests only on a PASSED closure' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.expires_at > c.expires_at THEN
        RAISE EXCEPTION 'a coverage snapshot expires no later than its closure' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER coverage_snapshots_closure BEFORE INSERT ON pc.coverage_snapshots
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_snapshot_closure();

CREATE TABLE pc.coverage_exclusions (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    -- NULL agent_id: every agent; NULL operation: every operation; NULL
    -- route_kind: the whole scope.
    agent_id      uuid,
    connection_id uuid        NOT NULL,
    operation     text        CHECK (operation ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$'),
    route_kind    text        CHECK (route_kind IN ('direct_api', 'host', 'git_ssh', 'credential', 'browser', 'delegated',
                                                    'intermediary', 'target_side')),
    reason        text        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 10 AND 1000),
    state         text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'REVOKED')),
    -- Only a person (HR-212).
    created_by    uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_by    uuid,
    revoked_at    timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, revoked_by) REFERENCES pc.users (org_id, id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days'),
    CHECK ((state = 'REVOKED') = (revoked_by IS NOT NULL AND revoked_at IS NOT NULL))
);
CREATE INDEX coverage_exclusions_active ON pc.coverage_exclusions (org_id, connection_id) WHERE state = 'ACTIVE';

-- An exclusion is revoked once and never comes back: a new one needs a new
-- person, reason and expiry (HR-212).
-- +goose StatementBegin
CREATE FUNCTION pc.coverage_exclusion_revoke() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF OLD.state <> 'ACTIVE' OR NEW.state <> 'REVOKED' THEN
        RAISE EXCEPTION 'a coverage exclusion only goes from ACTIVE to REVOKED, once' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER coverage_exclusions_revoke BEFORE UPDATE ON pc.coverage_exclusions
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_exclusion_revoke();

CREATE TABLE pc.coverage_findings (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    kind           text        NOT NULL CHECK (kind IN ('credential_overreach')),
    connection_id  uuid,
    agent_id       uuid,
    -- What holds the reach, e.g. "GitHub App installation 4711"; UNTRUSTED.
    subject        text        NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 256),
    -- Permissions: declared as needed, actually held, used by grants, and
    -- the excess (held beyond what is needed), shown as exposure (F048).
    declared       text[]      NOT NULL CHECK (cardinality(declared) <= 256),
    held           text[]      NOT NULL CHECK (cardinality(held) <= 256),
    used           text[]      NOT NULL CHECK (cardinality(used) <= 256),
    excess         text[]      NOT NULL CHECK (cardinality(excess) BETWEEN 1 AND 256),
    severity       text        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    state          text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'RESOLVED', 'DISMISSED')),
    fingerprint    bytea       NOT NULL CHECK (octet_length(fingerprint) = 32),
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    resolved_at    timestamptz,
    dismissed_by   uuid,
    dismiss_reason text        CHECK (char_length(btrim(dismiss_reason)) BETWEEN 10 AND 1000),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, kind, fingerprint),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, dismissed_by) REFERENCES pc.users (org_id, id),
    CHECK ((state = 'OPEN') = (resolved_at IS NULL)),
    CHECK ((state = 'DISMISSED') = (dismissed_by IS NOT NULL AND dismiss_reason IS NOT NULL))
);
CREATE INDEX coverage_findings_open ON pc.coverage_findings (org_id, id) WHERE state = 'OPEN';

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['coverage_routes', 'coverage_closures', 'coverage_invalidations', 'coverage_snapshots',
                             'coverage_exclusions', 'coverage_findings']
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

-- Closures and snapshots are evidence (HR-055); routes, invalidations,
-- exclusions and findings change only the columns below.
GRANT SELECT, INSERT ON pc.coverage_routes, pc.coverage_closures, pc.coverage_invalidations, pc.coverage_snapshots,
    pc.coverage_exclusions, pc.coverage_findings TO pc_app;
GRANT UPDATE (observation, source, source_ref, mode, attributes, seen_count, last_seen_at) ON pc.coverage_routes TO pc_app;
GRANT UPDATE (reassessed_at) ON pc.coverage_invalidations TO pc_app;
GRANT UPDATE (state, revoked_by, revoked_at) ON pc.coverage_exclusions TO pc_app;
GRANT UPDATE (declared, held, used, excess, severity, state, last_seen_at, resolved_at, dismissed_by, dismiss_reason)
    ON pc.coverage_findings TO pc_app;
GRANT SELECT ON pc.coverage_routes, pc.coverage_closures, pc.coverage_invalidations, pc.coverage_snapshots,
    pc.coverage_exclusions, pc.coverage_findings TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.coverage_findings;
DROP TABLE pc.coverage_exclusions;
DROP FUNCTION pc.coverage_exclusion_revoke();
DROP TABLE pc.coverage_snapshots;
DROP FUNCTION pc.coverage_snapshot_closure();
DROP TABLE pc.coverage_invalidations;
DROP TABLE pc.coverage_closures;
DROP TABLE pc.coverage_routes;
DROP FUNCTION pc.coverage_rank(text);
