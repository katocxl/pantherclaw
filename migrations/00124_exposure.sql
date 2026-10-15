-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Breach radius and posture findings (G0 M10, coordinator decisions D27,
-- D30, D31; F253–F260, F265, F268; HR-253, HR-255).
--
-- * exposure_snapshots: one computation of an org's reach, materialised from
--   the grants, published policy, coverage, connections and credentials it
--   read (D27). The newest is current; a read marks it stale when
--   exposure_changes records a change after it was computed (F258).
-- * exposure_rights: the snapshot's rows, one per view, agent, connection,
--   operation (or credential scope) and verb. The three views stay separate
--   (OBSERVED, EFFECTIVE, CREDENTIAL; HR-253) and every right carries a
--   label: USABLE, CONDITIONAL, EXPIRED or UNCERTAIN. Unknown credential
--   scope is UNCERTAIN, never left out. Snapshots and their rights are
--   insert-only except for pruning old snapshots.
-- * exposure_changes: per org, the last change the feed showed that moves
--   reach (grant, policy, coverage, connection, credential), and the feed
--   seq the recompute job has read.
-- * posture_findings: the posture remediation queue (D30): kinds, a root
--   cause they group by, the affected paths a remediation must reach, and
--   the lifecycle OPEN -> ASSIGNED -> TESTING -> REMEDIATED, or
--   ACCEPTED_TEMPORARILY (at most 90 days) or EVIDENCE_INCOMPLETE. A finding
--   is REMEDIATED only on a snapshot computed after it was last seen
--   (HR-255); the database holds to the transitions and the bounds.
-- * posture_finding_events: the append-only history of each finding.

-- +goose Up
CREATE TABLE pc.exposure_snapshots (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    -- The feed seq the computation had read up to (0 before any).
    feed_seq     bigint      NOT NULL DEFAULT 0 CHECK (feed_seq >= 0),
    cause        text        NOT NULL CHECK (cause IN ('initial', 'change', 'manual', 'schedule')),
    rights       integer     NOT NULL CHECK (rights BETWEEN 0 AND 100000),
    -- More rights than the cap: the snapshot says so and is never complete.
    truncated    boolean     NOT NULL DEFAULT false,
    -- What the computation could not read, as stable codes (a connection
    -- without a pinned package, an undecodable bundle).
    gaps         text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(gaps) <= 64),
    -- SHA-256 of the canonical rights, so two computations compare cheaply.
    rights_sha256 bytea      NOT NULL CHECK (octet_length(rights_sha256) = 32),
    computed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id)
);
CREATE INDEX exposure_snapshots_latest ON pc.exposure_snapshots (org_id, computed_at DESC, id DESC);

CREATE TABLE pc.exposure_rights (
    org_id         uuid        NOT NULL,
    snapshot_id    uuid        NOT NULL,
    seq            integer     NOT NULL CHECK (seq BETWEEN 1 AND 100000),
    reach_view     text        NOT NULL CHECK (reach_view IN ('OBSERVED', 'EFFECTIVE', 'CREDENTIAL')),
    label          text        NOT NULL CHECK (label IN ('USABLE', 'CONDITIONAL', 'EXPIRED', 'UNCERTAIN')),
    -- NULL: every agent that holds the credential (a credential right).
    agent_id       uuid,
    connection_id  uuid,
    grant_id       uuid,
    -- The operation, or NULL for a credential scope that names none.
    operation      text        CHECK (operation IS NULL OR operation ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$'),
    -- The resource group: the operation's target type, or the credential
    -- scope (e.g. "github:contents").
    resource_group text        NOT NULL CHECK (char_length(resource_group) BETWEEN 1 AND 200),
    verb           text        NOT NULL CHECK (verb IN ('read', 'export', 'update', 'delete', 'transfer', 'delegate')),
    -- The coverage state of the path (UNKNOWN when none was assessed).
    coverage       text        NOT NULL CHECK (coverage IN ('UNKNOWN', 'OBSERVE_ONLY', 'PARTIAL', 'ENFORCED')),
    -- Why the label and the path: stable codes.
    reasons        text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(reasons) <= 16),
    -- Delegation depth the grant allows (delegate rights).
    depth          smallint    NOT NULL DEFAULT 0 CHECK (depth BETWEEN 0 AND 4),
    expires_at     timestamptz,
    -- OBSERVED: the latest dispatch and how many in the window.
    observed_at    timestamptz,
    observations   integer     NOT NULL DEFAULT 0 CHECK (observations >= 0),
    -- Why the verb (D45): ACCESS, EFFECT_KIND:<kind>, DEFAULT_UPDATE,
    -- DELEGATION or SCOPE_LEVEL; and whether the operation is irreversible.
    basis          text        NOT NULL CHECK (basis ~ '^(ACCESS|DEFAULT_UPDATE|DELEGATION|SCOPE_LEVEL|EFFECT_KIND:[A-Za-z0-9_.-]{1,128})$'),
    irreversible   boolean     NOT NULL DEFAULT false,
    PRIMARY KEY (org_id, snapshot_id, seq),
    FOREIGN KEY (org_id, snapshot_id) REFERENCES pc.exposure_snapshots (org_id, id) ON DELETE CASCADE,
    CHECK ((reach_view = 'OBSERVED') = (observed_at IS NOT NULL)),
    CHECK (agent_id IS NOT NULL OR reach_view = 'CREDENTIAL')
);
CREATE INDEX exposure_rights_agent ON pc.exposure_rights (org_id, snapshot_id, agent_id);
CREATE INDEX exposure_rights_connection ON pc.exposure_rights (org_id, snapshot_id, connection_id);

CREATE TABLE pc.exposure_changes (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    -- The feed seq of the last change that moves reach, and when it was
    -- (the epoch until the first change).
    change_seq bigint      NOT NULL DEFAULT 0 CHECK (change_seq >= 0),
    changed_at timestamptz NOT NULL DEFAULT now(),
    -- The feed seq the recompute job has read up to.
    read_seq   bigint      NOT NULL DEFAULT 0 CHECK (read_seq >= 0),
    PRIMARY KEY (org_id)
);

CREATE TABLE pc.posture_findings (
    org_id                 uuid        NOT NULL REFERENCES pc.orgs (id),
    id                     uuid        NOT NULL,
    kind                   text        NOT NULL CHECK (kind IN ('excessive_grant', 'uncovered_path', 'unowned_agent',
                                                                'unsafe_delegation', 'stale_credential', 'unused_authority',
                                                                'unverified_sensitive_tool', 'credential_overreach')),
    -- What the finding groups by, e.g. "grant:<uuid>", "connection:<uuid>".
    root_cause             text        NOT NULL CHECK (root_cause ~ '^[a-z_]+:[0-9a-f-]{36}$'),
    agent_id               uuid,
    connection_id          uuid,
    grant_id               uuid,
    coverage_finding_id    uuid,
    title                  text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    -- Facts behind the finding (ids and codes only, never a secret).
    detail                 jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(detail) = 'object'
                                                                    AND octet_length(detail::text) <= 8192),
    -- The path keys a remediation must reach (HR-255).
    affected_paths         text[]      NOT NULL CHECK (cardinality(affected_paths) BETWEEN 1 AND 256),
    severity               text        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    state                  text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'ASSIGNED', 'TESTING', 'REMEDIATED',
                                                                               'ACCEPTED_TEMPORARILY', 'EVIDENCE_INCOMPLETE')),
    owner_user_id          uuid,
    accepted_until         timestamptz,
    accepted_reason        text        CHECK (char_length(btrim(accepted_reason)) BETWEEN 10 AND 1000),
    fingerprint            bytea       NOT NULL CHECK (octet_length(fingerprint) = 32),
    -- The latest snapshot that found it, and the one that proved it gone.
    last_snapshot_id       uuid        NOT NULL,
    remediated_snapshot_id uuid,
    first_seen_at          timestamptz NOT NULL DEFAULT now(),
    last_seen_at           timestamptz NOT NULL DEFAULT now(),
    state_changed_at       timestamptz NOT NULL DEFAULT now(),
    remediated_at          timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, kind, fingerprint),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, grant_id) REFERENCES pc.grants (org_id, id),
    FOREIGN KEY (org_id, coverage_finding_id) REFERENCES pc.coverage_findings (org_id, id),
    FOREIGN KEY (org_id, owner_user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, last_snapshot_id) REFERENCES pc.exposure_snapshots (org_id, id),
    FOREIGN KEY (org_id, remediated_snapshot_id) REFERENCES pc.exposure_snapshots (org_id, id),
    CHECK (last_seen_at >= first_seen_at),
    CHECK ((state = 'ACCEPTED_TEMPORARILY') = (accepted_until IS NOT NULL AND accepted_reason IS NOT NULL)),
    CHECK (accepted_until IS NULL OR (accepted_until > state_changed_at AND accepted_until <= state_changed_at + interval '90 days')),
    CHECK ((state = 'REMEDIATED') = (remediated_snapshot_id IS NOT NULL AND remediated_at IS NOT NULL)),
    CHECK (state NOT IN ('ASSIGNED', 'TESTING') OR owner_user_id IS NOT NULL),
    CHECK (kind <> 'credential_overreach' OR coverage_finding_id IS NOT NULL)
);
CREATE INDEX posture_findings_queue ON pc.posture_findings (org_id, state, severity, id DESC);
CREATE INDEX posture_findings_root ON pc.posture_findings (org_id, root_cause);
CREATE INDEX posture_findings_accepted ON pc.posture_findings (org_id, accepted_until) WHERE state = 'ACCEPTED_TEMPORARILY';

CREATE TABLE pc.posture_finding_events (
    org_id      uuid        NOT NULL,
    id          uuid        NOT NULL,
    finding_id  uuid        NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('OPENED', 'SEEN', 'ASSIGNED', 'TESTING', 'REMEDIATED', 'ACCEPTED',
                                                     'EXPIRED', 'EVIDENCE_INCOMPLETE', 'REOPENED', 'NOTE')),
    from_state  text        CHECK (from_state IN ('OPEN', 'ASSIGNED', 'TESTING', 'REMEDIATED', 'ACCEPTED_TEMPORARILY',
                                                  'EVIDENCE_INCOMPLETE')),
    to_state    text        NOT NULL CHECK (to_state IN ('OPEN', 'ASSIGNED', 'TESTING', 'REMEDIATED', 'ACCEPTED_TEMPORARILY',
                                                         'EVIDENCE_INCOMPLETE')),
    actor       text        NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 128),
    note        text        CHECK (char_length(note) <= 1000),
    snapshot_id uuid,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, finding_id) REFERENCES pc.posture_findings (org_id, id),
    FOREIGN KEY (org_id, snapshot_id) REFERENCES pc.exposure_snapshots (org_id, id)
);
CREATE INDEX posture_finding_events_finding ON pc.posture_finding_events (org_id, finding_id, occurred_at, id);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['exposure_snapshots', 'exposure_rights', 'exposure_changes', 'posture_findings',
                             'posture_finding_events']
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

-- A finding moves only along its lifecycle (D30). From an open state
-- (OPEN, ASSIGNED, TESTING, EVIDENCE_INCOMPLETE) it may be assigned, tested,
-- accepted for a while, marked evidence-incomplete or remediated; ASSIGNED
-- goes to TESTING; an accepted or remediated finding only reopens. It is
-- REMEDIATED only on a snapshot computed after it was last seen, so a
-- remediation is what a recomputation shows (HR-255). The state change time
-- is the database's.
-- +goose StatementBegin
CREATE FUNCTION pc.posture_finding_transition() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
DECLARE
    proof timestamptz;
BEGIN
    IF NEW.kind <> OLD.kind OR NEW.root_cause <> OLD.root_cause OR NEW.fingerprint <> OLD.fingerprint
        OR NEW.first_seen_at <> OLD.first_seen_at OR NEW.last_seen_at < OLD.last_seen_at THEN
        RAISE EXCEPTION 'posture finding % keeps its identity', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        IF NOT (
            (OLD.state IN ('OPEN', 'ASSIGNED', 'TESTING', 'EVIDENCE_INCOMPLETE')
                AND NEW.state IN ('ASSIGNED', 'ACCEPTED_TEMPORARILY', 'EVIDENCE_INCOMPLETE', 'REMEDIATED'))
            OR (OLD.state = 'ASSIGNED' AND NEW.state = 'TESTING')
            OR (OLD.state IN ('ACCEPTED_TEMPORARILY', 'REMEDIATED', 'EVIDENCE_INCOMPLETE', 'ASSIGNED', 'TESTING')
                AND NEW.state = 'OPEN')
        ) THEN
            RAISE EXCEPTION 'posture finding % cannot move from % to %', OLD.id, OLD.state, NEW.state
                USING ERRCODE = 'check_violation';
        END IF;
        NEW.state_changed_at := now();
        IF NEW.state = 'REMEDIATED' THEN
            SELECT computed_at INTO proof FROM pc.exposure_snapshots
                WHERE org_id = NEW.org_id AND id = NEW.remediated_snapshot_id;
            IF proof IS NULL OR proof < NEW.last_seen_at THEN
                RAISE EXCEPTION 'posture finding % is remediated only on a recomputation after it was last seen', OLD.id
                    USING ERRCODE = 'check_violation';
            END IF;
            NEW.remediated_at := now();
        ELSE
            NEW.remediated_snapshot_id := NULL;
            NEW.remediated_at := NULL;
        END IF;
        IF NEW.state <> 'ACCEPTED_TEMPORARILY' THEN
            NEW.accepted_until := NULL;
            NEW.accepted_reason := NULL;
        END IF;
    ELSIF NEW.remediated_snapshot_id IS DISTINCT FROM OLD.remediated_snapshot_id
        OR NEW.accepted_until IS DISTINCT FROM OLD.accepted_until THEN
        RAISE EXCEPTION 'posture finding % changes its proof or acceptance only with its state', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER posture_findings_transition BEFORE UPDATE ON pc.posture_findings
    FOR EACH ROW EXECUTE FUNCTION pc.posture_finding_transition();

GRANT SELECT, INSERT, DELETE ON pc.exposure_snapshots, pc.exposure_rights TO pc_app;
GRANT SELECT, INSERT ON pc.exposure_changes, pc.posture_findings, pc.posture_finding_events TO pc_app;
GRANT UPDATE (change_seq, changed_at, read_seq) ON pc.exposure_changes TO pc_app;
GRANT UPDATE (agent_id, connection_id, grant_id, coverage_finding_id, title, detail, affected_paths, severity, state,
    owner_user_id, accepted_until, accepted_reason, last_snapshot_id, remediated_snapshot_id, last_seen_at,
    state_changed_at, remediated_at) ON pc.posture_findings TO pc_app;
GRANT SELECT ON pc.exposure_snapshots, pc.exposure_rights, pc.exposure_changes, pc.posture_findings,
    pc.posture_finding_events TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.posture_finding_events;
DROP TABLE pc.posture_findings;
DROP FUNCTION pc.posture_finding_transition();
DROP TABLE pc.exposure_changes;
DROP TABLE pc.exposure_rights;
DROP TABLE pc.exposure_snapshots;
