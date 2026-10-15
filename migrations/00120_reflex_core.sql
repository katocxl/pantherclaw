-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Reflex core (G0 M10 D10, D14–D18; HR-240, HR-242, HR-243).
--
-- Detection reads the evidence ledger's chain in order. Each org has one
-- cursor, the chain seq of the last entry the engine evaluated; the engine
-- advances it by compare-and-set (WHERE seq = old) in the transaction that
-- records what the batch raised, so each entry is evaluated once per org
-- (HR-240). Window buckets, sequence progress and per-rule state are the
-- engine's working memory; they hold group keys and counts, never payloads.
--
-- A signal becomes an alert (FINDING and above), a reflex.live ledger entry
-- (LIVE) or nothing (TELEMETRY). An open alert with the same dedupe key
-- counts a repeat and appends its evidence; alert and incident changes add
-- events. Evidence and events are append-only: pc_app has no UPDATE or
-- DELETE on them (HR-243).
--
-- A suppression names a rule, optional subjects, a reason and an expiry at
-- most 30 days out; alerts it matches are stored SUPPRESSED, stay listable
-- and never notify or page (HR-242). A break records a subject the
-- suppression no longer covers because an alert bypassed it.
--
-- Owned failures (F641) say what broke, where, who owns it, by when and
-- what to do next; a repeat with the same dedupe key counts into the open
-- failure.

-- +goose Up
CREATE TABLE pc.detection_cursors (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    seq        bigint      NOT NULL DEFAULT 0 CHECK (seq >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

-- Per-rule engine state: consecutive evaluation errors, auto-disable after
-- ten in a row, and the day an overflow was last reported (one report per
-- rule per day, D10). window_groups and seen_keys count the rule's live window groups
-- and first-seen keys, so the cardinality caps are checked in O(1) (D59 M5).
CREATE TABLE pc.detection_rule_state (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    rule_id             text        NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 128),
    consecutive_errors  integer     NOT NULL DEFAULT 0 CHECK (consecutive_errors >= 0),
    last_error          text        CHECK (char_length(last_error) <= 512),
    disabled_at         timestamptz,
    disabled_reason     text        CHECK (char_length(disabled_reason) BETWEEN 1 AND 512),
    overflow_reported_on date,
    window_groups       integer     NOT NULL DEFAULT 0 CHECK (window_groups >= 0),
    seen_keys           integer     NOT NULL DEFAULT 0 CHECK (seen_keys >= 0),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, rule_id)
);

-- Window counters in one-minute buckets: a window's count is the sum of
-- the buckets inside its duration. distinct_values keeps at most 1000
-- values per bucket for distinct counts.
CREATE TABLE pc.detection_window_buckets (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    rule_id         text        NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 128),
    group_key       text        NOT NULL CHECK (char_length(group_key) BETWEEN 1 AND 512),
    bucket          timestamptz NOT NULL,
    n               integer     NOT NULL CHECK (n > 0),
    distinct_values text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(distinct_values) <= 1000),
    PRIMARY KEY (org_id, rule_id, group_key, bucket)
);
CREATE INDEX detection_window_buckets_age ON pc.detection_window_buckets (org_id, bucket);

-- The live groups of each window rule and when each was last counted; the
-- engine keeps detection_rule_state.window_groups equal to their number.
CREATE TABLE pc.detection_window_groups (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    rule_id     text        NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 128),
    group_key   text        NOT NULL CHECK (char_length(group_key) BETWEEN 1 AND 512),
    last_bucket timestamptz NOT NULL,
    PRIMARY KEY (org_id, rule_id, group_key)
);
CREATE INDEX detection_window_groups_age ON pc.detection_window_groups (org_id, last_bucket);

-- Sequence progress: the steps matched so far for one group, and the
-- ledger entries that matched them.
CREATE TABLE pc.detection_sequences (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    rule_id    text        NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 128),
    group_key  text        NOT NULL CHECK (char_length(group_key) BETWEEN 1 AND 512),
    step       smallint    NOT NULL CHECK (step BETWEEN 1 AND 4),
    started_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    evidence   uuid[]      NOT NULL CHECK (cardinality(evidence) BETWEEN 1 AND 4),
    PRIMARY KEY (org_id, rule_id, group_key)
);
CREATE INDEX detection_sequences_age ON pc.detection_sequences (org_id, started_at);

CREATE TABLE pc.incidents (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    title      text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    severity   text        NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    state      text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'CONTAINED', 'RESOLVED')),
    owner_id   uuid,
    -- The evidence-based grouping key (run/agent/principal/grant/target/
    -- connection, F603), empty for an incident opened by hand.
    group_key  text        NOT NULL DEFAULT '' CHECK (char_length(group_key) <= 512),
    -- "alert:<id>" or "user:<id>".
    opened_by  text        NOT NULL CHECK (char_length(opened_by) BETWEEN 1 AND 300),
    test       boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, owner_id) REFERENCES pc.users (org_id, id)
);
CREATE INDEX incidents_open ON pc.incidents (org_id, group_key, created_at) WHERE state <> 'RESOLVED';
CREATE INDEX incidents_by_time ON pc.incidents (org_id, id DESC);

CREATE TABLE pc.incident_events (
    org_id      uuid        NOT NULL,
    id          uuid        NOT NULL,
    incident_id uuid        NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('OPENED', 'STATE', 'OWNER', 'LINK', 'SEVERITY', 'NOTE')),
    actor_type  text        NOT NULL CHECK (char_length(actor_type) BETWEEN 1 AND 32),
    actor_id    text        NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 256),
    from_value  text        CHECK (char_length(from_value) <= 256),
    to_value    text        CHECK (char_length(to_value) <= 256),
    alert_id    uuid,
    note        text        CHECK (char_length(note) <= 2000),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, incident_id) REFERENCES pc.incidents (org_id, id)
);
CREATE INDEX incident_events_by_incident ON pc.incident_events (org_id, incident_id, id);

CREATE TABLE pc.suppressions (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    rule_id         text        NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 128),
    -- Subjects ([{type,id}]) the suppression is limited to; empty covers
    -- every subject of the rule.
    subjects        jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(subjects) = 'array'
                                                             AND jsonb_array_length(subjects) <= 32),
    -- Alerts above this severity bypass it (D16).
    max_severity    text        NOT NULL CHECK (max_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    reason          text        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 500),
    created_by      uuid        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    ended_at        timestamptz,
    ended_by        uuid,
    end_reason      text        CHECK (char_length(btrim(end_reason)) BETWEEN 1 AND 500),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, ended_by) REFERENCES pc.users (org_id, id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days'),
    CHECK ((ended_at IS NULL) = (end_reason IS NULL))
);
CREATE INDEX suppressions_active ON pc.suppressions (org_id, rule_id) WHERE ended_at IS NULL;

-- A suppression is inserted with the database's time and runs at most 30
-- days from it; it ends once and is never extended (HR-242).
-- +goose StatementBegin
CREATE FUNCTION pc.suppression_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    NEW.created_at := now();
    IF NEW.expires_at <= now() OR NEW.expires_at > now() + interval '30 days' THEN
        RAISE EXCEPTION 'a suppression expires within 30 days' USING ERRCODE = 'check_violation';
    END IF;
    NEW.ended_at := NULL;
    NEW.ended_by := NULL;
    NEW.end_reason := NULL;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER suppressions_insert BEFORE INSERT ON pc.suppressions
    FOR EACH ROW EXECUTE FUNCTION pc.suppression_insert();

-- +goose StatementBegin
CREATE FUNCTION pc.suppression_end() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF OLD.ended_at IS NOT NULL THEN
        RAISE EXCEPTION 'the suppression has already ended' USING ERRCODE = 'check_violation';
    END IF;
    NEW.ended_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER suppressions_end BEFORE UPDATE ON pc.suppressions
    FOR EACH ROW EXECUTE FUNCTION pc.suppression_end();

CREATE TABLE pc.alerts (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    source         text        NOT NULL CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage', 'system')),
    rule_id        text        NOT NULL DEFAULT '' CHECK (char_length(rule_id) <= 128),
    rule_version   text        NOT NULL DEFAULT '' CHECK (char_length(rule_version) <= 64),
    rule_digest    text        NOT NULL DEFAULT '' CHECK (char_length(rule_digest) <= 128),
    pack_version   text        NOT NULL DEFAULT '' CHECK (char_length(pack_version) <= 64),
    title          text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    summary        text        NOT NULL DEFAULT '' CHECK (char_length(summary) <= 2000),
    severity       text        NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    attention      text        NOT NULL CHECK (attention IN ('FINDING', 'ALERT', 'INCIDENT', 'PAGE')),
    basis          text        NOT NULL CHECK (basis IN ('OBSERVED', 'RULE_MATCH', 'INFERRED', 'HYPOTHESIS')),
    subjects       jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(subjects) = 'array'
                                                            AND octet_length(subjects::text) <= 8192),
    atlas          text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(atlas) <= 16),
    owasp          text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(owasp) <= 16),
    facts          jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(facts) = 'object'
                                                            AND octet_length(facts::text) <= 12288),
    group_key      text        NOT NULL DEFAULT '' CHECK (char_length(group_key) <= 512),
    dedupe_key     text        NOT NULL CHECK (char_length(dedupe_key) BETWEEN 1 AND 512),
    state          text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'SUPPRESSED')),
    incident_id    uuid,
    suppression_id uuid,
    count          integer     NOT NULL DEFAULT 1 CHECK (count >= 1),
    first_seen     timestamptz NOT NULL,
    last_seen      timestamptz NOT NULL,
    test           boolean     NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, incident_id) REFERENCES pc.incidents (org_id, id),
    FOREIGN KEY (org_id, suppression_id) REFERENCES pc.suppressions (org_id, id),
    CHECK ((state = 'SUPPRESSED') = (suppression_id IS NOT NULL)),
    -- A test signal is capped at ALERT and never pages (F616).
    CHECK (NOT test OR attention IN ('FINDING', 'ALERT')),
    CHECK (last_seen >= first_seen)
);
CREATE UNIQUE INDEX alerts_open_dedupe ON pc.alerts (org_id, dedupe_key)
    WHERE state IN ('OPEN', 'ACKNOWLEDGED', 'SUPPRESSED');
CREATE INDEX alerts_by_time ON pc.alerts (org_id, id DESC);
CREATE INDEX alerts_by_group ON pc.alerts (org_id, group_key, last_seen) WHERE group_key <> '';
CREATE INDEX alerts_by_incident ON pc.alerts (org_id, incident_id) WHERE incident_id IS NOT NULL;

CREATE TABLE pc.alert_evidence (
    org_id      uuid        NOT NULL,
    id          uuid        NOT NULL,
    alert_id    uuid        NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('ledger', 'transaction', 'run', 'receipt', 'case_entry')),
    ref_id      uuid        NOT NULL,
    occurred_at timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, alert_id) REFERENCES pc.alerts (org_id, id)
);
CREATE INDEX alert_evidence_by_alert ON pc.alert_evidence (org_id, alert_id, id);

CREATE TABLE pc.alert_events (
    org_id     uuid        NOT NULL,
    id         uuid        NOT NULL,
    alert_id   uuid        NOT NULL,
    kind       text        NOT NULL CHECK (kind IN ('RAISED', 'STATE', 'LINK', 'PROMOTE', 'SUPPRESS_BYPASS', 'NOTE')),
    actor_type text        NOT NULL CHECK (char_length(actor_type) BETWEEN 1 AND 32),
    actor_id   text        NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 256),
    from_value text        CHECK (char_length(from_value) <= 256),
    to_value   text        CHECK (char_length(to_value) <= 256),
    note       text        CHECK (char_length(note) <= 2000),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, alert_id) REFERENCES pc.alerts (org_id, id)
);
CREATE INDEX alert_events_by_alert ON pc.alert_events (org_id, alert_id, id);

CREATE TABLE pc.suppression_breaks (
    org_id         uuid        NOT NULL,
    id             uuid        NOT NULL,
    suppression_id uuid        NOT NULL,
    subject        text        NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 300),
    alert_id       uuid        NOT NULL,
    reason         text        NOT NULL CHECK (reason IN ('SEVERITY_ABOVE_MAX', 'SUBJECT_OUTSIDE_SCOPE', 'FAILED_CONTAINMENT')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, suppression_id) REFERENCES pc.suppressions (org_id, id),
    FOREIGN KEY (org_id, alert_id) REFERENCES pc.alerts (org_id, id)
);
CREATE INDEX suppression_breaks_by_suppression ON pc.suppression_breaks (org_id, suppression_id, subject);

CREATE TABLE pc.operational_failures (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    kind        text        NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$' AND char_length(kind) <= 100),
    summary     text        NOT NULL CHECK (char_length(summary) BETWEEN 1 AND 2000),
    next_step   text        NOT NULL CHECK (char_length(next_step) BETWEEN 1 AND 1000),
    scope       jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(scope) = 'array' AND jsonb_array_length(scope) <= 32),
    owner_type  text        CHECK (char_length(owner_type) BETWEEN 1 AND 32),
    owner_id    text        CHECK (char_length(owner_id) BETWEEN 1 AND 256),
    deadline    timestamptz NOT NULL,
    state       text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'ASSIGNED', 'RESOLVED')),
    dedupe_key  text        NOT NULL CHECK (char_length(dedupe_key) BETWEEN 1 AND 512),
    count       integer     NOT NULL DEFAULT 1 CHECK (count >= 1),
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    resolved_by uuid,
    resolved_at timestamptz,
    resolution  text        CHECK (char_length(btrim(resolution)) BETWEEN 1 AND 1000),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, resolved_by) REFERENCES pc.users (org_id, id),
    CHECK ((owner_type IS NULL) = (owner_id IS NULL)),
    CHECK ((state = 'RESOLVED') = (resolved_at IS NOT NULL))
);
CREATE UNIQUE INDEX operational_failures_open_dedupe ON pc.operational_failures (org_id, dedupe_key) WHERE state <> 'RESOLVED';
CREATE INDEX operational_failures_by_time ON pc.operational_failures (org_id, id DESC);

-- The daily digest (Team, F620) and its delivery state.
CREATE TABLE pc.reflex_digests (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    day             date        NOT NULL,
    state           text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'SENT', 'FAILED')),
    decisions       integer     NOT NULL DEFAULT 0 CHECK (decisions >= 0),
    authority_changes integer   NOT NULL DEFAULT 0 CHECK (authority_changes >= 0),
    alerts          integer     NOT NULL DEFAULT 0 CHECK (alerts >= 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,
    PRIMARY KEY (org_id, day)
);

ALTER TABLE pc.detection_cursors ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.detection_cursors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.detection_cursors
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.detection_rule_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.detection_rule_state FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.detection_rule_state
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.detection_window_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.detection_window_buckets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.detection_window_buckets
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.detection_window_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.detection_window_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.detection_window_groups
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.detection_sequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.detection_sequences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.detection_sequences
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.incidents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.incidents
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.incident_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.incident_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.incident_events
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.suppressions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.suppressions
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.alerts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.alerts
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.alert_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.alert_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.alert_evidence
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.alert_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.alert_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.alert_events
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.suppression_breaks ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.suppression_breaks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.suppression_breaks
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.operational_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.operational_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.operational_failures
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.reflex_digests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.reflex_digests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.reflex_digests
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- Engine working memory: the engine inserts, updates and prunes it.
GRANT SELECT, INSERT, UPDATE ON pc.detection_cursors, pc.detection_rule_state TO pc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pc.detection_window_buckets, pc.detection_window_groups, pc.detection_sequences TO pc_app;
-- Alerts, incidents and failures change only through their state, owner
-- and counting columns; their evidence and events are append-only.
GRANT SELECT, INSERT ON pc.alerts, pc.incidents, pc.suppressions, pc.operational_failures TO pc_app;
GRANT UPDATE (state, incident_id, suppression_id, count, last_seen, severity, updated_at) ON pc.alerts TO pc_app;
GRANT UPDATE (state, owner_id, severity, updated_at) ON pc.incidents TO pc_app;
GRANT UPDATE (ended_at, ended_by, end_reason) ON pc.suppressions TO pc_app;
GRANT UPDATE (state, owner_type, owner_id, count, last_seen, resolved_by, resolved_at, resolution, summary, next_step, deadline)
    ON pc.operational_failures TO pc_app;
GRANT SELECT, INSERT ON pc.alert_evidence, pc.alert_events, pc.incident_events, pc.suppression_breaks TO pc_app;
GRANT SELECT, INSERT, UPDATE ON pc.reflex_digests TO pc_app;
GRANT SELECT ON pc.detection_cursors, pc.detection_rule_state, pc.incidents, pc.incident_events, pc.suppressions,
    pc.alerts, pc.alert_evidence, pc.alert_events, pc.suppression_breaks, pc.operational_failures, pc.reflex_digests
    TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.reflex_digests;
DROP TABLE pc.operational_failures;
DROP TABLE pc.suppression_breaks;
DROP TABLE pc.alert_events;
DROP TABLE pc.alert_evidence;
DROP TABLE pc.alerts;
DROP TABLE pc.suppressions;
DROP FUNCTION pc.suppression_insert();
DROP FUNCTION pc.suppression_end();
DROP TABLE pc.incident_events;
DROP TABLE pc.incidents;
DROP TABLE pc.detection_sequences;
DROP TABLE pc.detection_window_groups;
DROP TABLE pc.detection_window_buckets;
DROP TABLE pc.detection_rule_state;
DROP TABLE pc.detection_cursors;
