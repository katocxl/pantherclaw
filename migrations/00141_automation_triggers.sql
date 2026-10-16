-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Automation triggers (G0 M11 part 2 D16-D23, D58, D59; HR-275..278,
-- T-122, T-123; founder decision F2).
--
-- Every trigger an automation sees is one row of pc.automation_triggers,
-- accepted or refused, with how it is known to be authentic and the
-- ancestry of the automations upstream of it. Accepted triggers start an
-- execution in the same transaction (the engine's Starter). Dedupe keys
-- (schedule occurrence, feed entry, webhook-id, manual idempotency key,
-- declared parameter key) are unique per automation while unexpired
-- (HR-277).
--
-- Schedules are materialized per automation; the platform-event consumer
-- keeps one cursor per org (compare-and-set); conditions keep one episode
-- row per subject and thresholds one count per group and minute.
--
-- Inbound event sources and automation destinations are inserted PENDING,
-- activated once by a person with a step-up, and DISABLED is final
-- (HR-275). Their secrets are sealed with the envelope key (HR-062).
-- Inbound bodies are never stored: a receipt keeps the webhook-id, type
-- and body digest for seven days. A delivery keeps its body until it is
-- delivered or failed.
--
-- automation_triggers.execution_id gains its foreign key with
-- pc.automation_executions (00142).

-- +goose Up

CREATE TABLE pc.automation_triggers (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    automation_id       uuid        NOT NULL,
    version_id          uuid        NOT NULL,
    kind                text        NOT NULL CHECK (kind IN ('SCHEDULE', 'EVENT', 'INBOUND', 'CONDITION', 'THRESHOLD', 'MANUAL')),
    mode                text        NOT NULL CHECK (mode IN ('LIVE', 'SHADOW', 'TEST')),
    source_ref          text        NOT NULL CHECK (char_length(source_ref) BETWEEN 1 AND 256),
    authenticity        text        NOT NULL CHECK (authenticity IN ('SCHEDULER', 'PLATFORM_FEED', 'SIGNED_SOURCE',
                                                                     'USER_STEP_UP', 'USER_SESSION')),
    authenticity_detail jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(authenticity_detail) = 'object'
                                                                 AND octet_length(authenticity_detail::text) <= 2048),
    params              jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object'
                                                                 AND octet_length(params::text) <= 4096),
    subjects            jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(subjects) = 'array'
                                                                 AND octet_length(subjects::text) <= 8192),
    evidence            jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(evidence) = 'array'
                                                                 AND octet_length(evidence::text) <= 8192),
    root_trigger_id     uuid        NOT NULL,
    ancestry            uuid[]      NOT NULL DEFAULT '{}' CHECK (cardinality(ancestry) <= 8
                                                                 AND array_position(ancestry, NULL) IS NULL),
    depth               integer     NOT NULL DEFAULT 0 CHECK (depth BETWEEN 0 AND 4),
    state               text        NOT NULL CHECK (state IN ('ACCEPTED', 'SHADOW', 'QUEUED', 'DISCARDED', 'EXPIRED',
                                                              'REFUSED_DUPLICATE', 'REFUSED_LOOP', 'REFUSED_LIMIT',
                                                              'REFUSED_CONCURRENCY', 'REFUSED_INVALID',
                                                              'REFUSED_CONDITION', 'REFUSED_WINDOW')),
    reason              text        CHECK (reason IS NULL OR reason ~ '^[A-Z][A-Z0-9_]{1,63}$'),
    execution_id        uuid,
    retried_from        uuid,
    queued_until        timestamptz,
    occurred_at         timestamptz NOT NULL,
    received_at         timestamptz NOT NULL DEFAULT now(),
    decided_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.automation_versions (org_id, id),
    -- An execution starts only from an accepted or shadow trigger; a
    -- refused, discarded or expired trigger never names one.
    CONSTRAINT automation_triggers_execution CHECK (execution_id IS NULL OR state IN ('ACCEPTED', 'SHADOW')),
    CONSTRAINT automation_triggers_queued CHECK ((state = 'QUEUED') OR queued_until IS NULL),
    CONSTRAINT automation_triggers_retry CHECK (retried_from IS NULL OR kind = 'MANUAL'),
    CONSTRAINT automation_triggers_depth CHECK ((depth = 0) = (cardinality(ancestry) = 0)),
    CONSTRAINT automation_triggers_root CHECK (depth > 0 OR root_trigger_id = id)
);
CREATE INDEX automation_triggers_recent ON pc.automation_triggers (org_id, automation_id, received_at DESC);
CREATE INDEX automation_triggers_queued ON pc.automation_triggers (org_id, automation_id, received_at)
    WHERE state = 'QUEUED';
CREATE UNIQUE INDEX automation_triggers_execution_unique ON pc.automation_triggers (org_id, execution_id)
    WHERE execution_id IS NOT NULL;

-- A trigger's identity, provenance and ancestry never change. Its state
-- moves only from ACCEPTED/SHADOW (an execution is attached once, or the
-- start is refused for concurrency) or from QUEUED (replayed, discarded,
-- expired).
-- +goose StatementBegin
CREATE FUNCTION pc.automation_trigger_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.received_at := now();
        NEW.decided_at := now();
        RETURN NEW;
    END IF;
    IF NEW.automation_id IS DISTINCT FROM OLD.automation_id OR NEW.version_id IS DISTINCT FROM OLD.version_id
            OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.mode IS DISTINCT FROM OLD.mode
            OR NEW.source_ref IS DISTINCT FROM OLD.source_ref OR NEW.authenticity IS DISTINCT FROM OLD.authenticity
            OR NEW.authenticity_detail IS DISTINCT FROM OLD.authenticity_detail
            OR NEW.params IS DISTINCT FROM OLD.params OR NEW.subjects IS DISTINCT FROM OLD.subjects
            OR NEW.evidence IS DISTINCT FROM OLD.evidence OR NEW.root_trigger_id IS DISTINCT FROM OLD.root_trigger_id
            OR NEW.ancestry IS DISTINCT FROM OLD.ancestry OR NEW.depth IS DISTINCT FROM OLD.depth
            OR NEW.retried_from IS DISTINCT FROM OLD.retried_from OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
            OR NEW.received_at IS DISTINCT FROM OLD.received_at THEN
        RAISE EXCEPTION 'a trigger record is immutable' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.execution_id IS NOT NULL AND (NEW.execution_id IS DISTINCT FROM OLD.execution_id
            OR NEW.state IS DISTINCT FROM OLD.state) THEN
        RAISE EXCEPTION 'a trigger that started an execution is final' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT (OLD.state = NEW.state
            OR (OLD.state IN ('ACCEPTED', 'SHADOW') AND NEW.state = 'REFUSED_CONCURRENCY')
            OR (OLD.state IN ('ACCEPTED', 'SHADOW') AND NEW.state = 'REFUSED_INVALID')
            OR (OLD.state = 'QUEUED' AND NEW.state IN ('ACCEPTED', 'SHADOW', 'DISCARDED', 'EXPIRED',
                                                        'REFUSED_CONCURRENCY', 'REFUSED_INVALID',
                                                        'REFUSED_DUPLICATE', 'REFUSED_LIMIT'))) THEN
        RAISE EXCEPTION 'trigger state % cannot become %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        NEW.decided_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER automation_triggers_guard BEFORE INSERT OR UPDATE ON pc.automation_triggers
    FOR EACH ROW EXECUTE FUNCTION pc.automation_trigger_guard();

-- One live claim per (automation, key) (HR-277). An expired claim may be
-- taken over by a later trigger.
CREATE TABLE pc.automation_dedupe (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    automation_id uuid        NOT NULL,
    key           text        NOT NULL CHECK (char_length(key) BETWEEN 1 AND 512),
    trigger_id    uuid        NOT NULL,
    expires_at    timestamptz NOT NULL,
    PRIMARY KEY (org_id, automation_id, key),
    FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id),
    -- Deferred: a key is claimed before its trigger row is written, so a
    -- duplicate is known before anything is recorded as accepted.
    FOREIGN KEY (org_id, trigger_id) REFERENCES pc.automation_triggers (org_id, id) DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX automation_dedupe_expiry ON pc.automation_dedupe (org_id, expires_at);

-- The materialized schedule of an automation whose enabled version has a
-- schedule trigger (D17).
CREATE TABLE pc.automation_schedules (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    automation_id uuid        NOT NULL,
    version_id    uuid        NOT NULL,
    cron          text        NOT NULL CHECK (char_length(cron) BETWEEN 9 AND 100),
    timezone      text        NOT NULL CHECK (char_length(timezone) BETWEEN 1 AND 64),
    next_fire_at  timestamptz,
    last_fire_at  timestamptz,
    state         text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'PAUSED')),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, automation_id),
    FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.automation_versions (org_id, id)
);
CREATE INDEX automation_schedules_due ON pc.automation_schedules (org_id, next_fire_at) WHERE state = 'ACTIVE';

-- The platform-event consumer's cursor per org (D18): the last feed seq
-- read, moved by compare-and-set.
CREATE TABLE pc.automation_feed_cursors (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    seq        bigint      NOT NULL DEFAULT 0 CHECK (seq >= 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

-- +goose StatementBegin
CREATE FUNCTION pc.automation_feed_cursor_forward() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.seq < OLD.seq THEN
        RAISE EXCEPTION 'an automation feed cursor never moves backwards' USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER automation_feed_cursors_forward BEFORE UPDATE ON pc.automation_feed_cursors
    FOR EACH ROW EXECUTE FUNCTION pc.automation_feed_cursor_forward();

-- One episode per (automation, probe subject) while its condition holds
-- (D19): since is when it started holding, fired_at when it fired.
CREATE TABLE pc.automation_condition_state (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    automation_id uuid        NOT NULL,
    subject_key   text        NOT NULL CHECK (char_length(subject_key) BETWEEN 1 AND 300),
    since         timestamptz NOT NULL,
    fired_at      timestamptz,
    seen_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, automation_id, subject_key),
    FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id)
);

-- Matching platform events per (automation, group, minute) (D19, D58):
-- ancestry is the union of the counted events' ancestries (≤ 8) and depth
-- their greatest depth.
CREATE TABLE pc.automation_threshold_counts (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    automation_id uuid        NOT NULL,
    group_key     text        NOT NULL CHECK (char_length(group_key) BETWEEN 1 AND 300),
    minute        timestamptz NOT NULL CHECK (date_trunc('minute', minute) = minute),
    count         integer     NOT NULL CHECK (count > 0),
    ancestry      uuid[]      NOT NULL DEFAULT '{}' CHECK (cardinality(ancestry) <= 8
                                                           AND array_position(ancestry, NULL) IS NULL),
    depth         integer     NOT NULL DEFAULT 0 CHECK (depth BETWEEN 0 AND 4),
    root_trigger_id uuid,
    PRIMARY KEY (org_id, automation_id, group_key, minute),
    FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id)
);
CREATE INDEX automation_threshold_counts_minute ON pc.automation_threshold_counts (org_id, minute);

-- Inbound event sources (D21, HR-275).
CREATE TABLE pc.automation_event_sources (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    name                 text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    description          text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    types                text[]      NOT NULL CHECK (cardinality(types) BETWEEN 1 AND 20
                                                     AND array_position(types, NULL) IS NULL),
    secret               bytea       NOT NULL CHECK (octet_length(secret) BETWEEN 16 AND 8192),
    prev_secret          bytea       CHECK (prev_secret IS NULL OR octet_length(prev_secret) BETWEEN 16 AND 8192),
    prev_until           timestamptz,
    rate_per_minute      integer     NOT NULL DEFAULT 60 CHECK (rate_per_minute BETWEEN 1 AND 600),
    state                text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'DISABLED')),
    created_by           uuid        NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    disabled_by          uuid,
    disabled_at          timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    FOREIGN KEY (org_id, disabled_by) REFERENCES pc.users (org_id, id),
    CHECK ((prev_secret IS NULL) = (prev_until IS NULL)),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'DISABLED') = (disabled_at IS NOT NULL))
);
CREATE UNIQUE INDEX automation_event_sources_name ON pc.automation_event_sources (org_id, name) WHERE state <> 'DISABLED';

-- Automation destinations (D22).
CREATE TABLE pc.automation_destinations (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    name                 text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    url                  text        NOT NULL CHECK (char_length(url) BETWEEN 9 AND 2048 AND url LIKE 'https://%'),
    internal             boolean     NOT NULL DEFAULT false,
    purposes             text[]      NOT NULL CHECK (cardinality(purposes) BETWEEN 1 AND 3
                                                     AND array_position(purposes, NULL) IS NULL
                                                     AND purposes <@ ARRAY['LAUNCH', 'DIGEST', 'NOTICE']::text[]),
    secret               bytea       NOT NULL CHECK (octet_length(secret) BETWEEN 16 AND 8192),
    prev_secret          bytea       CHECK (prev_secret IS NULL OR octet_length(prev_secret) BETWEEN 16 AND 8192),
    prev_until           timestamptz,
    state                text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'PAUSED', 'DISABLED')),
    created_by           uuid        NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    disabled_by          uuid,
    disabled_at          timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    FOREIGN KEY (org_id, disabled_by) REFERENCES pc.users (org_id, id),
    CHECK ((prev_secret IS NULL) = (prev_until IS NULL)),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state IN ('PENDING', 'DISABLED') OR activated_at IS NOT NULL),
    CHECK ((state = 'DISABLED') = (disabled_at IS NOT NULL))
);
CREATE UNIQUE INDEX automation_destinations_name ON pc.automation_destinations (org_id, name) WHERE state <> 'DISABLED';

-- Sources and destinations: what they are never changes, they are
-- inserted PENDING, activated once (by a person, with a credential) and
-- DISABLED is final.
-- +goose StatementBegin
CREATE FUNCTION pc.automation_endpoint_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    t text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.activated_by IS NOT NULL OR NEW.prev_secret IS NOT NULL THEN
            RAISE EXCEPTION 'an automation endpoint is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        IF TG_TABLE_NAME = 'automation_event_sources' THEN
            FOREACH t IN ARRAY NEW.types LOOP
                IF t !~ '^[a-z][a-z0-9_.-]{0,99}$' THEN
                    RAISE EXCEPTION 'an event type is a lowercase name of at most 100 characters'
                        USING ERRCODE = 'check_violation';
                END IF;
            END LOOP;
        END IF;
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.name IS DISTINCT FROM OLD.name OR NEW.created_by IS DISTINCT FROM OLD.created_by
            OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'an automation endpoint keeps its identity' USING ERRCODE = 'check_violation';
    END IF;
    IF TG_TABLE_NAME = 'automation_event_sources' THEN
        IF NEW.types IS DISTINCT FROM OLD.types OR NEW.rate_per_minute IS DISTINCT FROM OLD.rate_per_minute
                OR NEW.description IS DISTINCT FROM OLD.description THEN
            RAISE EXCEPTION 'an event source keeps its declared types and rate' USING ERRCODE = 'check_violation';
        END IF;
    ELSE
        IF to_jsonb(NEW) ->> 'url' IS DISTINCT FROM to_jsonb(OLD) ->> 'url'
                OR to_jsonb(NEW) ->> 'internal' IS DISTINCT FROM to_jsonb(OLD) ->> 'internal'
                OR to_jsonb(NEW) -> 'purposes' IS DISTINCT FROM to_jsonb(OLD) -> 'purposes' THEN
            RAISE EXCEPTION 'a destination keeps its URL and purposes' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF OLD.state = 'DISABLED' THEN
        RAISE EXCEPTION 'a disabled automation endpoint stays disabled' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state IS DISTINCT FROM 'PENDING' THEN
        RAISE EXCEPTION 'an automation endpoint cannot return to PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NOT NULL AND (NEW.activated_by IS DISTINCT FROM OLD.activated_by
            OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
            OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'an automation endpoint is activated once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NULL AND NEW.activated_by IS NOT NULL THEN
        NEW.activated_at := now();
    END IF;
    IF NEW.state = 'DISABLED' THEN
        NEW.disabled_at := now();
    END IF;
    -- A rotated secret overlaps for at most 24 hours (HR-275).
    IF NEW.prev_until IS NOT NULL AND NEW.prev_until > now() + interval '24 hours' THEN
        RAISE EXCEPTION 'a previous secret overlaps for at most 24 hours' USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER automation_event_sources_guard BEFORE INSERT OR UPDATE ON pc.automation_event_sources
    FOR EACH ROW EXECUTE FUNCTION pc.automation_endpoint_guard();
CREATE TRIGGER automation_destinations_guard BEFORE INSERT OR UPDATE ON pc.automation_destinations
    FOR EACH ROW EXECUTE FUNCTION pc.automation_endpoint_guard();

-- One receipt per (source, webhook-id) for seven days (HR-275); never the
-- body.
CREATE TABLE pc.automation_event_receipts (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    source_id   uuid        NOT NULL,
    webhook_id  text        NOT NULL CHECK (char_length(webhook_id) BETWEEN 1 AND 256),
    type        text        NOT NULL CHECK (char_length(type) BETWEEN 1 AND 100),
    body_sha256 bytea       NOT NULL CHECK (octet_length(body_sha256) = 32),
    received_at timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (org_id, source_id, webhook_id),
    FOREIGN KEY (org_id, source_id) REFERENCES pc.automation_event_sources (org_id, id),
    CHECK (expires_at > received_at)
);
CREATE INDEX automation_event_receipts_expiry ON pc.automation_event_receipts (org_id, expires_at);

-- One webhook to an automation destination (D22).
CREATE TABLE pc.automation_deliveries (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    destination_id  uuid        NOT NULL,
    execution_id    uuid        NOT NULL,
    kind            text        NOT NULL CHECK (kind IN ('LAUNCH', 'DIGEST', 'NOTICE')),
    msg_id          text        NOT NULL CHECK (msg_id ~ '^msg_[0-9a-f]{32}$'),
    body            jsonb       CHECK (body IS NULL OR octet_length(body::text) <= 65536),
    body_sha256     bytea       NOT NULL CHECK (octet_length(body_sha256) = 32),
    state           text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'DELIVERED', 'FAILED')),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_status     integer     CHECK (last_status IS NULL OR last_status BETWEEN 100 AND 599),
    last_error      text        CHECK (last_error IS NULL OR last_error ~ '^[a-z0-9_]{1,64}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, msg_id),
    FOREIGN KEY (org_id, destination_id) REFERENCES pc.automation_destinations (org_id, id),
    CHECK ((state = 'DELIVERED') = (delivered_at IS NOT NULL)),
    -- The body is kept only while it may still be sent.
    CHECK ((state = 'PENDING') = (body IS NOT NULL))
);
CREATE INDEX automation_deliveries_due ON pc.automation_deliveries (org_id, next_attempt_at) WHERE state = 'PENDING';
CREATE INDEX automation_deliveries_execution ON pc.automation_deliveries (org_id, execution_id);

-- +goose StatementBegin
CREATE FUNCTION pc.automation_delivery_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.destination_id IS DISTINCT FROM OLD.destination_id OR NEW.execution_id IS DISTINCT FROM OLD.execution_id
            OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.msg_id IS DISTINCT FROM OLD.msg_id
            OR NEW.body_sha256 IS DISTINCT FROM OLD.body_sha256 OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR (NEW.body IS NOT NULL AND NEW.body IS DISTINCT FROM OLD.body) THEN
        RAISE EXCEPTION 'a delivery keeps what it sends' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state <> 'PENDING' THEN
        RAISE EXCEPTION 'a delivered or failed delivery is final' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER automation_deliveries_guard BEFORE UPDATE ON pc.automation_deliveries
    FOR EACH ROW EXECUTE FUNCTION pc.automation_delivery_guard();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['automation_triggers', 'automation_dedupe', 'automation_schedules',
                             'automation_feed_cursors', 'automation_condition_state', 'automation_threshold_counts',
                             'automation_event_sources', 'automation_destinations', 'automation_event_receipts',
                             'automation_deliveries']
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

GRANT SELECT, INSERT ON pc.automation_triggers, pc.automation_dedupe, pc.automation_schedules,
    pc.automation_feed_cursors, pc.automation_condition_state, pc.automation_threshold_counts,
    pc.automation_event_sources, pc.automation_destinations, pc.automation_event_receipts,
    pc.automation_deliveries TO pc_app;
GRANT UPDATE (state, reason, execution_id, queued_until, decided_at) ON pc.automation_triggers TO pc_app;
GRANT UPDATE (trigger_id, expires_at) ON pc.automation_dedupe TO pc_app;
GRANT DELETE ON pc.automation_dedupe TO pc_app;
GRANT UPDATE (version_id, cron, timezone, next_fire_at, last_fire_at, state, updated_at) ON pc.automation_schedules TO pc_app;
GRANT DELETE ON pc.automation_schedules TO pc_app;
GRANT UPDATE (seq, updated_at) ON pc.automation_feed_cursors TO pc_app;
GRANT UPDATE (since, fired_at, seen_at) ON pc.automation_condition_state TO pc_app;
GRANT DELETE ON pc.automation_condition_state TO pc_app;
GRANT UPDATE (count, ancestry, depth, root_trigger_id) ON pc.automation_threshold_counts TO pc_app;
GRANT DELETE ON pc.automation_threshold_counts TO pc_app;
GRANT UPDATE (secret, prev_secret, prev_until, state, activated_by, activated_credential, activated_at, disabled_by,
    disabled_at, updated_at) ON pc.automation_event_sources, pc.automation_destinations TO pc_app;
GRANT UPDATE (type, body_sha256, received_at, expires_at) ON pc.automation_event_receipts TO pc_app;
GRANT DELETE ON pc.automation_event_receipts TO pc_app;
GRANT UPDATE (body, state, attempts, next_attempt_at, last_status, last_error, delivered_at) ON pc.automation_deliveries TO pc_app;
GRANT SELECT ON pc.automation_triggers, pc.automation_dedupe, pc.automation_schedules, pc.automation_feed_cursors,
    pc.automation_condition_state, pc.automation_threshold_counts, pc.automation_event_receipts TO pc_audit_ro;
GRANT SELECT (org_id, id, name, description, types, prev_until, rate_per_minute, state, created_by, created_at,
    activated_by, activated_credential, activated_at, disabled_by, disabled_at, updated_at)
    ON pc.automation_event_sources TO pc_audit_ro;
GRANT SELECT (org_id, id, name, url, internal, purposes, prev_until, state, created_by, created_at, activated_by,
    activated_credential, activated_at, disabled_by, disabled_at, updated_at) ON pc.automation_destinations TO pc_audit_ro;
GRANT SELECT (org_id, id, destination_id, execution_id, kind, msg_id, body_sha256, state, attempts, next_attempt_at,
    last_status, last_error, created_at, delivered_at) ON pc.automation_deliveries TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.automation_deliveries;
DROP FUNCTION pc.automation_delivery_guard();
DROP TABLE pc.automation_event_receipts;
DROP TABLE pc.automation_destinations;
DROP TABLE pc.automation_event_sources;
DROP FUNCTION pc.automation_endpoint_guard();
DROP TABLE pc.automation_threshold_counts;
DROP TABLE pc.automation_condition_state;
DROP TABLE pc.automation_feed_cursors;
DROP FUNCTION pc.automation_feed_cursor_forward();
DROP TABLE pc.automation_schedules;
DROP TABLE pc.automation_dedupe;
DROP TABLE pc.automation_triggers;
DROP FUNCTION pc.automation_trigger_guard();
