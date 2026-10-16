-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Protected changes and compromised publishers (G0 M11 part 2 D42, D42a,
-- D43; HR-292, HR-293, T-129).
--
-- An org protects a category of change (tool meaning, consequence rules,
-- custody, coverage exclusions) by setting it to DISTINCT_PUBLISHER; no row
-- means OFF. With a category on, a widening change in it is stored here as
-- PENDING and applies only when a different, non-compromised person with
-- the category's permission confirms its change request (internal/changes,
-- domain 'protected'); the surface's own code then runs again inside the
-- confirming transaction as the author. The payload is the surface's
-- input, never plaintext secret material (a credential stays sealed). A
-- newer change for the same subject voids the older pending one.
--
-- An emergency change (incident.respond with a step-up) applies at once,
-- is recorded EMERGENCY and must be reviewed by a distinct publisher within
-- 72 hours.
--
-- A person marked compromised (Business) stops confirming, approving,
-- publishing, activating and promoting at once; what they published since
-- the given time is listed and every item is reviewed KEEP or ROLLBACK by
-- someone else before the mark can be cleared by two other people.

-- +goose Up
CREATE TABLE pc.protected_change_settings (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    category   text        NOT NULL CHECK (category IN ('TOOL_MEANING', 'CONSEQUENCE_RULES', 'CUSTODY', 'COVERAGE_EXCLUSION')),
    mode       text        NOT NULL CHECK (mode IN ('OFF', 'DISTINCT_PUBLISHER')),
    updated_by uuid        NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, category),
    FOREIGN KEY (org_id, updated_by) REFERENCES pc.users (org_id, id)
);

CREATE TABLE pc.protected_changes (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    category          text        NOT NULL CHECK (category IN ('TOOL_MEANING', 'CONSEQUENCE_RULES', 'CUSTODY', 'COVERAGE_EXCLUSION')),
    -- Which surface's code applies the change (and SETTINGS: turning the
    -- category off).
    surface           text        NOT NULL CHECK (surface ~ '^[a-z][a-z_]*(\.[a-z_]+){1,3}$' AND char_length(surface) <= 64),
    subject_id        uuid        NOT NULL,
    subject           text        NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 256),
    summary           jsonb       NOT NULL CHECK (jsonb_typeof(summary) = 'object' AND octet_length(summary::text) <= 16384),
    widening          text[]      NOT NULL CHECK (cardinality(widening) BETWEEN 1 AND 32 AND array_position(widening, NULL) IS NULL),
    digest            bytea       NOT NULL CHECK (octet_length(digest) = 32),
    -- The subject's state when the change was asked; the confirmed re-run
    -- refuses when it differs (SUBJECT_CHANGED, D72 P5).
    subject_digest    bytea       NOT NULL CHECK (octet_length(subject_digest) = 32),
    payload           jsonb       NOT NULL CHECK (octet_length(payload::text) <= 262144),
    author            uuid        NOT NULL,
    author_credential text        NOT NULL CHECK (author_credential ~ '^[a-z_]{1,32}$'),
    state             text        NOT NULL DEFAULT 'PENDING'
                                  CHECK (state IN ('PENDING', 'APPLIED', 'EMERGENCY', 'DECLINED', 'EXPIRED', 'VOIDED')),
    change_request_id uuid,
    publisher         uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    decided_at        timestamptz,
    decided_reason    text        CHECK (decided_reason ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    -- An emergency change: who applied it, with which key, and its review.
    -- review_state is DUE, REVIEWED or REVIEW_EXPIRED; an expired review
    -- leaves the change applied (EMERGENCY) until a new review is opened
    -- (D98 L3).
    review_state      text        CHECK (review_state IN ('DUE', 'REVIEWED', 'REVIEW_EXPIRED')),
    review_due_at     timestamptz,
    review_request_id uuid,
    reviewed_by       uuid,
    reviewed_at       timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, author) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, publisher) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, reviewed_by) REFERENCES pc.users (org_id, id),
    CHECK ((state = 'PENDING') = (decided_at IS NULL)),
    CHECK ((state IN ('APPLIED', 'EMERGENCY')) = (publisher IS NOT NULL)),
    CHECK (publisher IS NULL OR state = 'EMERGENCY' OR publisher <> author),
    CHECK ((state = 'EMERGENCY') = (review_due_at IS NOT NULL)),
    CHECK ((state = 'EMERGENCY') = (review_state IS NOT NULL)),
    CHECK (state <> 'EMERGENCY' OR (review_state = 'REVIEWED') = (reviewed_by IS NOT NULL)),
    CHECK ((reviewed_by IS NULL) = (reviewed_at IS NULL)),
    CHECK (reviewed_by IS NULL OR (state = 'EMERGENCY' AND reviewed_by <> publisher AND reviewed_by <> author))
);
-- One pending change per subject (a newer one voids the older, D42a).
CREATE UNIQUE INDEX protected_changes_one_pending ON pc.protected_changes (org_id, surface, subject_id) WHERE state = 'PENDING';
CREATE INDEX protected_changes_created ON pc.protected_changes (org_id, created_at DESC);
CREATE INDEX protected_changes_request ON pc.protected_changes (org_id, change_request_id) WHERE change_request_id IS NOT NULL;
CREATE INDEX protected_changes_publisher ON pc.protected_changes (org_id, publisher, decided_at) WHERE publisher IS NOT NULL;

-- What a change is never changes; a decided change stays decided, and only
-- an emergency change gains its review.
-- +goose StatementBegin
CREATE FUNCTION pc.protected_change_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state NOT IN ('PENDING', 'EMERGENCY') OR NEW.reviewed_by IS NOT NULL THEN
            RAISE EXCEPTION 'a protected change is inserted PENDING or EMERGENCY' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.review_state := NULL;
        IF NEW.state = 'EMERGENCY' THEN
            NEW.decided_at := now();
            NEW.review_due_at := now() + interval '72 hours';
            NEW.review_state := 'DUE';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.category IS DISTINCT FROM OLD.category OR NEW.surface IS DISTINCT FROM OLD.surface
            OR NEW.subject_id IS DISTINCT FROM OLD.subject_id OR NEW.subject IS DISTINCT FROM OLD.subject
            OR NEW.summary IS DISTINCT FROM OLD.summary OR NEW.widening IS DISTINCT FROM OLD.widening
            OR NEW.digest IS DISTINCT FROM OLD.digest OR NEW.payload IS DISTINCT FROM OLD.payload
            OR NEW.subject_digest IS DISTINCT FROM OLD.subject_digest
            OR NEW.author IS DISTINCT FROM OLD.author OR NEW.author_credential IS DISTINCT FROM OLD.author_credential
            OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a protected change never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state <> 'PENDING' AND (NEW.state IS DISTINCT FROM OLD.state OR NEW.publisher IS DISTINCT FROM OLD.publisher
            OR NEW.decided_at IS DISTINCT FROM OLD.decided_at OR NEW.change_request_id IS DISTINCT FROM OLD.change_request_id
            OR NEW.review_due_at IS DISTINCT FROM OLD.review_due_at) THEN
        RAISE EXCEPTION 'a decided protected change stays decided' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'PENDING' THEN
        IF NEW.review_state IS DISTINCT FROM OLD.review_state THEN
            RAISE EXCEPTION 'a review state follows the emergency' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.state = 'EMERGENCY' THEN
            NEW.review_due_at := now() + interval '72 hours';
            NEW.review_state := 'DUE';
        END IF;
    END IF;
    IF OLD.state = 'PENDING' AND NEW.state <> 'PENDING' THEN
        NEW.decided_at := now();
    END IF;
    IF OLD.reviewed_by IS NOT NULL AND (NEW.reviewed_by IS DISTINCT FROM OLD.reviewed_by OR NEW.reviewed_at IS DISTINCT FROM OLD.reviewed_at) THEN
        RAISE EXCEPTION 'an emergency change is reviewed once' USING ERRCODE = 'check_violation';
    END IF;
    -- An emergency change's review (D98 L3): DUE becomes REVIEWED when
    -- someone reviews it or REVIEW_EXPIRED when its request expires; a new
    -- review moves REVIEW_EXPIRED back to DUE, with a new request and 72
    -- hours. The change itself stays applied throughout.
    IF OLD.state = 'EMERGENCY' THEN
        IF OLD.reviewed_by IS NULL AND NEW.reviewed_by IS NOT NULL THEN
            IF OLD.review_state <> 'DUE' OR NEW.review_state IS DISTINCT FROM OLD.review_state THEN
                RAISE EXCEPTION 'only a due review is confirmed' USING ERRCODE = 'check_violation';
            END IF;
            NEW.review_state := 'REVIEWED';
        ELSIF NEW.review_state IS DISTINCT FROM OLD.review_state THEN
            IF OLD.review_state = 'DUE' AND NEW.review_state = 'REVIEW_EXPIRED'
                    AND NEW.review_request_id IS NOT DISTINCT FROM OLD.review_request_id THEN
                NULL;
            ELSIF OLD.review_state = 'REVIEW_EXPIRED' AND NEW.review_state = 'DUE'
                    AND NEW.review_request_id IS NOT NULL AND NEW.review_request_id IS DISTINCT FROM OLD.review_request_id THEN
                NEW.review_due_at := now() + interval '72 hours';
            ELSE
                RAISE EXCEPTION 'review state % cannot become %', OLD.review_state, NEW.review_state
                    USING ERRCODE = 'check_violation';
            END IF;
        ELSIF NEW.review_request_id IS DISTINCT FROM OLD.review_request_id AND OLD.review_request_id IS NOT NULL THEN
            RAISE EXCEPTION 'a new review request needs an expired review' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF OLD.reviewed_by IS NULL AND NEW.reviewed_by IS NOT NULL THEN
        NEW.reviewed_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER protected_changes_guard BEFORE INSERT OR UPDATE ON pc.protected_changes
    FOR EACH ROW EXECUTE FUNCTION pc.protected_change_guard();

CREATE TABLE pc.compromised_publishers (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    user_id           uuid        NOT NULL,
    since             timestamptz NOT NULL,
    reason            text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
    state             text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'CLEARED')),
    marked_by         uuid        NOT NULL,
    marked_credential uuid        NOT NULL,
    marked_at         timestamptz NOT NULL DEFAULT now(),
    clear_request_id  uuid,
    cleared_at        timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, marked_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, marked_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK (since <= marked_at),
    CHECK ((state = 'CLEARED') = (cleared_at IS NOT NULL))
);
CREATE UNIQUE INDEX compromised_publishers_one_active ON pc.compromised_publishers (org_id, user_id) WHERE state = 'ACTIVE';
CREATE INDEX compromised_publishers_marked ON pc.compromised_publishers (org_id, marked_at DESC);

-- A mark is cleared once and never re-opened.
-- +goose StatementBegin
CREATE FUNCTION pc.compromised_publisher_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'ACTIVE' OR NEW.cleared_at IS NOT NULL THEN
            RAISE EXCEPTION 'a compromise is inserted ACTIVE' USING ERRCODE = 'check_violation';
        END IF;
        NEW.marked_at := now();
        IF NEW.since > NEW.marked_at THEN
            RAISE EXCEPTION 'since is in the future' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.since IS DISTINCT FROM OLD.since OR NEW.reason IS DISTINCT FROM OLD.reason
            OR NEW.marked_by IS DISTINCT FROM OLD.marked_by OR NEW.marked_credential IS DISTINCT FROM OLD.marked_credential
            OR NEW.marked_at IS DISTINCT FROM OLD.marked_at THEN
        RAISE EXCEPTION 'a compromise never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'CLEARED' AND (NEW.state IS DISTINCT FROM OLD.state OR NEW.cleared_at IS DISTINCT FROM OLD.cleared_at
            OR NEW.clear_request_id IS DISTINCT FROM OLD.clear_request_id) THEN
        RAISE EXCEPTION 'a cleared compromise stays cleared' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'ACTIVE' AND NEW.state = 'CLEARED' THEN
        NEW.cleared_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER compromised_publishers_guard BEFORE INSERT OR UPDATE ON pc.compromised_publishers
    FOR EACH ROW EXECUTE FUNCTION pc.compromised_publisher_guard();

-- One independent review of one exposed item: never by the compromised
-- person, once per item.
CREATE TABLE pc.compromise_reviews (
    org_id        uuid        NOT NULL,
    compromise_id uuid        NOT NULL,
    item_kind     text        NOT NULL CHECK (item_kind IN ('POLICY_VERSION', 'POLICY_CHANGE', 'PACKAGE_VERSION', 'PACKAGE_KEY',
                                                            'AUTOMATION_VERSION', 'PROTECTED_CHANGE', 'PROMOTION', 'GRANT')),
    item_id       text        NOT NULL CHECK (char_length(item_id) BETWEEN 1 AND 256),
    decision      text        NOT NULL CHECK (decision IN ('KEEP', 'ROLLBACK')),
    reviewer      uuid        NOT NULL,
    note          text        CHECK (char_length(note) BETWEEN 1 AND 500),
    reviewed_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, compromise_id, item_kind, item_id),
    FOREIGN KEY (org_id, compromise_id) REFERENCES pc.compromised_publishers (org_id, id),
    FOREIGN KEY (org_id, reviewer) REFERENCES pc.users (org_id, id)
);

-- +goose StatementBegin
CREATE FUNCTION pc.compromise_review_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM pc.compromised_publishers p
               WHERE p.org_id = NEW.org_id AND p.id = NEW.compromise_id AND (p.user_id = NEW.reviewer OR p.state <> 'ACTIVE')) THEN
        RAISE EXCEPTION 'a compromised person never reviews their own items, and a cleared compromise takes no reviews'
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.reviewed_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER compromise_reviews_guard BEFORE INSERT ON pc.compromise_reviews
    FOR EACH ROW EXECUTE FUNCTION pc.compromise_review_guard();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['protected_change_settings', 'protected_changes', 'compromised_publishers', 'compromise_reviews']
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

GRANT SELECT, INSERT ON pc.protected_change_settings, pc.protected_changes, pc.compromised_publishers,
    pc.compromise_reviews TO pc_app;
GRANT UPDATE (mode, updated_by, updated_at) ON pc.protected_change_settings TO pc_app;
GRANT UPDATE (state, change_request_id, publisher, decided_at, decided_reason, review_state, review_due_at,
    review_request_id, reviewed_by, reviewed_at) ON pc.protected_changes TO pc_app;
GRANT UPDATE (state, clear_request_id, cleared_at) ON pc.compromised_publishers TO pc_app;
GRANT SELECT ON pc.protected_change_settings, pc.protected_changes, pc.compromised_publishers,
    pc.compromise_reviews TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.compromise_reviews;
DROP FUNCTION pc.compromise_review_guard();
DROP TABLE pc.compromised_publishers;
DROP FUNCTION pc.compromised_publisher_guard();
DROP TABLE pc.protected_changes;
DROP FUNCTION pc.protected_change_guard();
DROP TABLE pc.protected_change_settings;
