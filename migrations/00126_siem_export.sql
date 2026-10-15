-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- SIEM export (G0 M10 D35, D36; PN-018, F537, HR-259, HR-260, founder
-- decision F3). A destination is an HTTPS URL that receives OCSF 1.9
-- batches signed with Standard Webhooks. It is created PENDING through the
-- API and becomes ACTIVE only when a person activates it on its page with a
-- fresh WebAuthn step-up (activated_by, activated_credential). The URL,
-- the internal flag and the data classes never change once stored: a
-- different target is a new destination, so a step-up always covers what
-- is sent where. A private or loopback target needs internal = true, which
-- the same activation step-up confirms. Signing secrets are envelope
-- ciphertexts bound to org, table, column and row (HR-062); pc_audit_ro
-- cannot read them.
--
-- Each destination has one cursor over the evidence feed (the ledger chain
-- seq), moved by compare-and-set, and a batch log: a batch is a fixed seq
-- range, re-sent identically (same webhook-id) on every retry. Delivery
-- health is kept on the destination: configured (ACTIVE) is separate from
-- delivery confirmed (confirmed_at, the first 2xx).

-- +goose Up
CREATE TABLE pc.siem_destinations (
    org_id                 uuid        NOT NULL REFERENCES pc.orgs (id),
    id                     uuid        NOT NULL,
    name                   text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    url                    text        NOT NULL CHECK (char_length(url) BETWEEN 9 AND 2048 AND url LIKE 'https://%'),
    internal               boolean     NOT NULL DEFAULT false,
    data_classes           text[]      NOT NULL CHECK (cardinality(data_classes) BETWEEN 1 AND 6
                                                       AND array_position(data_classes, NULL) IS NULL
                                                       AND data_classes <@ ARRAY['decisions', 'alerts', 'incidents', 'audit',
                                                                                 'containment', 'coverage']::text[]),
    format                 text        NOT NULL DEFAULT 'ocsf_1_9' CHECK (format = 'ocsf_1_9'),
    state                  text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'PAUSED', 'DISABLED')),
    secret                 bytea       NOT NULL CHECK (octet_length(secret) BETWEEN 16 AND 8192),
    prev_secret            bytea       CHECK (prev_secret IS NULL OR octet_length(prev_secret) BETWEEN 16 AND 8192),
    prev_secret_expires_at timestamptz,
    created_by             text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at             timestamptz NOT NULL DEFAULT now(),
    activated_by           uuid,
    activated_credential   uuid,
    activated_at           timestamptz,
    updated_at             timestamptz NOT NULL DEFAULT now(),
    -- Delivery health (F537).
    confirmed_at           timestamptz,
    last_delivered_seq     bigint      CHECK (last_delivered_seq IS NULL OR last_delivered_seq > 0),
    last_delivered_at      timestamptz,
    consecutive_failures   integer     NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    failing_since          timestamptz,
    last_failure_at        timestamptz,
    last_failure_code      text        CHECK (last_failure_code IS NULL OR last_failure_code ~ '^[a-z0-9_]{1,64}$'),
    delivered_batches      bigint      NOT NULL DEFAULT 0 CHECK (delivered_batches >= 0),
    failed_batches         bigint      NOT NULL DEFAULT 0 CHECK (failed_batches >= 0),
    retries                bigint      NOT NULL DEFAULT 0 CHECK (retries >= 0),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((prev_secret IS NULL) = (prev_secret_expires_at IS NULL)),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state IN ('PENDING', 'DISABLED') OR activated_at IS NOT NULL),
    CHECK ((consecutive_failures = 0) = (failing_since IS NULL)),
    CHECK (confirmed_at IS NOT NULL OR last_delivered_at IS NULL)
);
-- A deleted (DISABLED) destination frees its name.
CREATE UNIQUE INDEX siem_destinations_name ON pc.siem_destinations (org_id, name) WHERE state <> 'DISABLED';
CREATE INDEX siem_destinations_active ON pc.siem_destinations (org_id) WHERE state = 'ACTIVE';

-- The URL, the internal flag, the data classes and the creator never
-- change, a destination is inserted PENDING and never activated without a
-- person and a key, and DISABLED is final (HR-259).
-- +goose StatementBegin
CREATE FUNCTION pc.siem_destination_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.activated_by IS NOT NULL OR NEW.confirmed_at IS NOT NULL THEN
            RAISE EXCEPTION 'a SIEM destination is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF OLD.state = 'DISABLED' AND NEW.state IS DISTINCT FROM 'DISABLED' THEN
        RAISE EXCEPTION 'a disabled SIEM destination stays disabled' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state IS DISTINCT FROM 'PENDING' THEN
        RAISE EXCEPTION 'a SIEM destination cannot return to PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NOT NULL AND (NEW.activated_by IS DISTINCT FROM OLD.activated_by
            OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
            OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'a SIEM destination is activated once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NULL AND NEW.activated_by IS NOT NULL THEN
        NEW.activated_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER siem_destinations_guard BEFORE INSERT OR UPDATE ON pc.siem_destinations
    FOR EACH ROW EXECUTE FUNCTION pc.siem_destination_guard();

-- One cursor per destination: the last feed seq delivered (D36). Moved
-- only by compare-and-set (WHERE seq = $old).
CREATE TABLE pc.siem_cursors (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    destination_id uuid        NOT NULL,
    seq            bigint      NOT NULL DEFAULT 0 CHECK (seq >= 0),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, destination_id),
    FOREIGN KEY (org_id, destination_id) REFERENCES pc.siem_destinations (org_id, id)
);

-- A cursor never moves backwards.
-- +goose StatementBegin
CREATE FUNCTION pc.siem_cursor_forward() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.seq < OLD.seq THEN
        RAISE EXCEPTION 'a SIEM cursor never moves backwards' USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER siem_cursors_forward BEFORE UPDATE ON pc.siem_cursors
    FOR EACH ROW EXECUTE FUNCTION pc.siem_cursor_forward();

-- One batch: the events of the feed range (from_seq, to_seq] that the
-- destination's data classes select (event_count may be 0 when none do; such
-- a batch is never sent). PENDING until DELIVERED; FAILED after the last
-- attempt of the schedule, while retries continue at the last interval:
-- the cursor never skips a batch.
CREATE TABLE pc.siem_batches (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    destination_id  uuid        NOT NULL,
    from_seq        bigint      NOT NULL CHECK (from_seq >= 0),
    to_seq          bigint      NOT NULL,
    event_count     integer     NOT NULL CHECK (event_count BETWEEN 0 AND 100),
    body_bytes      integer     NOT NULL CHECK (body_bytes BETWEEN 0 AND 1048576),
    -- Feed entries in the range too large for any batch (never expected):
    -- recorded here and as an owned failure, never skipped silently (D64).
    skipped_uids    uuid[]      NOT NULL DEFAULT '{}' CHECK (cardinality(skipped_uids) <= 500),
    state           text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'DELIVERED', 'FAILED')),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_attempt_at timestamptz,
    last_status     integer     CHECK (last_status IS NULL OR last_status BETWEEN 100 AND 599),
    last_error      text        CHECK (last_error IS NULL OR last_error ~ '^[a-z0-9_]{1,64}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, destination_id, from_seq),
    FOREIGN KEY (org_id, destination_id) REFERENCES pc.siem_destinations (org_id, id),
    CHECK (to_seq > from_seq),
    CHECK ((state = 'DELIVERED') = (delivered_at IS NOT NULL))
);
-- At most one open batch per destination: batches go out in order.
CREATE UNIQUE INDEX siem_batches_open ON pc.siem_batches (org_id, destination_id) WHERE state <> 'DELIVERED';
CREATE INDEX siem_batches_recent ON pc.siem_batches (org_id, destination_id, created_at DESC);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['siem_destinations', 'siem_cursors', 'siem_batches']
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

GRANT SELECT, INSERT ON pc.siem_destinations, pc.siem_cursors, pc.siem_batches TO pc_app;
GRANT UPDATE (state, secret, prev_secret, prev_secret_expires_at, activated_by, activated_credential, activated_at,
    updated_at, confirmed_at, last_delivered_seq, last_delivered_at, consecutive_failures, failing_since,
    last_failure_at, last_failure_code, delivered_batches, failed_batches, retries) ON pc.siem_destinations TO pc_app;
GRANT UPDATE (seq, updated_at) ON pc.siem_cursors TO pc_app;
GRANT UPDATE (state, attempts, next_attempt_at, last_attempt_at, last_status, last_error, delivered_at)
    ON pc.siem_batches TO pc_app;
GRANT DELETE ON pc.siem_batches TO pc_app;
GRANT SELECT (org_id, id, name, url, internal, data_classes, format, state, prev_secret_expires_at, created_by,
    created_at, activated_by, activated_credential, activated_at, updated_at, confirmed_at, last_delivered_seq,
    last_delivered_at, consecutive_failures, failing_since, last_failure_at, last_failure_code, delivered_batches,
    failed_batches, retries) ON pc.siem_destinations TO pc_audit_ro;
GRANT SELECT ON pc.siem_cursors, pc.siem_batches TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.siem_batches;
DROP TABLE pc.siem_cursors;
DROP TABLE pc.siem_destinations;
DROP FUNCTION pc.siem_cursor_forward();
DROP FUNCTION pc.siem_destination_guard();
