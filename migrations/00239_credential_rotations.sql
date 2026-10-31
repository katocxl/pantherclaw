-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Target-confirmed rotation of a GitHub App key (G0 M20 S20c, D253, F424;
-- HR-517..520, T-224). GitHub has no API that creates or deletes an App
-- private key, so a person creates the new key in the App's settings,
-- seals it (pclaw seal) and later deletes the old one there. PantherClaw
-- tests the new key at GitHub and confirms the old one is dead, always
-- through the gateway, so a key is opened only in gateway memory (HR-060).
--
-- * credential_rotations: one rotation of one connection's credential,
--   REQUESTED → CANDIDATE_SEALED → TESTING → ACTIVATING →
--   AWAITING_OLD_REMOVAL → CONFIRMING → CONFIRMED, or FAILED (before
--   activation) or ROLLED_BACK (only from ACTIVATING, until rollback_until:
--   24 hours after activation at most; HR-519). CONFIRMING returns to
--   AWAITING_OLD_REMOVAL while GitHub still accepts the old key. At most
--   one open rotation per connection.
-- * credentials gain CANDIDATE: the sealed new key, which no gateway
--   configuration serves (that query serves ACTIVE only; HR-517). A state
--   moves only forward (ACTIVE → SUPERSEDED or REVOKED, SUPERSEDED →
--   REVOKED, CANDIDATE → ACTIVE or REVOKED), except that the candidate
--   becomes ACTIVE, and a SUPERSEDED old key ACTIVE again on rollback, only
--   while their rotation is ACTIVATING. REVOKED is final.
-- * verifications gain the purposes credential_rotation_test and
--   credential_rotation_confirm: leases of no transaction that the
--   connection's gateway runs with the candidate, or the old key, which the
--   lease carries; the task's request holds only ids, never sealed bytes
--   (HR-061).

-- +goose Up
-- Checks on the small credentials table are swapped as they are; a new
-- state widens the old check, so every row satisfies it.
ALTER TABLE pc.credentials
    DROP CONSTRAINT credentials_state_check,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT credentials_state_check CHECK (state IN ('CANDIDATE', 'ACTIVE', 'SUPERSEDED', 'REVOKED'));
-- credentials is small, and the index has no CANDIDATE row to find yet.
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX credentials_candidate ON pc.credentials (org_id, connection_id) WHERE state = 'CANDIDATE';

CREATE TABLE pc.credential_rotations (
    org_id                  uuid        NOT NULL REFERENCES pc.orgs (id),
    id                      uuid        NOT NULL,
    connection_id           uuid        NOT NULL,
    state                   text        NOT NULL DEFAULT 'REQUESTED' CHECK (state IN ('REQUESTED', 'CANDIDATE_SEALED', 'TESTING',
                                            'ACTIVATING', 'AWAITING_OLD_REMOVAL', 'CONFIRMING', 'CONFIRMED', 'FAILED',
                                            'ROLLED_BACK')),
    -- The ACTIVE credential when the rotation was requested.
    old_credential_id       uuid        NOT NULL,
    -- The sealed new key (state CANDIDATE until activation).
    candidate_credential_id uuid,
    -- The digest of the preview the requester saw: who shares the
    -- credential (HR-252).
    preview_digest          text        NOT NULL CHECK (preview_digest ~ '^sha256:[0-9a-f]{64}$'),
    requested_by            text        NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 100),
    test_verification_id    uuid,
    test_passed_at          timestamptz,
    activated_by            text        CHECK (char_length(activated_by) BETWEEN 1 AND 100),
    activated_at            timestamptz,
    rollback_until          timestamptz,
    confirm_verification_id uuid,
    confirmed_at            timestamptz,
    -- When the rotation first entered AWAITING_OLD_REMOVAL; an ACTIVATING
    -- rotation past its rollback window awaits the removal from
    -- rollback_until (the unconfirmed_rotation finding counts from either).
    awaiting_since          timestamptz,
    end_reason              text        CHECK (char_length(end_reason) BETWEEN 1 AND 500),
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    finished_at             timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, old_credential_id) REFERENCES pc.credentials (org_id, id),
    FOREIGN KEY (org_id, candidate_credential_id) REFERENCES pc.credentials (org_id, id),
    FOREIGN KEY (org_id, test_verification_id) REFERENCES pc.verifications (org_id, id),
    FOREIGN KEY (org_id, confirm_verification_id) REFERENCES pc.verifications (org_id, id),
    CHECK (candidate_credential_id IS DISTINCT FROM old_credential_id),
    CHECK (candidate_credential_id IS NOT NULL OR state IN ('REQUESTED', 'FAILED')),
    CHECK ((state IN ('ACTIVATING', 'AWAITING_OLD_REMOVAL', 'CONFIRMING', 'CONFIRMED', 'ROLLED_BACK')) = (activated_at IS NOT NULL)),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL)),
    CHECK ((activated_at IS NULL) = (rollback_until IS NULL)),
    CHECK (rollback_until IS NULL OR rollback_until <= activated_at + interval '24 hours'),
    -- Activation needs a passed target test (HR-518).
    CHECK (activated_at IS NULL OR test_passed_at IS NOT NULL),
    CHECK ((state = 'CONFIRMED') = (confirmed_at IS NOT NULL)),
    CHECK ((state IN ('AWAITING_OLD_REMOVAL', 'CONFIRMING', 'CONFIRMED')) = (awaiting_since IS NOT NULL)),
    CHECK ((state IN ('CONFIRMED', 'FAILED', 'ROLLED_BACK')) = (finished_at IS NOT NULL)),
    CHECK ((state IN ('FAILED', 'ROLLED_BACK')) = (end_reason IS NOT NULL))
);
CREATE UNIQUE INDEX credential_rotations_open ON pc.credential_rotations (org_id, connection_id)
    WHERE state NOT IN ('CONFIRMED', 'FAILED', 'ROLLED_BACK');
CREATE INDEX credential_rotations_connection ON pc.credential_rotations (org_id, connection_id, created_at DESC);

-- A rotation moves only along its state machine, a finished one never
-- changes, what it rotates is fixed (the candidate once, when it is
-- sealed), and a rollback comes only from ACTIVATING within its window
-- (HR-519).
-- +goose StatementBegin
CREATE FUNCTION pc.credential_rotations_forward() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF OLD.state IN ('CONFIRMED', 'FAILED', 'ROLLED_BACK') THEN
        RAISE EXCEPTION 'credential rotation % is finished', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.connection_id <> OLD.connection_id OR NEW.old_credential_id <> OLD.old_credential_id
        OR NEW.preview_digest <> OLD.preview_digest OR NEW.requested_by <> OLD.requested_by OR NEW.created_at <> OLD.created_at
        OR (OLD.candidate_credential_id IS NOT NULL AND NEW.candidate_credential_id IS DISTINCT FROM OLD.candidate_credential_id)
        OR (OLD.activated_at IS NOT NULL AND (NEW.activated_at IS DISTINCT FROM OLD.activated_at
                                              OR NEW.rollback_until IS DISTINCT FROM OLD.rollback_until))
        OR (OLD.test_passed_at IS NOT NULL AND NEW.test_passed_at IS DISTINCT FROM OLD.test_passed_at)
        OR (OLD.awaiting_since IS NOT NULL AND NEW.awaiting_since IS DISTINCT FROM OLD.awaiting_since) THEN
        RAISE EXCEPTION 'credential rotation % keeps what it rotates', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state <> OLD.state AND NOT (OLD.state, NEW.state) IN (
        ('REQUESTED', 'CANDIDATE_SEALED'), ('REQUESTED', 'FAILED'),
        ('CANDIDATE_SEALED', 'TESTING'), ('CANDIDATE_SEALED', 'FAILED'),
        ('TESTING', 'ACTIVATING'), ('TESTING', 'FAILED'),
        ('ACTIVATING', 'AWAITING_OLD_REMOVAL'), ('ACTIVATING', 'ROLLED_BACK'),
        ('AWAITING_OLD_REMOVAL', 'CONFIRMING'),
        ('CONFIRMING', 'CONFIRMED'), ('CONFIRMING', 'AWAITING_OLD_REMOVAL')) THEN
        RAISE EXCEPTION 'credential rotation % cannot move from % to %', OLD.id, OLD.state, NEW.state
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'ROLLED_BACK' AND now() > OLD.rollback_until THEN
        RAISE EXCEPTION 'credential rotation % is past its rollback window', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER credential_rotations_forward BEFORE UPDATE ON pc.credential_rotations
    FOR EACH ROW EXECUTE FUNCTION pc.credential_rotations_forward();

-- A credential's state moves only forward; a candidate is created as one
-- and becomes ACTIVE, and a SUPERSEDED old key ACTIVE again, only while
-- its rotation is ACTIVATING (HR-517, HR-519).
-- +goose StatementBegin
CREATE FUNCTION pc.credentials_state_forward() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.state = OLD.state THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'REVOKED' THEN
        RAISE EXCEPTION 'credential % is revoked', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF (OLD.state, NEW.state) IN (('ACTIVE', 'SUPERSEDED'), ('ACTIVE', 'REVOKED'), ('SUPERSEDED', 'REVOKED'),
                                  ('CANDIDATE', 'REVOKED')) THEN
        RETURN NEW;
    END IF;
    IF (OLD.state = 'CANDIDATE' AND NEW.state = 'ACTIVE' AND EXISTS (
            SELECT 1 FROM pc.credential_rotations r
            WHERE r.org_id = NEW.org_id AND r.candidate_credential_id = NEW.id AND r.state = 'ACTIVATING'))
        OR (OLD.state = 'SUPERSEDED' AND NEW.state = 'ACTIVE' AND EXISTS (
            SELECT 1 FROM pc.credential_rotations r
            WHERE r.org_id = NEW.org_id AND r.old_credential_id = NEW.id AND r.state = 'ACTIVATING')) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'credential % cannot move from % to %', OLD.id, OLD.state, NEW.state USING ERRCODE = 'check_violation';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER credentials_state_forward BEFORE UPDATE OF state ON pc.credentials
    FOR EACH ROW EXECUTE FUNCTION pc.credentials_state_forward();

ALTER TABLE pc.credential_rotations ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.credential_rotations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.credential_rotations
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.credential_rotations
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.credential_rotations TO pc_app;
GRANT UPDATE (state, candidate_credential_id, test_verification_id, test_passed_at, activated_by, activated_at, rollback_until,
    confirm_verification_id, confirmed_at, awaiting_since, end_reason, updated_at, finished_at) ON pc.credential_rotations TO pc_app;
GRANT SELECT ON pc.credential_rotations TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.credential_rotations TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- A rotation left in AWAITING_OLD_REMOVAL or CONFIRMING for more than 24
-- hours is a posture finding (D259).
ALTER TABLE pc.posture_findings
    DROP CONSTRAINT posture_findings_kind_check,
    ADD CONSTRAINT posture_findings_kind CHECK (kind IN ('excessive_grant', 'uncovered_path', 'unowned_agent', 'unsafe_delegation',
        'stale_credential', 'unused_authority', 'unverified_sensitive_tool', 'credential_overreach', 'unconfirmed_rotation')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.posture_findings VALIDATE CONSTRAINT posture_findings_kind;

-- The purpose checks gain the two rotation purposes, whatever their names
-- (00081, 00084 and 00095 rewrote them); neither belongs to a transaction.
-- Any other shape fails the migration.
-- +goose StatementBegin
DO $$
DECLARE
    c        record;
    purposes text;
    n        integer := 0;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c'
               AND pg_get_constraintdef(oid) LIKE '%purpose%' AND pg_get_constraintdef(oid) NOT LIKE '%window_start%'
               AND pg_get_constraintdef(oid) NOT LIKE '%definition_digest%' LOOP
        SELECT string_agg(quote_literal(m.v[1]), ', ' ORDER BY m.i) INTO purposes
          FROM regexp_matches(c.def, '''([a-z_]+)''', 'g') WITH ORDINALITY AS m (v, i);
        IF purposes IS NULL OR purposes LIKE '%credential_rotation%' THEN
            RAISE EXCEPTION '00239: unexpected check % on pc.verifications: %', c.conname, c.def;
        END IF;
        -- Prepended: 00084's and 00095's Downs and Ups remove and append their
        -- own purposes last, and must find the list as they left it.
        purposes := '''credential_rotation_test'', ''credential_rotation_confirm'', ' || purposes;
        IF c.def LIKE '%transaction_id IS NULL%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((purpose IN (%s)) = (transaction_id IS NULL)) NOT VALID',
                           c.conname, c.conname, purposes);
        ELSIF c.def LIKE '%follow_up%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (purpose IN (%s)) NOT VALID',
                           c.conname, c.conname, purposes);
        ELSE
            RAISE EXCEPTION '00239: unexpected check % on pc.verifications: %', c.conname, c.def;
        END IF;
        EXECUTE format('ALTER TABLE pc.verifications VALIDATE CONSTRAINT %I', c.conname);
        n := n + 1;
    END LOOP;
    IF n <> 2 THEN
        RAISE EXCEPTION '00239: found % purpose checks on pc.verifications, not 2', n;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- Rows only this migration allows go first: rotations, their tasks and
-- observations, and candidates. Row security is lifted for these deletes
-- only.
DROP TABLE pc.credential_rotations;
DROP FUNCTION pc.credential_rotations_forward();
DROP TRIGGER credentials_state_forward ON pc.credentials;
DROP FUNCTION pc.credentials_state_forward();
ALTER TABLE pc.observations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.credentials NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.observations o USING pc.verifications v
 WHERE o.org_id = v.org_id AND o.verification_id = v.id AND v.purpose IN ('credential_rotation_test', 'credential_rotation_confirm');
DELETE FROM pc.verifications WHERE purpose IN ('credential_rotation_test', 'credential_rotation_confirm');
DELETE FROM pc.credentials WHERE state = 'CANDIDATE';
ALTER TABLE pc.observations FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.credentials FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
DECLARE
    c record;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c'
               AND pg_get_constraintdef(oid) LIKE '%''credential_rotation_test''%' LOOP
        EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (%s)', c.conname, c.conname,
                       replace(regexp_replace(c.def, '^CHECK \((.*)\)$', '\1'),
                               '''credential_rotation_test''::text, ''credential_rotation_confirm''::text, ', ''));
    END LOOP;
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.posture_finding_events NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.posture_findings NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.posture_finding_events e USING pc.posture_findings f
 WHERE e.org_id = f.org_id AND e.finding_id = f.id AND f.kind = 'unconfirmed_rotation';
DELETE FROM pc.posture_findings WHERE kind = 'unconfirmed_rotation';
ALTER TABLE pc.posture_finding_events FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.posture_findings FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.posture_findings
    DROP CONSTRAINT posture_findings_kind,
    ADD CONSTRAINT posture_findings_kind_check CHECK (kind IN ('excessive_grant', 'uncovered_path', 'unowned_agent',
        'unsafe_delegation', 'stale_credential', 'unused_authority', 'unverified_sensitive_tool', 'credential_overreach')) NOT VALID;
ALTER TABLE pc.posture_findings VALIDATE CONSTRAINT posture_findings_kind_check;
DROP INDEX pc.credentials_candidate;
ALTER TABLE pc.credentials
    DROP CONSTRAINT credentials_state_check,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT credentials_state_check CHECK (state IN ('ACTIVE', 'SUPERSEDED', 'REVOKED'));
