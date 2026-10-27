-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Hosted account deletion (G0 M13 D34, D47; HR-394). A deleted account
-- becomes a tombstone: it keeps its id, so evidence that names it by
-- opaque id stays consistent, but its email and name are removed and its
-- (issuer, subject) is replaced by ('deleted', a random value), so the
-- person signing in again gets a brand-new account. deleted_at is set
-- once and the tombstone never changes again. Its sessions end with the
-- reason ACCOUNT_DELETED and the deletion is an account event.
--
-- Its users in each org are disabled and pseudonymised the same way:
-- email and display name become "deleted user <short id>" and (issuer,
-- subject) becomes ('deleted', a random value), so a later invitation of
-- the same person makes a new user. They stay linked to the tombstone.
--
-- The accounts tables are small (one row per person, their sessions and
-- events), so their constraints are checked at once.

-- +goose Up
ALTER TABLE pc.accounts
    ADD COLUMN deleted_at timestamptz,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT accounts_deleted_scrubbed CHECK (deleted_at IS NULL OR (email = '' AND display_name = ''
                                                                            AND NOT email_verified AND issuer = 'deleted'));

-- +goose StatementBegin
CREATE FUNCTION pc.account_deleted_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pc, pg_temp
AS $$
BEGIN
    IF OLD.deleted_at IS NOT NULL AND (to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD)) THEN
        RAISE EXCEPTION 'a deleted account stays deleted' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.issuer, NEW.subject) IS DISTINCT FROM (OLD.issuer, OLD.subject) AND NEW.deleted_at IS NULL THEN
        RAISE EXCEPTION 'an account''s identity changes only when it is deleted' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER accounts_deleted_guard BEFORE UPDATE ON pc.accounts
    FOR EACH ROW EXECUTE FUNCTION pc.account_deleted_guard();
GRANT UPDATE (deleted_at, issuer, subject) ON pc.accounts TO pc_app;

-- +goose StatementBegin
CREATE FUNCTION pc.user_pseudonym_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pc, pg_temp
AS $$
BEGIN
    IF OLD.issuer = 'deleted' AND (NEW.issuer, NEW.subject, NEW.email, NEW.display_name, NEW.state)
                                   IS DISTINCT FROM (OLD.issuer, OLD.subject, OLD.email, OLD.display_name, OLD.state) THEN
        RAISE EXCEPTION 'a deleted user stays deleted' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.issuer, NEW.subject) IS DISTINCT FROM (OLD.issuer, OLD.subject)
       AND (NEW.issuer <> 'deleted' OR NEW.state <> 'DISABLED') THEN
        RAISE EXCEPTION 'a user''s identity changes only when its account is deleted' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER users_pseudonym_guard BEFORE UPDATE OF issuer, subject, email, display_name, state ON pc.users
    FOR EACH ROW EXECUTE FUNCTION pc.user_pseudonym_guard();
GRANT UPDATE (issuer, subject) ON pc.users TO pc_app;

ALTER TABLE pc.account_sessions
    DROP CONSTRAINT account_sessions_end_reason_check,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT account_sessions_end_reason_check CHECK (end_reason IS NULL OR end_reason IN
        ('LOGOUT', 'REVOKED', 'IDLE', 'EXPIRED', 'REUSE', 'SESSION_LIMIT', 'ORG_SELECTED', 'ACCOUNT_DELETED'));
ALTER TABLE pc.account_events
    DROP CONSTRAINT account_events_kind_check,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT account_events_kind_check CHECK (kind IN ('SIGNED_IN', 'SESSION_STARTED', 'SESSION_ENDED',
        'ORG_CREATED', 'ORG_CREATE_REFUSED', 'INVITATION_ACCEPTED', 'INVITATION_REFUSED', 'ACCOUNT_DELETED'));

-- +goose Down
ALTER TABLE pc.account_events
    DROP CONSTRAINT account_events_kind_check,
    ADD CONSTRAINT account_events_kind_check CHECK (kind IN ('SIGNED_IN', 'SESSION_STARTED', 'SESSION_ENDED',
        'ORG_CREATED', 'ORG_CREATE_REFUSED', 'INVITATION_ACCEPTED', 'INVITATION_REFUSED'));
ALTER TABLE pc.account_sessions
    DROP CONSTRAINT account_sessions_end_reason_check,
    ADD CONSTRAINT account_sessions_end_reason_check CHECK (end_reason IS NULL OR end_reason IN
        ('LOGOUT', 'REVOKED', 'IDLE', 'EXPIRED', 'REUSE', 'SESSION_LIMIT', 'ORG_SELECTED'));
REVOKE UPDATE (issuer, subject) ON pc.users FROM pc_app;
DROP TRIGGER users_pseudonym_guard ON pc.users;
DROP FUNCTION pc.user_pseudonym_guard();
REVOKE UPDATE (deleted_at, issuer, subject) ON pc.accounts FROM pc_app;
DROP TRIGGER accounts_deleted_guard ON pc.accounts;
DROP FUNCTION pc.account_deleted_guard();
ALTER TABLE pc.accounts
    DROP CONSTRAINT accounts_deleted_scrubbed,
    DROP COLUMN deleted_at;
