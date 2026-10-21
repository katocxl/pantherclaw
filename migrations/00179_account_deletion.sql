-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Hosted account deletion (G0 M13 D34; HR-394). A deleted account keeps
-- its id and its (issuer, subject), so evidence that names it by opaque id
-- stays consistent; its email and name are removed and deleted_at is set,
-- once. Its sessions end with the reason ACCOUNT_DELETED and the deletion
-- is an account event. Its users in each org are disabled and
-- pseudonymised by the server through the existing column grants.
--
-- The accounts tables are small (one row per person, their sessions and
-- events), so their constraints are checked at once.

-- +goose Up
ALTER TABLE pc.accounts
    ADD COLUMN deleted_at timestamptz,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT accounts_deleted_scrubbed CHECK (deleted_at IS NULL OR (email = '' AND display_name = ''
                                                                            AND NOT email_verified));

-- +goose StatementBegin
CREATE FUNCTION pc.account_deleted_guard() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pc, pg_temp
AS $$
BEGIN
    IF OLD.deleted_at IS NOT NULL AND (NEW.deleted_at IS DISTINCT FROM OLD.deleted_at OR NEW.email <> ''
                                       OR NEW.display_name <> '' OR NEW.email_verified) THEN
        RAISE EXCEPTION 'a deleted account stays deleted' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER accounts_deleted_guard BEFORE UPDATE ON pc.accounts
    FOR EACH ROW EXECUTE FUNCTION pc.account_deleted_guard();
GRANT UPDATE (deleted_at) ON pc.accounts TO pc_app;

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
REVOKE UPDATE (deleted_at) ON pc.accounts FROM pc_app;
DROP TRIGGER accounts_deleted_guard ON pc.accounts;
DROP FUNCTION pc.account_deleted_guard();
ALTER TABLE pc.accounts
    DROP CONSTRAINT accounts_deleted_scrubbed,
    DROP COLUMN deleted_at;
