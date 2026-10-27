-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Customer-approved support access, grants and support sessions (G0 M13
-- D32, D38; ADR-0034; HR-385..388). Approving a request creates its one
-- grant, which starts at the approval and ends after the request's
-- duration; any org admin can revoke it earlier. A support session is a
-- browser session of the staff member inside the customer org, bound to a
-- grant: it can only be opened while the grant is in force, never outlives
-- it, and every authentication checks the grant again (HR-385). There is no
-- standing access: nothing but a live grant opens a session.

-- +goose Up

CREATE TABLE pc.support_access_grants (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    request_id          uuid        NOT NULL,
    account_id          uuid        NOT NULL,
    scope               text        NOT NULL CHECK (scope IN ('READ_ONLY', 'READ_ONLY_PLUS_EVIDENCE')),
    approved_by         uuid        NOT NULL,
    approved_credential uuid        NOT NULL,
    starts_at           timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    revoked_at          timestamptz,
    revoked_by_type     text        CHECK (revoked_by_type IS NULL OR char_length(revoked_by_type) BETWEEN 1 AND 32),
    revoked_by_id       text        CHECK (revoked_by_id IS NULL OR char_length(revoked_by_id) BETWEEN 1 AND 256),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, request_id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.support_access_requests (org_id, id),
    FOREIGN KEY (org_id, approved_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, approved_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK (expires_at > starts_at AND expires_at <= starts_at + interval '72 hours'),
    CHECK ((revoked_at IS NULL) = (revoked_by_type IS NULL) AND (revoked_by_type IS NULL) = (revoked_by_id IS NULL))
);
CREATE INDEX support_access_grants_created ON pc.support_access_grants (org_id, starts_at DESC, id DESC);
CREATE INDEX support_access_grants_account ON pc.support_access_grants (org_id, account_id) WHERE revoked_at IS NULL;

-- A grant matches its approved request exactly (same account, scope and
-- approver, at most its duration), and afterwards only its revocation is
-- ever written, once.
-- +goose StatementBegin
CREATE FUNCTION pc.support_access_grant_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    r pc.support_access_requests;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO r FROM pc.support_access_requests WHERE org_id = NEW.org_id AND id = NEW.request_id;
        IF r.state IS DISTINCT FROM 'APPROVED' OR r.requester_account IS DISTINCT FROM NEW.account_id
            OR r.scope IS DISTINCT FROM NEW.scope OR r.decided_by IS DISTINCT FROM NEW.approved_by
            OR r.decided_credential IS DISTINCT FROM NEW.approved_credential
            OR NEW.expires_at > NEW.starts_at + make_interval(hours => r.duration_hours)
            OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'a support grant must match its approved request' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.revoked_at IS NOT NULL THEN
        RAISE EXCEPTION 'a revoked support grant is final' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.request_id IS DISTINCT FROM OLD.request_id OR NEW.account_id IS DISTINCT FROM OLD.account_id
        OR NEW.scope IS DISTINCT FROM OLD.scope OR NEW.approved_by IS DISTINCT FROM OLD.approved_by
        OR NEW.approved_credential IS DISTINCT FROM OLD.approved_credential
        OR NEW.starts_at IS DISTINCT FROM OLD.starts_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'a support grant is never rewritten' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER support_access_grants_guard BEFORE INSERT OR UPDATE ON pc.support_access_grants
    FOR EACH ROW EXECUTE FUNCTION pc.support_access_grant_guard();

CREATE TABLE pc.support_sessions (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    grant_id         uuid        NOT NULL,
    account_id       uuid        NOT NULL,
    -- The staff org's key the session was opened with (step-up).
    staff_credential uuid        NOT NULL,
    secret_hash      bytea       NOT NULL CHECK (octet_length(secret_hash) = 32),
    state            text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'ENDED')),
    end_reason       text        CHECK (end_reason IS NULL OR end_reason IN ('LOGOUT', 'REVOKED', 'EXPIRED', 'IDLE', 'GRANT_ENDED')),
    user_agent       text        NOT NULL DEFAULT '' CHECK (char_length(user_agent) <= 256),
    client_ip        text        NOT NULL DEFAULT '' CHECK (char_length(client_ip) <= 64),
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    ended_at         timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, secret_hash),
    FOREIGN KEY (org_id, grant_id) REFERENCES pc.support_access_grants (org_id, id),
    CHECK (expires_at > created_at),
    CHECK ((state = 'ENDED') = (ended_at IS NOT NULL) AND (ended_at IS NULL) = (end_reason IS NULL))
);
CREATE INDEX support_sessions_grant ON pc.support_sessions (org_id, grant_id) WHERE state = 'ACTIVE';

-- A session opens only under a grant in force, for the grant's account,
-- and never outlives it; afterwards only its use and its end are written.
-- +goose StatementBegin
CREATE FUNCTION pc.support_session_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
DECLARE
    g pc.support_access_grants;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO g FROM pc.support_access_grants WHERE org_id = NEW.org_id AND id = NEW.grant_id;
        IF g.id IS NULL OR g.revoked_at IS NOT NULL OR now() < g.starts_at OR now() >= g.expires_at
            OR g.account_id IS DISTINCT FROM NEW.account_id OR NEW.expires_at > g.expires_at OR NEW.state <> 'ACTIVE' THEN
            RAISE EXCEPTION 'a support session needs a grant in force' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'ENDED' AND NEW.state <> 'ENDED' THEN
        RAISE EXCEPTION 'an ended support session is final' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.grant_id IS DISTINCT FROM OLD.grant_id OR NEW.account_id IS DISTINCT FROM OLD.account_id
        OR NEW.staff_credential IS DISTINCT FROM OLD.staff_credential OR NEW.secret_hash IS DISTINCT FROM OLD.secret_hash
        OR NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'a support session is never rewritten' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER support_sessions_guard BEFORE INSERT OR UPDATE ON pc.support_sessions
    FOR EACH ROW EXECUTE FUNCTION pc.support_session_guard();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['support_access_grants', 'support_sessions'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.support_access_grants, pc.support_sessions TO pc_app;
GRANT UPDATE (revoked_at, revoked_by_type, revoked_by_id) ON pc.support_access_grants TO pc_app;
GRANT UPDATE (state, end_reason, ended_at, last_seen_at) ON pc.support_sessions TO pc_app;
GRANT SELECT ON pc.support_access_grants TO pc_audit_ro;
GRANT SELECT (org_id, id, grant_id, account_id, staff_credential, state, end_reason, user_agent, client_ip, created_at,
    last_seen_at, expires_at, ended_at) ON pc.support_sessions TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.support_sessions;
DROP FUNCTION pc.support_session_guard();
DROP TABLE pc.support_access_grants;
DROP FUNCTION pc.support_access_grant_guard();
