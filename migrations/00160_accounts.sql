-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Hosted accounts (G0 UI D8, D41; PN-026; HR-348..353). An account is one
-- OIDC identity (issuer, subject) across organizations; it is never linked
-- to another issuer's identity by email (HR-348). The account tables hold
-- no tenant data, so they have no org_id, but they hold every hosted
-- person's identity and sessions, so their rows are visible only in an
-- account context (app.account_id set to the row's account, by the server,
-- for that account's own transaction) or in the restricted global
-- transaction with the audited purpose "accounts" (app.purpose). A tenant
-- transaction sees none of them (D41). An org user row links to its
-- account by account_id, and a trigger keeps the link to the same
-- (issuer, subject). An account's memberships are found only through the
-- audited cross-org lister (purpose account_memberships, HR-349), whose
-- audit row now records the account listed.
--
-- Sign-in without an org starts an account login request; its callback
-- resolves the account and then opens an org session (one membership, or
-- the one picked) or an account session, which may call only the
-- allow-listed procedures (HR-350). The sign-in state, the browser binding,
-- the nonce and session secrets are stored only as SHA-256 hashes; the PKCE
-- verifier is stored as is until the callback consumes it, because it must
-- be sent to the provider's token endpoint.

-- +goose Up
CREATE TABLE pc.accounts (
    id              uuid        PRIMARY KEY,
    issuer          text        NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 512),
    subject         text        NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
    email           text        NOT NULL DEFAULT '' CHECK (char_length(email) <= 320),
    email_verified  boolean     NOT NULL DEFAULT false,
    display_name    text        NOT NULL DEFAULT '' CHECK (char_length(display_name) <= 200),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_sign_in_at timestamptz,
    UNIQUE (issuer, subject),
    CHECK (email <> '' OR NOT email_verified)
);

-- One sign-in without an org in progress: PENDING until the provider's
-- callback consumes it (single use, 10 minutes).
CREATE TABLE pc.account_login_requests (
    id            uuid        PRIMARY KEY,
    state_hash    bytea       UNIQUE CHECK (state_hash IS NULL OR octet_length(state_hash) = 32),
    binding_hash  bytea       CHECK (binding_hash IS NULL OR octet_length(binding_hash) = 32),
    nonce_hash    bytea       CHECK (nonce_hash IS NULL OR octet_length(nonce_hash) = 32),
    pkce_verifier text        CHECK (pkce_verifier IS NULL OR char_length(pkce_verifier) <= 128),
    provider      text        NOT NULL CHECK (provider ~ '^[a-z0-9-]{1,32}$'),
    -- A PantherClaw path from a fixed list (HR-152): never another origin.
    next_path     text        NOT NULL CHECK (char_length(next_path) BETWEEN 2 AND 512 AND next_path ~ '^/[A-Za-z0-9]'),
    max_age       integer     CHECK (max_age IS NULL OR max_age BETWEEN 0 AND 3600),
    requested_ip  text        NOT NULL DEFAULT '' CHECK (char_length(requested_ip) <= 64),
    state         text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'CONSUMED')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    consumed_at   timestamptz,
    CHECK (expires_at <= created_at + interval '10 minutes'),
    CHECK ((state = 'PENDING') = (consumed_at IS NULL)),
    CHECK (state <> 'PENDING' OR (state_hash IS NOT NULL AND binding_hash IS NOT NULL)),
    CHECK (state = 'PENDING' OR (state_hash IS NULL AND binding_hash IS NULL AND nonce_hash IS NULL AND pkce_verifier IS NULL))
);

-- One account browser session (HR-150, HR-350): no org, so no role and no
-- org-scoped record is ever reachable from it. Same lifetimes and rotation
-- grace as an org session.
CREATE TABLE pc.account_sessions (
    id               uuid        PRIMARY KEY,
    account_id       uuid        NOT NULL REFERENCES pc.accounts (id),
    secret_hash      bytea       NOT NULL UNIQUE CHECK (octet_length(secret_hash) = 32),
    prev_secret_hash bytea       CHECK (prev_secret_hash IS NULL OR octet_length(prev_secret_hash) = 32),
    rotated_at       timestamptz,
    generation       integer     NOT NULL DEFAULT 1 CHECK (generation >= 1),
    provider         text        NOT NULL CHECK (provider ~ '^[a-z0-9-]{1,32}$'),
    auth_time        timestamptz,
    user_agent       text        NOT NULL DEFAULT '' CHECK (char_length(user_agent) <= 256),
    client_ip        text        NOT NULL DEFAULT '' CHECK (char_length(client_ip) <= 64),
    state            text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'ENDED')),
    end_reason       text        CHECK (end_reason IS NULL OR end_reason IN
                                     ('LOGOUT', 'REVOKED', 'IDLE', 'EXPIRED', 'REUSE', 'SESSION_LIMIT', 'ORG_SELECTED')),
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    ended_at         timestamptz,
    CHECK ((state = 'ENDED') = (end_reason IS NOT NULL AND ended_at IS NOT NULL)),
    CHECK ((prev_secret_hash IS NULL) = (rotated_at IS NULL)),
    CHECK (expires_at <= created_at + interval '12 hours')
);
CREATE INDEX account_sessions_prev_secret ON pc.account_sessions (prev_secret_hash) WHERE prev_secret_hash IS NOT NULL;
CREATE INDEX account_sessions_account_active ON pc.account_sessions (account_id) WHERE state = 'ACTIVE';

-- What happened to an account (append only): sign-ins, sessions, org
-- creation (which the per-account limits and rate limits count) and
-- invitation acceptance. org_id names the org an event concerns, if any.
CREATE TABLE pc.account_events (
    id         bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id uuid        NOT NULL REFERENCES pc.accounts (id),
    kind       text        NOT NULL CHECK (kind IN ('SIGNED_IN', 'SESSION_STARTED', 'SESSION_ENDED', 'ORG_CREATED',
                                                    'ORG_CREATE_REFUSED', 'INVITATION_ACCEPTED', 'INVITATION_REFUSED')),
    org_id     uuid,
    client_ip  text        NOT NULL DEFAULT '' CHECK (char_length(client_ip) <= 64),
    detail     text        NOT NULL DEFAULT '' CHECK (char_length(detail) <= 256),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX account_events_account_kind ON pc.account_events (account_id, kind, created_at);
CREATE INDEX account_events_ip_kind ON pc.account_events (client_ip, kind, created_at) WHERE client_ip <> '';

GRANT SELECT, INSERT ON pc.accounts, pc.account_login_requests, pc.account_sessions TO pc_app;
GRANT UPDATE (email, email_verified, display_name, last_sign_in_at) ON pc.accounts TO pc_app;
GRANT UPDATE (state_hash, binding_hash, nonce_hash, pkce_verifier, state, consumed_at) ON pc.account_login_requests TO pc_app;
GRANT UPDATE (secret_hash, prev_secret_hash, rotated_at, generation, state, end_reason, last_seen_at, ended_at)
    ON pc.account_sessions TO pc_app;
GRANT DELETE ON pc.account_login_requests, pc.account_sessions TO pc_app;
GRANT SELECT, INSERT ON pc.account_events TO pc_app;
GRANT SELECT (id, issuer, subject, email, email_verified, display_name, created_at, last_sign_in_at) ON pc.accounts TO pc_audit_ro;
GRANT SELECT (id, account_id, provider, auth_time, user_agent, client_ip, state, end_reason, created_at, last_seen_at,
    expires_at, ended_at, generation) ON pc.account_sessions TO pc_audit_ro;
GRANT SELECT ON pc.account_events TO pc_audit_ro;

-- D41: an account's own rows in its account context, every row in the
-- audited global purpose "accounts", nothing anywhere else. Pending
-- sign-ins belong to no account yet: only the global purpose sees them.
ALTER TABLE pc.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.accounts FORCE ROW LEVEL SECURITY;
CREATE POLICY account_isolation ON pc.accounts
    USING (id = (SELECT NULLIF(current_setting('app.account_id', true), '')::uuid)
           OR (SELECT current_setting('app.purpose', true)) = 'accounts')
    WITH CHECK (id = (SELECT NULLIF(current_setting('app.account_id', true), '')::uuid)
                OR (SELECT current_setting('app.purpose', true)) = 'accounts');
ALTER TABLE pc.account_login_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.account_login_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY account_isolation ON pc.account_login_requests
    USING ((SELECT current_setting('app.purpose', true)) = 'accounts')
    WITH CHECK ((SELECT current_setting('app.purpose', true)) = 'accounts');
-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['account_sessions', 'account_events'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY account_isolation ON pc.%I
            USING (account_id = (SELECT NULLIF(current_setting('app.account_id', true), '')::uuid)
                   OR (SELECT current_setting('app.purpose', true)) = 'accounts')
            WITH CHECK (account_id = (SELECT NULLIF(current_setting('app.account_id', true), '')::uuid)
                        OR (SELECT current_setting('app.purpose', true)) = 'accounts')$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- The lister's audit row names what a parameterized purpose listed (the
-- account of account_memberships, L1).
ALTER TABLE pc.cross_org_list_audit ADD COLUMN subject text CHECK (subject IS NULL OR char_length(subject) <= 600);

-- An org user's account: set when the account signs in to the org, joins
-- it or creates it. No foreign key (tenant keys lead with org_id, HR-050);
-- the trigger checks the account exists and has the user's own (issuer,
-- subject), so a link never crosses issuers (HR-348) and never changes.
ALTER TABLE pc.users ADD COLUMN account_id uuid;
-- The new column is NULL in every row, so the partial index is empty and
-- built at once.
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX users_account ON pc.users (account_id) WHERE account_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION pc.user_account_link() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.account_id IS NOT NULL AND NEW.account_id IS DISTINCT FROM OLD.account_id THEN
        RAISE EXCEPTION 'a user''s account link never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.account_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM pc.accounts a WHERE a.id = NEW.account_id AND a.issuer = NEW.issuer AND a.subject = NEW.subject) THEN
        RAISE EXCEPTION 'a user links only to the account of its own issuer and subject' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER users_account_link BEFORE INSERT OR UPDATE OF account_id ON pc.users
    FOR EACH ROW EXECUTE FUNCTION pc.user_account_link();

GRANT UPDATE (account_id) ON pc.users TO pc_app;
GRANT SELECT (org_id, id, issuer, subject, account_id, state) ON pc.users TO pc_lister;
GRANT SELECT (id, issuer, subject) ON pc.accounts TO pc_lister;
-- The lister finds an account's users by (issuer, subject) across orgs. pc.users
-- holds people, a small table, so the build blocks writes only briefly.
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX users_identity ON pc.users (issuer, subject);

-- The lister below replaces the whole function, starting from 00111's.
-- Refuse to run if the current one has purposes it does not carry (a
-- migration merged before this one added them), rather than drop them:
-- add them below and to this list first.
-- +goose StatementBegin
DO $$
DECLARE
    found text[];
BEGIN
    SELECT array_agg(m[1] ORDER BY m[1]) INTO found
    FROM regexp_matches(
        (SELECT prosrc FROM pg_proc WHERE oid = 'pc.cross_org_list(text, integer)'::regprocedure),
        'WHEN ''([a-z_]+)'' THEN', 'g') AS m;
    IF found IS DISTINCT FROM ARRAY['budget_settle', 'checkpoints_due', 'coverage_reassess', 'integrity_due',
                                    'ledger_unchained', 'orgs', 'permits_sweep', 'policy_rollouts_due',
                                    'retention_due', 'verifications_due'] THEN
        RAISE EXCEPTION '00160_accounts: pc.cross_org_list has purposes %; carry the new ones into this migration', found;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller, subject)
    VALUES (left(p_purpose, 64), p_max_rows, session_user,
            CASE WHEN p_purpose = 'account_memberships' THEN NULLIF(current_setting('app.account_id', true), '') END);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'checkpoints_due' THEN
            -- Orgs whose chain grew past their latest checkpoint and whose
            -- checkpointing has not stopped.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE h.seq > coalesce((SELECT max(c.tree_size) FROM pc.checkpoints c WHERE c.org_id = h.org_id), 0)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id AND i.state = 'FAILED')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'integrity_due' THEN
            -- Orgs with a checkpoint whose chain was not re-verified in the
            -- last day.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE EXISTS (SELECT 1 FROM pc.checkpoints c WHERE c.org_id = h.org_id)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id
                                  AND (i.state = 'FAILED' OR i.verified_at > now() - interval '1 day'))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'retention_due' THEN
            -- Active orgs whose retention job has not run successfully in
            -- the last day (HR-198).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND NOT EXISTS (SELECT 1 FROM pc.retention_status s WHERE s.org_id = o.id
                                  AND s.last_run_at > now() - interval '1 day')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'coverage_reassess' THEN
            -- Active orgs with pending coverage invalidations, with
            -- transactions the route inventory has not read (a minute
            -- behind the clock), or with a current ENFORCED snapshot past
            -- its expiry (HR-211).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND (EXISTS (SELECT 1 FROM pc.coverage_invalidations i WHERE i.org_id = o.id AND i.reassessed_at IS NULL)
                       OR EXISTS (SELECT 1 FROM pc.transactions t
                                  WHERE t.org_id = o.id AND t.created_at < now() - interval '1 minute'
                                    AND t.id > coalesce((SELECT w.transactions_after FROM pc.coverage_inventory w
                                                         WHERE w.org_id = o.id), '00000000-0000-0000-0000-000000000000'))
                       OR EXISTS (SELECT 1 FROM pc.coverage_snapshots s
                                  WHERE s.org_id = o.id AND s.state = 'ENFORCED' AND s.expires_at <= now()
                                    AND NOT EXISTS (SELECT 1 FROM pc.coverage_snapshots n
                                                    WHERE n.org_id = s.org_id AND n.agent_id = s.agent_id
                                                      AND n.connection_id = s.connection_id
                                                      AND n.operation = s.operation AND n.id > s.id)))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'policy_rollouts_due' THEN
            -- Active orgs with a policy rollout in SHADOW or PILOT, or one
            -- completed less than 7 days ago (G0 M11.1, D12, D31).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND EXISTS (SELECT 1 FROM pc.policy_rollouts r
                              WHERE r.org_id = o.id
                                AND (r.stage IN ('SHADOW', 'PILOT')
                                     OR (r.stage = 'COMPLETE' AND r.completed_at > now() - interval '7 days')))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'account_memberships' THEN
            -- The active memberships of one hosted account (G0 UI D8,
            -- HR-349): (org, user) pairs of the active users of active orgs
            -- with the (issuer, subject) of the account the caller set in
            -- app.account_id for this transaction — linked already or not,
            -- never matched by email (HR-348). Without the setting the
            -- purpose matches nothing.
            RETURN QUERY
                SELECT u.org_id, u.id
                FROM pc.accounts a
                JOIN pc.users u ON u.issuer = a.issuer AND u.subject = a.subject
                JOIN pc.orgs o ON o.id = u.org_id
                WHERE a.id = (SELECT NULLIF(current_setting('app.account_id', true), '')::uuid)
                  AND (u.account_id IS NULL OR u.account_id = a.id)
                  AND u.state = 'ACTIVE' AND o.state = 'ACTIVE'
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'checkpoints_due' THEN
            -- Orgs whose chain grew past their latest checkpoint and whose
            -- checkpointing has not stopped.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE h.seq > coalesce((SELECT max(c.tree_size) FROM pc.checkpoints c WHERE c.org_id = h.org_id), 0)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id AND i.state = 'FAILED')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'integrity_due' THEN
            -- Orgs with a checkpoint whose chain was not re-verified in the
            -- last day.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE EXISTS (SELECT 1 FROM pc.checkpoints c WHERE c.org_id = h.org_id)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id
                                  AND (i.state = 'FAILED' OR i.verified_at > now() - interval '1 day'))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'retention_due' THEN
            -- Active orgs whose retention job has not run successfully in
            -- the last day (HR-198).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND NOT EXISTS (SELECT 1 FROM pc.retention_status s WHERE s.org_id = o.id
                                  AND s.last_run_at > now() - interval '1 day')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'coverage_reassess' THEN
            -- Active orgs with pending coverage invalidations, with
            -- transactions the route inventory has not read (a minute
            -- behind the clock), or with a current ENFORCED snapshot past
            -- its expiry (HR-211).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND (EXISTS (SELECT 1 FROM pc.coverage_invalidations i WHERE i.org_id = o.id AND i.reassessed_at IS NULL)
                       OR EXISTS (SELECT 1 FROM pc.transactions t
                                  WHERE t.org_id = o.id AND t.created_at < now() - interval '1 minute'
                                    AND t.id > coalesce((SELECT w.transactions_after FROM pc.coverage_inventory w
                                                         WHERE w.org_id = o.id), '00000000-0000-0000-0000-000000000000'))
                       OR EXISTS (SELECT 1 FROM pc.coverage_snapshots s
                                  WHERE s.org_id = o.id AND s.state = 'ENFORCED' AND s.expires_at <= now()
                                    AND NOT EXISTS (SELECT 1 FROM pc.coverage_snapshots n
                                                    WHERE n.org_id = s.org_id AND n.agent_id = s.agent_id
                                                      AND n.connection_id = s.connection_id
                                                      AND n.operation = s.operation AND n.id > s.id)))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'policy_rollouts_due' THEN
            -- Active orgs with a policy rollout in SHADOW or PILOT, or one
            -- completed less than 7 days ago (G0 M11.1, D12, D31).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND EXISTS (SELECT 1 FROM pc.policy_rollouts r
                              WHERE r.org_id = o.id
                                AND (r.stage IN ('SHADOW', 'PILOT')
                                     OR (r.stage = 'COMPLETE' AND r.completed_at > now() - interval '7 days')))
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER users_account_link ON pc.users;
DROP FUNCTION pc.user_account_link();
REVOKE SELECT (org_id, id, issuer, subject, account_id, state) ON pc.users FROM pc_lister;
DROP INDEX pc.users_identity;
DROP INDEX pc.users_account;
ALTER TABLE pc.users DROP COLUMN account_id;
DROP TABLE pc.account_events;
DROP TABLE pc.account_sessions;
DROP TABLE pc.account_login_requests;
DROP TABLE pc.accounts;
ALTER TABLE pc.cross_org_list_audit DROP COLUMN subject;
