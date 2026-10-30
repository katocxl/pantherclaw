-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Hosted gateways (G0 M19 D203, ADR-0041, HR-499..503): an org's request
-- for one PantherClaw-hosted gateway process on a shared host. The
-- provisioner (a worker job) creates the org's gateway and a single-use
-- enrollment token, sealed here until the host agent pulls it once over its
-- own mTLS identity; the host agent runs one container for the org and
-- reports its state and version. One live hosted gateway per org (HR-499);
-- its slug names it as <slug>.gw.<host domain>, and pc.hosting_slugs holds
-- each slug for one hosted gateway across all hosts and orgs, so no org gets
-- a certificate for a name another org's process serves (D222). No index of
-- the tenant table spans orgs (HR-050). Deprovisioning revokes the gateway
-- first, then the host agent stops the process (HR-503).
--
-- The audited lister gains two purposes: hosting_due (orgs whose hosted
-- gateway the provisioner must act on) and hosting_assigned (the
-- (org, hosted gateway) pairs placed on one host, set in app.hosting_host
-- for the lister's transaction only). Every purpose of 00184 is carried
-- forward, and the function stays the one SECURITY DEFINER function
-- (HR-053).
-- +goose Up
CREATE TABLE pc.hosted_gateways (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    slug             text        NOT NULL CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    state            text        NOT NULL DEFAULT 'REQUESTED'
        CHECK (state IN ('REQUESTED', 'PROVISIONED', 'ENROLLED', 'RUNNING', 'DEPROVISIONING', 'DEPROVISIONED', 'FAILED')),
    gateway_id       uuid,
    -- host_id names a row of the operator-level pc.hosting_hosts (00228);
    -- no foreign key, so every key of this tenant table stays scoped to
    -- its org (HR-050).
    host_id          uuid,
    milli_cpus       integer     NOT NULL CHECK (milli_cpus BETWEEN 100 AND 2000),
    memory_mib       integer     NOT NULL CHECK (memory_mib BETWEEN 128 AND 1024),
    pids             integer     NOT NULL CHECK (pids BETWEEN 32 AND 512),
    -- The single-use enrollment token, sealed with the org's DEK
    -- (HR-062), until the host agent pulls it once; then cleared.
    token_sealed     bytea       CHECK (octet_length(token_sealed) <= 1024),
    token_pulled_at  timestamptz,
    -- The token the provisioner minted last, and the certificate it
    -- enrolled: the only identity that gets this row's server certificate
    -- (G0 M19 D219), through its renewals.
    enrollment_id    uuid,
    enrolled_cert_id uuid,
    version          text        CHECK (char_length(version) <= 64),
    target_version   text        CHECK (char_length(target_version) <= 64),
    failure          text        CHECK (char_length(failure) <= 500),
    created_by       text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    deprovisioned_at timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    FOREIGN KEY (org_id, enrolled_cert_id) REFERENCES pc.gateway_certs (org_id, id),
    CHECK ((state IN ('REQUESTED', 'FAILED')) OR (gateway_id IS NOT NULL AND host_id IS NOT NULL)),
    CHECK ((state = 'DEPROVISIONED') = (deprovisioned_at IS NOT NULL))
);
-- One live hosted gateway per org (HR-499).
CREATE UNIQUE INDEX hosted_gateways_one_per_org ON pc.hosted_gateways (org_id)
    WHERE state NOT IN ('DEPROVISIONED', 'FAILED');
CREATE INDEX hosted_gateways_host ON pc.hosted_gateways (host_id, state);
CREATE UNIQUE INDEX hosted_gateways_gateway ON pc.hosted_gateways (org_id, gateway_id) WHERE gateway_id IS NOT NULL;

ALTER TABLE pc.hosted_gateways ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.hosted_gateways FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.hosted_gateways
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.hosted_gateways
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.hosted_gateways TO pc_app;
GRANT UPDATE (state, gateway_id, host_id, token_sealed, token_pulled_at, enrollment_id, enrolled_cert_id, version, target_version,
    failure, updated_at, deprovisioned_at)
    ON pc.hosted_gateways TO pc_app;
GRANT SELECT ON pc.hosted_gateways TO pc_audit_ro;
-- The lister reads only what its two purposes select (HR-053).
GRANT SELECT (org_id, id, slug, state, host_id, token_pulled_at, updated_at) ON pc.hosted_gateways TO pc_lister;
-- The slugs in use (D222): operator-level like pc.hosting_hosts (00228), no
-- org, rows only in purpose hosting. A slug is a public hostname. hosted_id
-- is the record that holds it; no foreign key, its table is a tenant's
-- (HR-050).
CREATE TABLE pc.hosting_slugs (
    slug       text        PRIMARY KEY CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    hosted_id  uuid        NOT NULL,
    claimed_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE pc.hosting_slugs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.hosting_slugs FORCE ROW LEVEL SECURITY;
CREATE POLICY hosting_purpose ON pc.hosting_slugs
    USING ((SELECT current_setting('app.purpose', true)) = 'hosting')
    WITH CHECK ((SELECT current_setting('app.purpose', true)) = 'hosting');
GRANT SELECT, INSERT, DELETE ON pc.hosting_slugs TO pc_app;
GRANT UPDATE (hosted_id) ON pc.hosting_slugs TO pc_app;
GRANT SELECT ON pc.hosting_slugs TO pc_audit_ro;

-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.hosted_gateways TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
DECLARE
    v_after uuid;
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    -- The paging cursor: the last org id of the previous page, or none.
    v_after := NULLIF(current_setting('app.lister_after', true), '')::uuid;
    IF v_after IS NOT NULL AND p_purpose IN ('account_memberships', 'account_users', 'billing_link_lookup', 'hosting_assigned') THEN
        RAISE EXCEPTION 'cross_org_list: purpose % does not page', left(p_purpose, 64);
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller, subject)
    VALUES (left(p_purpose, 64), p_max_rows, session_user,
            CASE WHEN p_purpose IN ('account_memberships','account_users') THEN NULLIF(current_setting('app.account_id', true), '')
                 WHEN p_purpose = 'billing_link_lookup' THEN left(current_setting('app.billing_provider', true) || ':'
                     || current_setting('app.billing_kind', true) || ':' || current_setting('app.billing_ref', true), 600)
                 WHEN p_purpose = 'hosting_assigned' THEN left('host:' || coalesce(current_setting('app.hosting_host', true), ''), 200)
                 WHEN v_after IS NOT NULL THEN 'after:' || v_after::text END);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE'
                AND (v_after IS NULL OR o.id > v_after) ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_all' THEN
            -- Every org, whatever its state (G0 M13 D6).
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o
                WHERE (v_after IS NULL OR o.id > v_after) ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_lapsed' THEN
            -- Active orgs whose plan lapsed (G0 M13 D34, HR-393): the
            -- daily job reminds their admins and deletes them on day 90.
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                JOIN pc.org_entitlements e ON e.org_id = o.id
                WHERE o.state = 'ACTIVE' AND e.lapsed_at IS NOT NULL
                  AND (v_after IS NULL OR o.id > v_after)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                  AND (v_after IS NULL OR e.org_id > v_after)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE ((p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds'))
                  AND (v_after IS NULL OR p.org_id > v_after)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE ((v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now()))
                  AND (v_after IS NULL OR v.org_id > v_after)
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
                  AND (v_after IS NULL OR h.org_id > v_after)
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
                  AND (v_after IS NULL OR h.org_id > v_after)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                  AND (v_after IS NULL OR r.org_id > v_after)
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
                  AND (v_after IS NULL OR o.id > v_after)
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
                  AND (v_after IS NULL OR o.id > v_after)
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
                  AND (v_after IS NULL OR o.id > v_after)
                  AND EXISTS (SELECT 1 FROM pc.policy_rollouts r
                              WHERE r.org_id = o.id
                                AND (r.stage IN ('SHADOW', 'PILOT')
                                     OR (r.stage = 'COMPLETE' AND r.completed_at > now() - interval '7 days')))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'account_users' THEN
            RETURN QUERY SELECT u.org_id,u.id FROM pc.accounts a
            JOIN pc.users u ON u.account_id=a.id OR (u.account_id IS NULL AND u.issuer=a.issuer AND u.subject=a.subject)
            WHERE a.id=NULLIF(current_setting('app.account_id',true),'')::uuid
            ORDER BY 1 LIMIT p_max_rows;
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
        WHEN 'billing_link_lookup' THEN
            -- The org of one billing ref (G0 UI D37): the (org, link) pair
            -- of the link with the provider, kind and ref the caller set in
            -- app.billing_provider, app.billing_kind and app.billing_ref for
            -- this transaction. Without them the purpose matches nothing.
            RETURN QUERY
                SELECT l.org_id, l.id
                FROM pc.billing_links l
                WHERE l.provider = (SELECT NULLIF(current_setting('app.billing_provider', true), ''))
                  AND l.kind = (SELECT NULLIF(current_setting('app.billing_kind', true), ''))
                  AND l.ref = (SELECT NULLIF(current_setting('app.billing_ref', true), ''))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'hosting_due' THEN
            -- Active orgs with a hosted gateway the provisioner must act
            -- on (G0 M19 D203): requested and not yet provisioned, or a
            -- token not pulled within 10 minutes (it expires after 15).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND (v_after IS NULL OR o.id > v_after)
                  AND EXISTS (SELECT 1 FROM pc.hosted_gateways h
                              WHERE h.org_id = o.id
                                AND (h.state = 'REQUESTED'
                                     OR (h.state = 'PROVISIONED' AND h.token_pulled_at IS NULL
                                         AND h.updated_at < now() - interval '10 minutes')))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'hosting_assigned' THEN
            -- The (org, hosted gateway) pairs placed on the one host the
            -- caller set in app.hosting_host for this transaction, in any
            -- state its host agent acts on. Without the host the purpose
            -- matches nothing.
            RETURN QUERY
                SELECT h.org_id, h.id
                FROM pc.hosted_gateways h
                WHERE h.host_id = (SELECT NULLIF(current_setting('app.hosting_host', true), '')::uuid)
                  AND h.state IN ('PROVISIONED', 'ENROLLED', 'RUNNING', 'DEPROVISIONING')
                ORDER BY 1, 2
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
DECLARE
    v_after uuid;
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    -- The paging cursor: the last org id of the previous page, or none.
    v_after := NULLIF(current_setting('app.lister_after', true), '')::uuid;
    IF v_after IS NOT NULL AND p_purpose IN ('account_memberships', 'account_users', 'billing_link_lookup') THEN
        RAISE EXCEPTION 'cross_org_list: purpose % does not page', left(p_purpose, 64);
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller, subject)
    VALUES (left(p_purpose, 64), p_max_rows, session_user,
            CASE WHEN p_purpose IN ('account_memberships','account_users') THEN NULLIF(current_setting('app.account_id', true), '')
                 WHEN p_purpose = 'billing_link_lookup' THEN left(current_setting('app.billing_provider', true) || ':'
                     || current_setting('app.billing_kind', true) || ':' || current_setting('app.billing_ref', true), 600)
                 WHEN v_after IS NOT NULL THEN 'after:' || v_after::text END);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE'
                AND (v_after IS NULL OR o.id > v_after) ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_all' THEN
            -- Every org, whatever its state (G0 M13 D6).
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o
                WHERE (v_after IS NULL OR o.id > v_after) ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_lapsed' THEN
            -- Active orgs whose plan lapsed (G0 M13 D34, HR-393): the
            -- daily job reminds their admins and deletes them on day 90.
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                JOIN pc.org_entitlements e ON e.org_id = o.id
                WHERE o.state = 'ACTIVE' AND e.lapsed_at IS NOT NULL
                  AND (v_after IS NULL OR o.id > v_after)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                  AND (v_after IS NULL OR e.org_id > v_after)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE ((p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds'))
                  AND (v_after IS NULL OR p.org_id > v_after)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE ((v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now()))
                  AND (v_after IS NULL OR v.org_id > v_after)
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
                  AND (v_after IS NULL OR h.org_id > v_after)
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
                  AND (v_after IS NULL OR h.org_id > v_after)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                  AND (v_after IS NULL OR r.org_id > v_after)
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
                  AND (v_after IS NULL OR o.id > v_after)
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
                  AND (v_after IS NULL OR o.id > v_after)
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
                  AND (v_after IS NULL OR o.id > v_after)
                  AND EXISTS (SELECT 1 FROM pc.policy_rollouts r
                              WHERE r.org_id = o.id
                                AND (r.stage IN ('SHADOW', 'PILOT')
                                     OR (r.stage = 'COMPLETE' AND r.completed_at > now() - interval '7 days')))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'account_users' THEN
            RETURN QUERY SELECT u.org_id,u.id FROM pc.accounts a
            JOIN pc.users u ON u.account_id=a.id OR (u.account_id IS NULL AND u.issuer=a.issuer AND u.subject=a.subject)
            WHERE a.id=NULLIF(current_setting('app.account_id',true),'')::uuid
            ORDER BY 1 LIMIT p_max_rows;
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
        WHEN 'billing_link_lookup' THEN
            -- The org of one billing ref (G0 UI D37): the (org, link) pair
            -- of the link with the provider, kind and ref the caller set in
            -- app.billing_provider, app.billing_kind and app.billing_ref for
            -- this transaction. Without them the purpose matches nothing.
            RETURN QUERY
                SELECT l.org_id, l.id
                FROM pc.billing_links l
                WHERE l.provider = (SELECT NULLIF(current_setting('app.billing_provider', true), ''))
                  AND l.kind = (SELECT NULLIF(current_setting('app.billing_kind', true), ''))
                  AND l.ref = (SELECT NULLIF(current_setting('app.billing_ref', true), ''))
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd

DROP TABLE pc.hosting_slugs;
DROP TABLE pc.hosted_gateways;
