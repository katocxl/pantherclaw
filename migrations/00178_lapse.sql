-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The lapse lifecycle of a hosted plan (G0 M13 D34, F2; HR-393). A plan
-- that ends (LAPSED, PAUSED, or CANCELED past its period end, with no comp
-- plan in force) keeps enforcement, reads and export for 90 days while
-- changes are blocked; org admins are reminded on days 0, 30, 60 and 83;
-- on day 90 the org is deleted (00177) unless a plan was paid again.
--
-- org_entitlements.lapsed_at is the anchor of those days: set by the plan
-- writer and the comp end when the effective plan enters a lapse, cleared
-- when it recovers, never moved while the lapse lasts. The lister's
-- orgs_lapsed purpose lists the active orgs with an anchor for the daily
-- job.

-- +goose Up
ALTER TABLE pc.org_entitlements ADD COLUMN lapsed_at timestamptz;
GRANT UPDATE (lapsed_at) ON pc.org_entitlements TO pc_app;
-- Small (one row per hosted org): built at once.
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX org_entitlements_lapsed ON pc.org_entitlements (lapsed_at) WHERE lapsed_at IS NOT NULL;
GRANT SELECT (org_id, lapsed_at) ON pc.org_entitlements TO pc_lister;

-- The lister below replaces the whole function, starting from 00169's.
-- +goose StatementBegin
DO $$
DECLARE
    found text[];
BEGIN
    SELECT array_agg(m[1] ORDER BY m[1]) INTO found
    FROM regexp_matches(
        (SELECT prosrc FROM pg_proc WHERE oid = 'pc.cross_org_list(text, integer)'::regprocedure),
        'WHEN ''([a-z_]+)'' THEN', 'g') AS m;
    IF found IS DISTINCT FROM ARRAY['account_memberships', 'billing_link_lookup', 'budget_settle', 'checkpoints_due',
                                    'coverage_reassess', 'integrity_due', 'ledger_unchained', 'orgs', 'orgs_all',
                                    'permits_sweep', 'policy_rollouts_due', 'retention_due', 'verifications_due'] THEN
        RAISE EXCEPTION '00178_lapse: pc.cross_org_list has purposes %; carry the new ones into this migration', found;
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
            CASE WHEN p_purpose = 'account_memberships' THEN NULLIF(current_setting('app.account_id', true), '')
                 WHEN p_purpose = 'billing_link_lookup' THEN left(current_setting('app.billing_provider', true) || ':'
                     || current_setting('app.billing_kind', true) || ':' || current_setting('app.billing_ref', true), 600) END);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_all' THEN
            -- Every org, whatever its state (G0 M13 D6).
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_lapsed' THEN
            -- Active orgs whose plan lapsed (G0 M13 D34, HR-393): the
            -- daily job reminds their admins and deletes them on day 90.
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                JOIN pc.org_entitlements e ON e.org_id = o.id
                WHERE o.state = 'ACTIVE' AND e.lapsed_at IS NOT NULL
                ORDER BY 1
                LIMIT p_max_rows;
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
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller, subject)
    VALUES (left(p_purpose, 64), p_max_rows, session_user,
            CASE WHEN p_purpose = 'account_memberships' THEN NULLIF(current_setting('app.account_id', true), '')
                 WHEN p_purpose = 'billing_link_lookup' THEN left(current_setting('app.billing_provider', true) || ':'
                     || current_setting('app.billing_kind', true) || ':' || current_setting('app.billing_ref', true), 600) END);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'orgs_all' THEN
            -- Every org, whatever its state (G0 M13 D6).
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o ORDER BY o.id LIMIT p_max_rows;
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
REVOKE SELECT (org_id, lapsed_at) ON pc.org_entitlements FROM pc_lister;
DROP INDEX pc.org_entitlements_lapsed;
REVOKE UPDATE (lapsed_at) ON pc.org_entitlements FROM pc_app;
ALTER TABLE pc.org_entitlements DROP COLUMN lapsed_at;
