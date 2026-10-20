-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Per-org entitlements (G0 UI D9; HR-354..361), in the org's tenant
-- transaction.

-- name: GetOrgEntitlements :one
SELECT * FROM pc.org_entitlements WHERE org_id = sqlc.arg(org_id);

-- name: LockOrgEntitlements :one
SELECT * FROM pc.org_entitlements WHERE org_id = sqlc.arg(org_id) FOR UPDATE;

-- name: InsertEntitlementEvent :execrows
-- Records a billing event once; a replay inserts nothing (HR-355).
INSERT INTO pc.entitlement_events (org_id, event_id, kind, status, event_at)
VALUES (sqlc.arg(org_id), sqlc.arg(event_id), sqlc.arg(kind), sqlc.arg(status), sqlc.arg(event_at))
ON CONFLICT (org_id, event_id) DO NOTHING;

-- name: PutBillingPlan :one
INSERT INTO pc.org_entitlements (org_id, plan_id, edition, limits, features, status, source, period_end, last_event_at)
VALUES (sqlc.arg(org_id), sqlc.arg(plan_id), sqlc.arg(edition), sqlc.arg(limits), sqlc.arg(features), sqlc.arg(status),
        'BILLING', sqlc.narg(period_end), sqlc.arg(event_at))
ON CONFLICT (org_id) DO UPDATE
SET plan_id = EXCLUDED.plan_id, edition = EXCLUDED.edition, limits = EXCLUDED.limits, features = EXCLUDED.features,
    status = EXCLUDED.status, source = 'BILLING', period_end = EXCLUDED.period_end, comp_until = NULL, comp_reason = NULL,
    comp_by = NULL, comp_at = NULL, version = pc.org_entitlements.version + 1, last_event_at = EXCLUDED.last_event_at,
    updated_at = now()
RETURNING version;

-- name: PutCompPlan :one
INSERT INTO pc.org_entitlements (org_id, plan_id, edition, limits, features, status, source, comp_until, comp_reason,
                                 comp_by, comp_at, last_event_at)
VALUES (sqlc.arg(org_id), sqlc.arg(plan_id), sqlc.arg(edition), '{}', '{}', 'COMP', 'COMP', sqlc.arg(comp_until),
        sqlc.arg(comp_reason), sqlc.arg(comp_by), now(), NULL)
ON CONFLICT (org_id) DO UPDATE
SET plan_id = EXCLUDED.plan_id, edition = EXCLUDED.edition, limits = '{}', features = '{}', status = 'COMP',
    source = 'COMP', period_end = NULL, comp_until = EXCLUDED.comp_until, comp_reason = EXCLUDED.comp_reason,
    comp_by = EXCLUDED.comp_by, comp_at = now(), version = pc.org_entitlements.version + 1, updated_at = now()
RETURNING version;

-- name: RevokeCompPlan :one
UPDATE pc.org_entitlements
SET status = 'LAPSED', comp_until = LEAST(comp_until, now()), comp_reason = sqlc.arg(comp_reason),
    version = version + 1, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND source = 'COMP' AND status = 'COMP'
RETURNING version;

-- name: EntitlementUsage :one
SELECT (SELECT count(*) FROM pc.agents a WHERE a.org_id = sqlc.arg(org_id) AND a.state <> 'RETIRED' AND NOT a.range_agent)::int AS agents,
       (SELECT count(*) FROM pc.environments e WHERE e.org_id = sqlc.arg(org_id) AND e.state = 'ACTIVE')::int AS environments,
       (SELECT count(*) FROM pc.users u WHERE u.org_id = sqlc.arg(org_id) AND u.state = 'ACTIVE')::int AS members;

-- name: CountActiveEnvironments :one
SELECT count(*)::int FROM pc.environments WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE';
