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
-- Only the billing state changes; a comp override stays (D87).
SET plan_id = EXCLUDED.plan_id, edition = EXCLUDED.edition, limits = EXCLUDED.limits, features = EXCLUDED.features,
    status = EXCLUDED.status, source = 'BILLING', period_end = EXCLUDED.period_end,
    version = pc.org_entitlements.version + 1, last_event_at = EXCLUDED.last_event_at, updated_at = now()
RETURNING version;

-- name: PutCompPlan :one
-- Sets the comp override; the billing state stays (D87). A new org row
-- has no billing state yet.
INSERT INTO pc.org_entitlements (org_id, edition, status, source, comp_plan_id, comp_edition, comp_until, comp_reason,
                                 comp_by, comp_at)
VALUES (sqlc.arg(org_id), 'community', 'NONE', 'NONE', sqlc.arg(comp_plan_id), sqlc.arg(comp_edition), sqlc.arg(comp_until),
        sqlc.arg(comp_reason), sqlc.arg(comp_by), now())
ON CONFLICT (org_id) DO UPDATE
SET comp_plan_id = EXCLUDED.comp_plan_id, comp_edition = EXCLUDED.comp_edition, comp_until = EXCLUDED.comp_until,
    comp_reason = EXCLUDED.comp_reason, comp_by = EXCLUDED.comp_by, comp_at = now(),
    version = pc.org_entitlements.version + 1, updated_at = now()
RETURNING version;

-- name: RevokeCompPlan :one
-- Ends a comp override in force now; the effective plan falls back to the
-- billing state at once (D87).
UPDATE pc.org_entitlements
SET comp_until = now(), comp_reason = sqlc.arg(comp_reason), version = version + 1, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND comp_until > now() AND comp_at < now()
RETURNING version;

-- name: EntitlementUsage :one
SELECT (SELECT count(*) FROM pc.agents a WHERE a.org_id = sqlc.arg(org_id) AND a.state <> 'RETIRED' AND NOT a.range_agent)::int AS agents,
       (SELECT count(*) FROM pc.environments e WHERE e.org_id = sqlc.arg(org_id) AND e.state = 'ACTIVE')::int AS environments,
       (SELECT count(*) FROM pc.users u WHERE u.org_id = sqlc.arg(org_id) AND u.state = 'ACTIVE')::int AS members;

-- name: CountActiveEnvironments :one
SELECT count(*)::int FROM pc.environments WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE';
