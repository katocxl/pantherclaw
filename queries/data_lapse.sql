-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- name: RefreshPlanLapse :one
-- The database clock decides when a comp/cancelled plan ends. A recovery
-- clears the old lapse; an uninterrupted lapse keeps its original date.
UPDATE pc.org_entitlements
SET lapsed_at = CASE
    WHEN comp_until > now() AND comp_at IS NOT NULL THEN NULL
    WHEN source = 'BILLING' AND status IN ('LAPSED', 'PAUSED') THEN coalesce(lapsed_at, now())
    WHEN source = 'BILLING' AND status = 'CANCELED' AND (period_end IS NULL OR period_end <= now())
        THEN coalesce(lapsed_at, period_end, now())
    WHEN source <> 'BILLING' AND comp_until IS NOT NULL AND comp_until <= now()
        THEN coalesce(lapsed_at, comp_until)
    ELSE NULL END
WHERE org_id = sqlc.arg(org_id)
RETURNING lapsed_at;

-- name: DataRequestAdmins :many
SELECT DISTINCT u.id FROM pc.users u
JOIN pc.role_bindings r ON r.org_id = u.org_id AND r.user_id = u.id
WHERE u.org_id = sqlc.arg(org_id) AND u.state = 'ACTIVE'
  AND r.role = 'org_admin' AND r.scope_type = 'ORG'
ORDER BY u.id LIMIT 10001;

-- name: DataRequestAdminsPage :many
SELECT DISTINCT u.id FROM pc.users u
JOIN pc.role_bindings r ON r.org_id = u.org_id AND r.user_id = u.id
WHERE u.org_id = sqlc.arg(org_id) AND u.state = 'ACTIVE'
  AND u.id > sqlc.arg(after_id) AND r.role = 'org_admin' AND r.scope_type = 'ORG'
ORDER BY u.id LIMIT 1000;

-- name: TenantDatabaseTime :one
SELECT now()::timestamptz AS at;
