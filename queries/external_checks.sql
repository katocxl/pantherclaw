-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- External policy checks (G0 M16 D81; HR-436..440). Every state change is
-- a conditional update; the guard trigger keeps the target fixed and at
-- most three checks ACTIVE.

-- name: InsertExternalCheck :exec
INSERT INTO pc.external_policy_checks (org_id, id, name, endpoint, ca_pem, timeout_ms, operations, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(endpoint), sqlc.narg(ca_pem), sqlc.arg(timeout_ms),
        sqlc.arg(operations), sqlc.arg(created_by));

-- name: GetExternalCheck :one
SELECT id, name, endpoint, ca_pem, timeout_ms, operations, state, created_by, activated_by, activated_at, created_at, updated_at
FROM pc.external_policy_checks
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListExternalChecks :many
SELECT id, name, endpoint, ca_pem, timeout_ms, operations, state, created_by, activated_by, activated_at, created_at, updated_at
FROM pc.external_policy_checks
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(include_disabled)::boolean OR state <> 'DISABLED')
ORDER BY name, id
LIMIT 200;

-- ListActiveExternalChecks are the checks the Authority asks (at most
-- three).
-- name: ListActiveExternalChecks :many
SELECT id, name, endpoint, ca_pem, timeout_ms, operations
FROM pc.external_policy_checks
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE'
ORDER BY name, id;

-- name: ActivateExternalCheck :execrows
-- A person with a fresh step-up activates a PENDING check (HR-438); the
-- database clock sets activated_at.
UPDATE pc.external_policy_checks
SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: DisableExternalCheck :execrows
UPDATE pc.external_policy_checks SET state = 'DISABLED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'ACTIVE');
