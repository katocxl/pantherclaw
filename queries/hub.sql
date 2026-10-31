-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- PantherClaw Hub (G0 M23 D102).

-- name: GetHubState :one
SELECT * FROM pc.hub_state WHERE org_id = sqlc.arg(org_id);

-- name: LockHubState :one
SELECT * FROM pc.hub_state WHERE org_id = sqlc.arg(org_id) FOR UPDATE;

-- name: AdvanceHubState :execrows
INSERT INTO pc.hub_state (org_id, index_version, index_digest)
VALUES (sqlc.arg(org_id), sqlc.arg(index_version), sqlc.arg(index_digest))
ON CONFLICT (org_id) DO UPDATE
SET index_version = EXCLUDED.index_version, index_digest = EXCLUDED.index_digest, updated_at = now()
WHERE pc.hub_state.index_version < EXCLUDED.index_version
   OR (pc.hub_state.index_version = EXCLUDED.index_version AND pc.hub_state.index_digest = EXCLUDED.index_digest);

-- name: LockHubInstall :one
SELECT *, now() - installed_at > interval '5 minutes' AS stale
FROM pc.hub_installs
WHERE org_id = sqlc.arg(org_id) AND name = sqlc.arg(name) AND version = sqlc.arg(version)
FOR UPDATE;

-- name: InsertHubInstall :one
INSERT INTO pc.hub_installs (org_id, id, name, version, kind, item_sha256, index_version, installed_by, claim)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(version), sqlc.arg(kind), sqlc.arg(item_sha256),
        sqlc.arg(index_version), sqlc.arg(installed_by), sqlc.arg(claim))
RETURNING *;

-- name: ReclaimHubInstall :one
UPDATE pc.hub_installs
SET status = 'PENDING', index_version = sqlc.arg(index_version), installed_by = sqlc.arg(installed_by), installed_at = now(),
    claim = sqlc.arg(claim)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: FinishHubInstall :one
UPDATE pc.hub_installs
SET status = sqlc.arg(status), result_kind = sqlc.arg(result_kind), result_ref = sqlc.arg(result_ref), installed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = 'PENDING' AND claim = sqlc.arg(claim)
RETURNING *;

-- A crashed install's draft, found by what the item would have made (D130).

-- name: FindHubCustomRule :one
SELECT id FROM pc.custom_detection_rules
WHERE org_id = sqlc.arg(org_id) AND content_digest = sqlc.arg(content_digest)
ORDER BY version DESC
LIMIT 1;

-- name: FindHubAutomation :one
SELECT a.id FROM pc.automations a
JOIN pc.automation_versions v ON v.org_id = a.org_id AND v.automation_id = a.id
WHERE a.org_id = sqlc.arg(org_id) AND a.name = sqlc.arg(name) AND v.digest = sqlc.arg(digest)
  AND a.state = 'DRAFT' AND v.state = 'DRAFT'
LIMIT 1;

-- name: ListHubPolicyDrafts :many
SELECT id, bundle FROM pc.policy_versions
WHERE org_id = sqlc.arg(org_id) AND state = 'DRAFT'
ORDER BY version DESC
LIMIT 50;

-- name: ListHubInstalls :many
SELECT * FROM pc.hub_installs
WHERE org_id = sqlc.arg(org_id) AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: EnvironmentIDsBySlug :many
SELECT id FROM pc.environments
WHERE org_id = sqlc.arg(org_id) AND slug = sqlc.arg(slug) AND state = 'ACTIVE'
ORDER BY id
LIMIT 2;
