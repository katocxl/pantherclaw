-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Policy bundles per org (M4 part 2): immutable versions, at most one
-- published per org; publication supersedes the previous version in the
-- same transaction, conditionally (HR-004).

-- name: GetPolicyID :one
SELECT id FROM pc.policies WHERE org_id = sqlc.arg(org_id) AND bundle_id = sqlc.arg(bundle_id);

-- name: InsertPolicy :exec
INSERT INTO pc.policies (org_id, id, bundle_id) VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(bundle_id));

-- name: NextPolicyVersion :one
SELECT (coalesce(max(version), 0) + 1)::integer AS next
FROM pc.policy_versions
WHERE org_id = sqlc.arg(org_id) AND policy_id = sqlc.arg(policy_id);

-- name: InsertPolicyVersion :exec
INSERT INTO pc.policy_versions (org_id, id, policy_id, version, bundle, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(policy_id), sqlc.arg(version), sqlc.arg(bundle), sqlc.arg(created_by));

-- name: GetPolicyVersion :one
SELECT v.id, v.version, v.bundle, v.state, p.bundle_id, v.created_by, v.created_at, v.published_at
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id);

-- name: GetPublishedPolicy :one
SELECT v.id, v.version, v.bundle, p.bundle_id, v.created_by, v.created_at, v.published_at
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id) AND v.state = 'PUBLISHED';

-- name: SupersedePublishedPolicy :execrows
UPDATE pc.policy_versions SET state = 'SUPERSEDED'
WHERE org_id = sqlc.arg(org_id) AND state = 'PUBLISHED' AND id <> sqlc.arg(except_id);

-- name: PublishPolicyVersion :execresult
UPDATE pc.policy_versions
SET state = 'PUBLISHED', published_by = sqlc.arg(published_by), published_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'DRAFT';

-- name: ListPolicyVersions :many
SELECT v.id, v.version, v.state, v.created_by, v.created_at, v.published_at, p.bundle_id
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id)
ORDER BY v.created_at DESC
LIMIT sqlc.arg(max_rows);

-- name: LockPublishedPolicyVersion :one
-- The published version, locked until the transaction ends, so a publish
-- that expects it sees any other publish first (C4, expected version).
SELECT id FROM pc.policy_versions
WHERE org_id = sqlc.arg(org_id) AND state = 'PUBLISHED'
FOR UPDATE;
