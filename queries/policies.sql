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
INSERT INTO pc.policy_versions (org_id, id, policy_id, version, bundle, content_digest, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(policy_id), sqlc.arg(version), sqlc.arg(bundle), sqlc.arg(content_digest),
    sqlc.arg(created_by));

-- name: GetPolicyVersion :one
SELECT v.id, v.version, v.bundle, v.state, p.bundle_id, v.created_by, v.created_at, v.published_at, v.content_digest
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id);

-- name: GetPublishedPolicy :one
SELECT v.id, v.version, v.bundle, p.bundle_id, v.created_by, v.created_at, v.published_at, v.content_digest
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id) AND v.state = 'PUBLISHED';

-- name: SupersedePublishedPolicy :execrows
UPDATE pc.policy_versions SET state = 'SUPERSEDED'
WHERE org_id = sqlc.arg(org_id) AND state = 'PUBLISHED' AND id <> sqlc.arg(except_id);

-- PublishPolicyVersion is the publish gate's last step (G0 M11.1 design
-- decision 6, HR-230): only a TESTED version of exactly this content, with
-- a passing test run of that content, becomes the published one.
-- name: PublishPolicyVersion :execresult
UPDATE pc.policy_versions v
SET state = 'PUBLISHED', published_by = sqlc.arg(published_by), published_at = now()
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id) AND v.state = 'TESTED'
  AND v.content_digest = sqlc.arg(content_digest)
  AND EXISTS (SELECT 1 FROM pc.policy_test_runs t
              WHERE t.org_id = v.org_id AND t.id = sqlc.arg(test_run_id) AND t.version_id = v.id AND t.passed
                AND t.content_digest = v.content_digest);

-- AdvancePolicyVersion moves a version one step of DRAFT -> VALIDATED ->
-- TESTED, only from the expected state and for its recorded content
-- (HR-004).
-- name: AdvancePolicyVersion :execrows
UPDATE pc.policy_versions
SET state = sqlc.arg(to_state)::text
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state)::text
  AND content_digest = sqlc.arg(content_digest)
  AND (sqlc.arg(from_state)::text, sqlc.arg(to_state)::text) IN (('DRAFT', 'VALIDATED'), ('VALIDATED', 'TESTED'));

-- name: InsertPolicyValidation :exec
INSERT INTO pc.policy_validations (org_id, id, version_id, content_digest, definitions_digest, catalog_digest, passed,
    findings, run_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(version_id), sqlc.arg(content_digest), sqlc.arg(definitions_digest),
    sqlc.arg(catalog_digest), sqlc.arg(passed), sqlc.arg(findings), sqlc.arg(run_by));

-- name: InsertPolicyTestRun :exec
INSERT INTO pc.policy_test_runs (org_id, id, version_id, content_digest, definitions_digest, catalog_digest, passed,
    cases, mutants, survivors, results, run_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(version_id), sqlc.arg(content_digest), sqlc.arg(definitions_digest),
    sqlc.arg(catalog_digest), sqlc.arg(passed), sqlc.arg(cases), sqlc.arg(mutants), sqlc.arg(survivors),
    sqlc.arg(results), sqlc.arg(run_by));

-- LatestPassedTestRun is the newest passing test run of a version's
-- recorded content.
-- name: LatestPassedTestRun :one
SELECT t.id, t.definitions_digest, t.catalog_digest, t.created_at
FROM pc.policy_test_runs t
JOIN pc.policy_versions v ON v.org_id = t.org_id AND v.id = t.version_id
WHERE t.org_id = sqlc.arg(org_id) AND t.version_id = sqlc.arg(version_id) AND t.passed
  AND t.content_digest = v.content_digest
ORDER BY t.created_at DESC, t.id DESC
LIMIT 1;

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
