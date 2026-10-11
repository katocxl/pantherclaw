-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- GitHub identities (G0 M8, HR-207): a person of the org linked to a
-- GitHub user id, which independence compares.

-- name: InsertGitHubIdentity :one
INSERT INTO pc.github_identities (org_id, id, user_id, github_login, github_user_id, linked_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(github_login), sqlc.arg(github_user_id), sqlc.arg(linked_by))
RETURNING *;

-- name: DeleteGitHubIdentity :one
DELETE FROM pc.github_identities WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;

-- name: ListGitHubIdentities :many
SELECT * FROM pc.github_identities
WHERE org_id = sqlc.arg(org_id) AND (sqlc.narg(user_id)::uuid IS NULL OR user_id = sqlc.narg(user_id)::uuid)
  AND id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- Organisation scans (PN-001.2, HR-209): a github_scan_runs row and the
-- org_scan lease its gateway claims.

-- ScanConnection is what a scan needs to know of a connection: whether it
-- is active, its package, and the kind of its active credential.
-- name: ScanConnection :one
SELECT c.state, c.kind, c.package,
       coalesce((SELECT cr.kind FROM pc.credentials cr
                 WHERE cr.org_id = c.org_id AND cr.connection_id = c.id AND cr.state = 'ACTIVE'), '')::text AS credential_kind
FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id) AND c.id = sqlc.arg(id);

-- name: OpenOrgScan :one
SELECT EXISTS (SELECT 1 FROM pc.verifications
               WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND purpose = 'org_scan'
                 AND state IN ('PENDING', 'LEASED'))::boolean;

-- name: ScheduleOrgScan :exec
INSERT INTO pc.verifications (org_id, id, purpose, connection_id, operation, request, next_at, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'org_scan', sqlc.arg(connection_id), 'github.org_scan', sqlc.arg(request), now(),
        now() + interval '30 minutes');

-- name: InsertGitHubScanRun :exec
INSERT INTO pc.github_scan_runs (org_id, id, connection_id, verification_id, started_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(verification_id), sqlc.arg(started_by));

-- GetGitHubScanRun is a scan with its lease's state: a PENDING run whose
-- lease is held is RUNNING, and one whose lease ended unreported FAILED.
-- name: GetGitHubScanRun :one
SELECT r.id, r.connection_id, r.counts, r.scanned, r.not_scanned, r.started_by, r.created_at, r.finished_at,
       (CASE WHEN r.state <> 'PENDING' THEN r.state
             WHEN v.state = 'LEASED' THEN 'RUNNING'
             WHEN v.state IN ('EXPIRED', 'CANCELLED', 'DONE') THEN 'FAILED'
             ELSE 'PENDING' END)::text AS state
FROM pc.github_scan_runs r
LEFT JOIN pc.verifications v ON v.org_id = r.org_id AND v.id = r.verification_id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- LeasedOrgScan is an org scan task under a live lease of this gateway,
-- with its run.
-- name: LeasedOrgScan :one
SELECT v.id, v.connection_id, r.id AS run_id
FROM pc.verifications v
JOIN pc.github_scan_runs r ON r.org_id = v.org_id AND r.verification_id = v.id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id) AND v.purpose = 'org_scan' AND v.state = 'LEASED'
  AND v.leased_by = sqlc.arg(gateway_id) AND v.lease_hash = sqlc.arg(lease_hash) AND v.lease_expires_at >= now()
FOR UPDATE OF v;

-- name: FinishGitHubScanRun :exec
UPDATE pc.github_scan_runs
SET state = sqlc.arg(state), counts = sqlc.arg(counts), scanned = sqlc.arg(scanned)::text[], not_scanned = sqlc.arg(not_scanned),
    finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'RUNNING');

-- GatewayScanRun is a scan whose org_scan lease this gateway holds now:
-- only then may it submit the scan's findings (HR-209).
-- name: GatewayScanRun :one
SELECT r.id FROM pc.github_scan_runs r
JOIN pc.verifications v ON v.org_id = r.org_id AND v.id = r.verification_id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id) AND v.purpose = 'org_scan' AND v.state = 'LEASED'
  AND v.leased_by = sqlc.arg(gateway_id)::uuid AND v.lease_expires_at >= now();

-- ListOrgScanFindings are the discoveries a scan saw last.
-- name: ListOrgScanFindings :many
SELECT d.id, d.agent_id, d.observed, d.seen_count, d.first_seen_at, d.last_seen_at
FROM pc.discoveries d
WHERE d.org_id = sqlc.arg(org_id) AND d.source = 'github_scan' AND d.observed ->> 'scan_run' = sqlc.arg(scan_run)::text
  AND d.id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY d.id
LIMIT sqlc.arg(max_rows);
