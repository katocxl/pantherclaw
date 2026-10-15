-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Posture findings (G0 M10 D30): the remediation queue and its history.

-- PostureFindingsForReconcile lists every finding that is not remediated,
-- plus remediated ones (a remediated finding found again reopens).
-- name: PostureFindingsForReconcile :many
SELECT id, kind, fingerprint, state, affected_paths, accepted_until, connection_id FROM pc.posture_findings
WHERE org_id = sqlc.arg(org_id)
ORDER BY id
FOR UPDATE;

-- name: InsertPostureFinding :one
INSERT INTO pc.posture_findings (org_id, id, kind, root_cause, agent_id, connection_id, grant_id, coverage_finding_id, title,
    detail, affected_paths, severity, fingerprint, last_snapshot_id, first_seen_at, last_seen_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(root_cause), sqlc.narg(agent_id), sqlc.narg(connection_id),
    sqlc.narg(grant_id), sqlc.narg(coverage_finding_id), sqlc.arg(title), sqlc.arg(detail), sqlc.arg(affected_paths),
    sqlc.arg(severity), sqlc.arg(fingerprint), sqlc.arg(snapshot_id), sqlc.arg(seen_at), sqlc.arg(seen_at))
RETURNING *;

-- SeePostureFinding refreshes a finding that a snapshot found again.
-- name: SeePostureFinding :one
UPDATE pc.posture_findings SET title = sqlc.arg(title), detail = sqlc.arg(detail), affected_paths = sqlc.arg(affected_paths),
    severity = sqlc.arg(severity), last_snapshot_id = sqlc.arg(snapshot_id), last_seen_at = sqlc.arg(seen_at),
    agent_id = sqlc.narg(agent_id), connection_id = sqlc.narg(connection_id), grant_id = sqlc.narg(grant_id),
    coverage_finding_id = sqlc.narg(coverage_finding_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING *;

-- MovePostureFinding changes a finding's state, conditional on its current
-- one (HR-004); the trigger holds to the lifecycle.
-- name: MovePostureFinding :one
UPDATE pc.posture_findings SET state = sqlc.arg(to_state), owner_user_id = COALESCE(sqlc.narg(owner_user_id), owner_user_id),
    accepted_until = sqlc.narg(accepted_until), accepted_reason = sqlc.narg(accepted_reason),
    remediated_snapshot_id = sqlc.narg(remediated_snapshot_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state)
RETURNING *;

-- name: InsertPostureFindingEvent :exec
INSERT INTO pc.posture_finding_events (org_id, id, finding_id, kind, from_state, to_state, actor, note, snapshot_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(finding_id), sqlc.arg(kind), sqlc.narg(from_state), sqlc.arg(to_state),
    sqlc.arg(actor), sqlc.narg(note), sqlc.narg(snapshot_id));

-- name: GetPostureFinding :one
SELECT * FROM pc.posture_findings WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- ListPostureFindings lists findings newest first, optionally in some
-- states, of one kind or root cause.
-- name: ListPostureFindings :many
SELECT * FROM pc.posture_findings
WHERE org_id = sqlc.arg(org_id)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(kind)::text IS NULL OR kind = sqlc.narg(kind))
  AND (sqlc.narg(root_cause)::text IS NULL OR root_cause = sqlc.narg(root_cause))
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before))
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: ListPostureFindingEvents :many
SELECT * FROM pc.posture_finding_events
WHERE org_id = sqlc.arg(org_id) AND finding_id = sqlc.arg(finding_id)
ORDER BY occurred_at, id;

-- PostureCredentials lists each connection's active credential age.
-- name: PostureCredentials :many
SELECT c.id AS connection_id, c.name, cr.created_at FROM pc.connections c
JOIN pc.credentials cr ON cr.org_id = c.org_id AND cr.connection_id = c.id AND cr.state = 'ACTIVE'
WHERE c.org_id = sqlc.arg(org_id) AND c.state <> 'RETIRED'
ORDER BY c.id;

-- GetExposureSnapshotTime is when a snapshot was computed.
-- name: GetExposureSnapshotTime :one
SELECT computed_at FROM pc.exposure_snapshots WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
