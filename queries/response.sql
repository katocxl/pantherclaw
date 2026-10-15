-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Graduated containment and response actions (G0 M10 D21–D26).

-- ActiveContainmentControls are the controls the decision pipeline enforces
-- (HR-248): not lifted and not expired by the database clock.
-- name: ActiveContainmentControls :many
SELECT id, scope_type, scope_id, control, operation, expires_at
FROM pc.containment_controls
WHERE org_id = sqlc.arg(org_id) AND lifted_at IS NULL AND (expires_at IS NULL OR expires_at > now())
ORDER BY created_at, id
LIMIT 1000;

-- name: InsertResponseAction :one
INSERT INTO pc.response_actions (org_id, id, kind, scope_type, scope_id, control, operation, reason, case_id, incident_id,
                                 actor, source, preview_digest, skip_preview, skip_reason, skip_step_up_at,
                                 idempotency_key, request_digest)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(scope_type), sqlc.arg(scope_id),
        sqlc.narg(control), sqlc.narg(operation), sqlc.arg(reason), sqlc.narg(case_id), sqlc.narg(incident_id),
        sqlc.arg(actor), sqlc.arg(source), sqlc.narg(preview_digest), sqlc.arg(skip_preview), sqlc.narg(skip_reason),
        sqlc.narg(skip_step_up_at), sqlc.narg(idempotency_key), sqlc.narg(request_digest))
RETURNING requested_at;

-- InsertContainmentControl adds a control; its trigger raises the epoch in
-- the same transaction (HR-248).
-- name: InsertContainmentControl :one
INSERT INTO pc.containment_controls (org_id, id, action_id, scope_type, scope_id, control, operation, reason, case_id,
                                     incident_id, created_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(action_id), sqlc.arg(scope_type), sqlc.arg(scope_id), sqlc.arg(control),
        sqlc.narg(operation), sqlc.arg(reason), sqlc.narg(case_id), sqlc.narg(incident_id), sqlc.arg(created_by),
        sqlc.narg(expires_at))
RETURNING created_at;

-- LiftContainmentControl lifts an active control through a restoration
-- plan; its trigger stamps the database time and raises the epoch.
-- name: LiftContainmentControl :execrows
UPDATE pc.containment_controls
SET lifted_at = now(), lifted_by = sqlc.arg(lifted_by), restoration_id = sqlc.arg(restoration_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND lifted_at IS NULL;

-- name: GetContainmentControl :one
SELECT * FROM pc.containment_controls WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListContainmentControls :many
SELECT * FROM pc.containment_controls
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(include_lifted)::boolean OR lifted_at IS NULL)
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(max_rows);

-- name: GetResponseAction :one
SELECT * FROM pc.response_actions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ResponseActionByKey :one
SELECT * FROM pc.response_actions WHERE org_id = sqlc.arg(org_id) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: SetResponseActionEpoch :exec
UPDATE pc.response_actions SET epoch = sqlc.arg(epoch), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- SettleResponseAction moves an unsettled action to its next status
-- (conditional on the status read, HR-249).
-- name: SettleResponseAction :execrows
UPDATE pc.response_actions
SET status = sqlc.arg(status), future_confirmed = sqlc.arg(future_confirmed), historical_open = sqlc.arg(historical_open),
    updated_at = now(),
    settled_at = CASE WHEN sqlc.arg(status)::text IN ('CONFIRMED', 'FAILED', 'UNSUPPORTED') THEN now() END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND status = sqlc.arg(expected) AND settled_at IS NULL;

-- name: UnsettledResponseActions :many
SELECT * FROM pc.response_actions
WHERE org_id = sqlc.arg(org_id) AND settled_at IS NULL
ORDER BY requested_at, id
LIMIT sqlc.arg(max_rows);

-- name: InsertResponsePath :exec
INSERT INTO pc.response_paths (org_id, action_id, id, path_type, subject_type, subject_id, material, control, status,
                               evidence, failure, unsupported_reason, cancel_capability, confirmed_at)
VALUES (sqlc.arg(org_id), sqlc.arg(action_id), sqlc.arg(id), sqlc.arg(path_type), sqlc.arg(subject_type),
        sqlc.arg(subject_id), sqlc.arg(material), sqlc.arg(control), sqlc.arg(status), sqlc.arg(evidence),
        sqlc.narg(failure), sqlc.narg(unsupported_reason), sqlc.narg(cancel_capability),
        CASE WHEN sqlc.arg(status)::text = 'CONFIRMED' THEN now() END)
ON CONFLICT (org_id, action_id, path_type, subject_type, subject_id) DO NOTHING;

-- name: ListResponsePaths :many
SELECT * FROM pc.response_paths
WHERE org_id = sqlc.arg(org_id) AND action_id = sqlc.arg(action_id)
ORDER BY path_type, subject_type, subject_id;

-- UpdateResponsePath moves an open path (conditional on its status).
-- name: UpdateResponsePath :execrows
UPDATE pc.response_paths
SET status = sqlc.arg(status), evidence = sqlc.arg(evidence), failure = sqlc.narg(failure),
    unsupported_reason = sqlc.narg(unsupported_reason), updated_at = now(),
    confirmed_at = CASE WHEN sqlc.arg(status)::text = 'CONFIRMED' THEN now() END
WHERE org_id = sqlc.arg(org_id) AND action_id = sqlc.arg(action_id) AND id = sqlc.arg(id)
  AND status = sqlc.arg(expected) AND status IN ('PENDING', 'UNRESOLVED');
