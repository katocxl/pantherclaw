-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Automation proposals (G0 M11 part 2 D31, HR-286).

-- name: InsertAutomationProposal :one
-- Records a proposal once per execution, step and subject; a repeat of the
-- same step returns the first.
INSERT INTO pc.automation_proposals (org_id, id, execution_id, step_id, kind, subject_type, subject_id, body)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(execution_id), sqlc.arg(step_id), sqlc.arg(kind),
    sqlc.arg(subject_type), sqlc.arg(subject_id), sqlc.arg(body))
ON CONFLICT (org_id, execution_id, step_id, subject_id) DO NOTHING
RETURNING *;

-- name: GetAutomationProposalByStep :one
SELECT * FROM pc.automation_proposals
WHERE org_id = sqlc.arg(org_id) AND execution_id = sqlc.arg(execution_id) AND step_id = sqlc.arg(step_id)
    AND subject_id = sqlc.arg(subject_id);

-- name: GetAutomationProposal :one
SELECT * FROM pc.automation_proposals WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SupersedeAutomationProposals :execrows
-- An open proposal of the same kind about the same subject is superseded by
-- a newer one.
UPDATE pc.automation_proposals SET state = 'SUPERSEDED', decided_at = now()
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND subject_id = sqlc.arg(subject_id)
    AND state = 'PROPOSED' AND id <> sqlc.arg(keep);

-- name: DecideAutomationProposal :one
UPDATE pc.automation_proposals SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PROPOSED'
RETURNING *;

-- name: ListAutomationProposals :many
SELECT p.*, e.automation_id FROM pc.automation_proposals p
JOIN pc.automation_executions e ON e.org_id = p.org_id AND e.id = p.execution_id
WHERE p.org_id = sqlc.arg(org_id)
    AND (sqlc.narg(state)::text IS NULL OR p.state = sqlc.narg(state))
    AND (sqlc.narg(kind)::text IS NULL OR p.kind = sqlc.narg(kind))
    AND (sqlc.narg(subject_id)::uuid IS NULL OR p.subject_id = sqlc.narg(subject_id))
    AND (sqlc.narg(automation_id)::uuid IS NULL OR e.automation_id = sqlc.narg(automation_id))
    AND (sqlc.narg(after)::uuid IS NULL OR p.id < sqlc.narg(after))
ORDER BY p.id DESC
LIMIT sqlc.arg(max_rows);

-- name: AutomationStepDoneRefs :one
-- The refs of a step's last DONE attempt in an execution (resume_launches
-- resumes exactly what its pause_launches step paused).
SELECT refs FROM pc.automation_step_attempts
WHERE org_id = sqlc.arg(org_id) AND execution_id = sqlc.arg(execution_id) AND step_id = sqlc.arg(step_id)
    AND state = 'DONE' AND NOT compensation
ORDER BY attempt DESC
LIMIT 1;

-- name: LatestApprovalRequestOfTransaction :one
-- The approval request a held action made (approval routing steps).
SELECT * FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id)
ORDER BY created_at DESC
LIMIT 1;

-- name: AutomationOwnerOfConnection :one
-- The person who created a connection (connections have no owner column;
-- assign_owner CONNECTION_OWNER).
SELECT created_by FROM pc.connections WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: AutomationTransactionOutcome :one
-- What became of a held action once decided (wait_resolution).
SELECT state, effect_state FROM pc.transactions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
