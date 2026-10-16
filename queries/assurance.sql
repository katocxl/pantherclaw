-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Governed automations, assurance (G0 M11 part 2 D34–D38).

-- name: AssuranceVersion :one
-- A version with its automation, for tests, simulation and inspection.
SELECT v.id, v.automation_id, v.number, v.state, v.definition, v.digest, v.tested_run_id,
       a.name AS automation_name, a.owner_user_id, a.state AS automation_state, a.rollout, a.enabled_version_id,
       a.service_account_id
FROM pc.automation_versions v
JOIN pc.automations a ON a.org_id = v.org_id AND a.id = v.automation_id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id);

-- name: LockAssuranceVersion :one
SELECT v.id, v.automation_id, v.state, v.digest
FROM pc.automation_versions v
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id)
FOR UPDATE;

-- name: DeleteAutomationTestCases :execrows
DELETE FROM pc.automation_test_cases WHERE org_id = sqlc.arg(org_id) AND version_id = sqlc.arg(version_id);

-- name: InsertAutomationTestCase :exec
INSERT INTO pc.automation_test_cases (org_id, id, version_id, name, case_kind, trigger, stubs, expect, seq, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(version_id), sqlc.arg(name), sqlc.arg(case_kind), sqlc.arg(trigger),
        sqlc.arg(stubs), sqlc.arg(expect), sqlc.arg(seq), sqlc.arg(created_by));

-- name: ListAutomationTestCases :many
SELECT c.id, c.name, c.case_kind, c.trigger, c.stubs, c.expect, c.seq, c.created_by, c.created_at
FROM pc.automation_test_cases c
WHERE c.org_id = sqlc.arg(org_id) AND c.version_id = sqlc.arg(version_id)
ORDER BY c.seq;

-- name: InsertAutomationTestRun :one
INSERT INTO pc.automation_test_runs (org_id, id, version_id, definition_digest, tests_digest, passed, results, run_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(version_id), sqlc.arg(definition_digest), sqlc.arg(tests_digest),
        sqlc.arg(passed), sqlc.arg(results), sqlc.arg(run_by))
RETURNING created_at;

-- name: GetAutomationTestRun :one
SELECT r.id, r.version_id, r.definition_digest, r.tests_digest, r.passed, r.results, r.run_by, r.created_at
FROM pc.automation_test_runs r
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- name: LatestAutomationTestRun :one
-- The newest run of a version for this definition digest (D34).
SELECT r.id, r.version_id, r.definition_digest, r.tests_digest, r.passed, r.results, r.run_by, r.created_at
FROM pc.automation_test_runs r
WHERE r.org_id = sqlc.arg(org_id) AND r.version_id = sqlc.arg(version_id) AND r.definition_digest = sqlc.arg(digest)
ORDER BY r.created_at DESC, r.id DESC
LIMIT 1;

-- name: InsertAutomationSimulation :exec
INSERT INTO pc.automation_simulations (org_id, id, version_id, from_at, to_at, requested_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(version_id), sqlc.arg(from_at), sqlc.arg(to_at), sqlc.arg(requested_by));

-- name: GetAutomationSimulation :one
SELECT s.id, s.version_id, s.from_at, s.to_at, s.state, s.results, s.error, s.requested_by, s.created_at, s.started_at,
       s.finished_at
FROM pc.automation_simulations s
WHERE s.org_id = sqlc.arg(org_id) AND s.id = sqlc.arg(id);

-- name: StartAutomationSimulation :execrows
UPDATE pc.automation_simulations SET state = 'RUNNING', started_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'QUEUED';

-- name: FinishAutomationSimulation :execrows
UPDATE pc.automation_simulations SET state = 'DONE', results = sqlc.arg(results), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'RUNNING';

-- name: FailAutomationSimulation :execrows
UPDATE pc.automation_simulations SET state = 'FAILED', error = sqlc.arg(error), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('QUEUED', 'RUNNING');

-- name: AssuranceEnabledDefinitions :many
-- The enabled versions of the org's ACTIVE or PAUSED automations (D37:
-- triggered workflows).
SELECT a.id AS automation_id, v.definition
FROM pc.automations a
JOIN pc.automation_versions v ON v.org_id = a.org_id AND v.id = a.enabled_version_id
WHERE a.org_id = sqlc.arg(org_id) AND a.state IN ('ACTIVE', 'PAUSED')
ORDER BY a.id
LIMIT 1000;

-- name: AssuranceIssuedGrants :many
-- Grants an automation's executions were issued since a time, with the
-- bounds of their first revision (D37 CompareRestriction).
SELECT g.id, g.agent_id, g.automation_execution_id, r.bounds, g.created_at
FROM pc.grants g
JOIN pc.automation_ceilings c ON c.org_id = g.org_id AND c.id = g.ceiling_id
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = 1
WHERE g.org_id = sqlc.arg(org_id) AND c.automation_id = sqlc.arg(automation_id) AND g.created_at >= sqlc.arg(since)
ORDER BY g.created_at DESC, g.id DESC
LIMIT sqlc.arg(max_rows)::int;

-- name: AssuranceVersionOrg :one
-- The org of a version visible under the tenant setting (TestGate is
-- called inside the confirming transaction with no org argument).
SELECT v.org_id FROM pc.automation_versions v WHERE v.id = sqlc.arg(id);

-- name: AssuranceFeedSeqAt :one
-- The feed position just before the first entry at or after a time (D35).
SELECT coalesce((SELECT c.seq FROM pc.ledger_chain c
                 JOIN pc.ledger_entries e ON e.org_id = c.org_id AND e.id = c.entry_id
                 WHERE c.org_id = sqlc.arg(org_id) AND e.occurred_at >= sqlc.arg(at)::timestamptz
                 ORDER BY c.seq LIMIT 1) - 1, -1)::bigint AS seq;

-- name: AssuranceReceipts :many
-- Past inbound deliveries of one source and type (types only, D35).
SELECT r.source_id, r.type, r.received_at
FROM pc.automation_event_receipts r
WHERE r.org_id = sqlc.arg(org_id) AND r.source_id = sqlc.arg(source_id) AND r.type = sqlc.arg(type)
  AND r.received_at >= sqlc.arg(from_at) AND r.received_at < sqlc.arg(to_at)
ORDER BY r.received_at
LIMIT 100000;

-- name: AssuranceGrantExpiries :many
-- Grants whose current window ended or ends in a period (D35 grant.expiring).
SELECT g.id, g.agent_id, g.principal_user_id, g.principal_sa_id, r.task_ref, r.expires_at
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND r.expires_at >= sqlc.arg(from_at) AND r.expires_at < sqlc.arg(to_at)
ORDER BY r.expires_at, g.id
LIMIT 10000;
