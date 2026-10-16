-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Governed-automation executions, step attempts and launches (G0 M11 part 2
-- D24–D29).

-- name: InsertAutomationExecution :exec
INSERT INTO pc.automation_executions (org_id, id, automation_id, version_id, trigger_id, mode, ceiling_id,
    service_account_id, principal_user_id, principal_sa_id, trigger_kind, params, subjects, evidence, occurred_at,
    root_trigger_id, ancestry, depth, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(automation_id), sqlc.arg(version_id), sqlc.arg(trigger_id),
    sqlc.arg(mode), sqlc.narg(ceiling_id), sqlc.arg(service_account_id), sqlc.narg(principal_user_id),
    sqlc.narg(principal_sa_id), sqlc.arg(trigger_kind), sqlc.arg(params), sqlc.arg(subjects), sqlc.arg(evidence),
    sqlc.arg(occurred_at), sqlc.arg(root_trigger_id), sqlc.arg(ancestry), sqlc.arg(depth),
    now() + make_interval(secs => sqlc.arg(deadline_s)::bigint));

-- name: CountActiveAutomationExecutions :one
SELECT count(*)::int FROM pc.automation_executions
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND state IN ('PENDING', 'RUNNING', 'WAITING');

-- name: GetAutomationExecution :one
SELECT * FROM pc.automation_executions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockAutomationExecution :one
SELECT * FROM pc.automation_executions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: SaveAutomationExecution :execrows
UPDATE pc.automation_executions
SET state = sqlc.arg(state), reason = sqlc.narg(reason), current_step = sqlc.arg(current_step),
    compensating = sqlc.arg(compensating), result = sqlc.narg(result), transitions = sqlc.arg(transitions),
    started_at = sqlc.narg(started_at), wake_at = sqlc.narg(wake_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: RequestAutomationExecutionCancel :execrows
-- Asks an active execution to stop at its next boundary (D28); a second
-- request keeps the first.
UPDATE pc.automation_executions
SET cancel_requested_by = sqlc.arg(requested_by), cancel_reason = sqlc.arg(reason), cancel_requested_at = now(),
    wake_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'RUNNING', 'WAITING')
    AND cancel_requested_at IS NULL;

-- name: ActiveAutomationExecutions :many
SELECT id FROM pc.automation_executions
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND state IN ('PENDING', 'RUNNING', 'WAITING')
ORDER BY created_at;

-- name: AllActiveAutomationExecutions :many
SELECT id FROM pc.automation_executions
WHERE org_id = sqlc.arg(org_id) AND state IN ('PENDING', 'RUNNING', 'WAITING')
ORDER BY created_at
LIMIT sqlc.arg(max_rows);

-- name: DueAutomationExecutions :many
-- Executions whose wake time passed (D24 WakeSweep), including
-- NEEDS_RECONCILIATION rechecks.
SELECT id FROM pc.automation_executions
WHERE org_id = sqlc.arg(org_id) AND state IN ('PENDING', 'RUNNING', 'WAITING', 'NEEDS_RECONCILIATION')
    AND (wake_at IS NULL OR wake_at <= now())
ORDER BY wake_at NULLS FIRST
LIMIT sqlc.arg(max_rows);

-- name: ListAutomationStepAttempts :many
SELECT * FROM pc.automation_step_attempts
WHERE org_id = sqlc.arg(org_id) AND execution_id = sqlc.arg(execution_id)
ORDER BY compensation, step_index, attempt;

-- name: InsertAutomationStepAttempt :exec
INSERT INTO pc.automation_step_attempts (org_id, id, execution_id, step_index, step_id, attempt, kind, compensation,
    state, decision, reason, output, refs, effect, wake_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(execution_id), sqlc.arg(step_index), sqlc.arg(step_id),
    sqlc.arg(attempt), sqlc.arg(kind), sqlc.arg(compensation), sqlc.arg(state), sqlc.arg(decision), sqlc.narg(reason),
    sqlc.arg(output), sqlc.arg(refs), sqlc.arg(effect), sqlc.narg(wake_at));

-- name: SaveAutomationStepAttempt :execrows
UPDATE pc.automation_step_attempts
SET state = sqlc.arg(state), decision = sqlc.arg(decision), reason = sqlc.narg(reason), output = sqlc.arg(output),
    refs = sqlc.arg(refs), effect = sqlc.arg(effect), wake_at = sqlc.narg(wake_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('RUNNING', 'WAITING');

-- name: ListAutomationExecutions :many
-- Newest first; automation, states and mode filter when set.
SELECT * FROM pc.automation_executions
WHERE org_id = sqlc.arg(org_id)
    AND (sqlc.narg(automation_id)::uuid IS NULL OR automation_id = sqlc.narg(automation_id))
    AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY(sqlc.arg(states)::text[]))
    AND (sqlc.narg(mode)::text IS NULL OR mode = sqlc.narg(mode))
    AND (sqlc.narg(since)::timestamptz IS NULL OR created_at >= sqlc.narg(since))
    AND (sqlc.narg(until)::timestamptz IS NULL OR created_at < sqlc.narg(until))
    AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before))
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: AutomationAuthorityState :one
-- Everything HR-273 revalidates, read in the driver's transaction: the
-- automation and its enabled version, the owner, the execution identity
-- and whether it is contained, the execution's ceiling, the represented
-- person and the kill switch.
SELECT a.state, a.pause_reason, a.enabled_version_id, a.owner_user_id, a.service_account_id, a.name,
       (SELECT u.state FROM pc.users u WHERE u.org_id = a.org_id AND u.id = a.owner_user_id)::text AS owner_state,
       (SELECT s.state FROM pc.service_accounts s
        WHERE s.org_id = a.org_id AND s.id = a.service_account_id)::text AS identity_state,
       EXISTS (SELECT 1 FROM pc.containment_controls k
               WHERE k.org_id = a.org_id AND k.scope_type = 'principal'
                   AND k.scope_id = 'service_account:' || a.service_account_id::text
                   AND k.lifted_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now()))::bool AS identity_contained,
       coalesce((SELECT c.state FROM pc.automation_ceilings c
                 WHERE c.org_id = a.org_id AND c.id = sqlc.narg(ceiling_id)), '')::text AS ceiling_state,
       coalesce((SELECT c.review_by > now() FROM pc.automation_ceilings c
                 WHERE c.org_id = a.org_id AND c.id = sqlc.narg(ceiling_id)), false)::bool AS ceiling_in_review,
       coalesce((SELECT c.approved_by FROM pc.automation_ceilings c
                 WHERE c.org_id = a.org_id AND c.id = sqlc.narg(ceiling_id)), '{}')::uuid[] AS ceiling_approvers,
       coalesce((SELECT u.state FROM pc.users u
                 WHERE u.org_id = a.org_id AND u.id = sqlc.narg(principal_user_id)), 'ACTIVE')::text AS principal_state,
       coalesce((SELECT o.kill_switch FROM pc.org_containment o WHERE o.org_id = a.org_id), false)::bool AS kill_switch
FROM pc.automations a
WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(automation_id);

-- name: OperationsQuarantined :one
-- Whether a pinned definition of one of the operations (exact names, or
-- prefixes "x." of "x.*") is QUARANTINED or RETIRED (D59).
SELECT EXISTS (
    SELECT 1 FROM pc.package_pins p
    JOIN pc.package_versions v ON v.org_id = p.org_id AND v.id = p.version_id
    JOIN pc.action_definitions d ON d.org_id = v.org_id AND d.version_id = v.id
    WHERE p.org_id = sqlc.arg(org_id) AND v.state IN ('QUARANTINED', 'RETIRED')
        AND (d.operation = ANY(sqlc.arg(exact)::text[])
             OR EXISTS (SELECT 1 FROM unnest(sqlc.arg(prefixes)::text[]) pr WHERE starts_with(d.operation, pr)))
)::bool;

-- name: InsertAutomationLaunch :exec
INSERT INTO pc.automation_launches (org_id, id, execution_id, attempt_id, agent_id, instance_id, run_id, grant_id,
    task_ref, delivery, destination_id, claim_deadline, calls, run_params)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(execution_id), sqlc.arg(attempt_id), sqlc.arg(agent_id),
    sqlc.narg(instance_id), sqlc.arg(run_id), sqlc.arg(grant_id), sqlc.arg(task_ref), sqlc.arg(delivery),
    sqlc.narg(destination_id), now() + make_interval(secs => sqlc.arg(claim_within_s)::bigint), sqlc.arg(calls),
    sqlc.arg(run_params));

-- name: SetAutomationLaunchDelivery :execrows
UPDATE pc.automation_launches SET delivery_id = sqlc.arg(delivery_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND delivery_id IS NULL;

-- name: GetAutomationLaunch :one
-- With whether its run has bound an instance and the run's state.
SELECT l.*, (r.instance_id IS NOT NULL)::bool AS run_bound, r.instance_id AS run_instance_id, r.state AS run_state,
       (now() >= l.claim_deadline)::bool AS claim_due
FROM pc.automation_launches l
JOIN pc.runs r ON r.org_id = l.org_id AND r.id = l.run_id
WHERE l.org_id = sqlc.arg(org_id) AND l.id = sqlc.arg(id);

-- name: ClaimBoundAutomationLaunch :execrows
-- A launch whose run bound an instance counts as claimed by it (D26).
UPDATE pc.automation_launches SET state = 'CLAIMED', claimed_instance_id = sqlc.arg(instance_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: EndAutomationLaunch :execrows
-- EXPIRED (claim deadline passed) or CANCELLED (cleanup).
UPDATE pc.automation_launches SET state = sqlc.arg(state)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'CLAIMED');

-- name: OpenAutomationLaunches :many
SELECT id, run_id, grant_id, delivery_id FROM pc.automation_launches
WHERE org_id = sqlc.arg(org_id) AND execution_id = sqlc.arg(execution_id) AND state IN ('PENDING', 'CLAIMED');

-- name: RunEffectCounts :one
-- How a run's transactions of one operation ended (F500): those in the
-- wanted effect states, those whose outcome is unknown, those confirmed
-- to have had no effect, and all of them.
SELECT count(*) FILTER (WHERE t.effect_state = ANY(sqlc.arg(states)::text[]))::int AS matched,
       count(*) FILTER (WHERE t.effect_state IN ('UNKNOWN', 'CONFLICTING', 'UNVERIFIABLE', 'PROPAGATION_PENDING'))::int AS unknown,
       count(*) FILTER (WHERE t.effect_state = 'NONE_CONFIRMED')::int AS none_confirmed,
       count(*) FILTER (WHERE t.effect_state IS NULL AND t.decision = 'ALLOW')::int AS pending,
       count(*)::int AS total
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id) AND t.operation = sqlc.arg(operation);

-- name: RunEffectTransactions :many
SELECT t.id FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id) AND t.operation = sqlc.arg(operation)
    AND t.effect_state = ANY(sqlc.arg(states)::text[])
ORDER BY t.created_at
LIMIT 16;

-- name: RunTransactionCounts :one
SELECT count(*)::int AS total,
       count(*) FILTER (WHERE t.effect_state IN ('UNKNOWN', 'CONFLICTING', 'UNVERIFIABLE'))::int AS unknown
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id);

-- name: OperationIrreversible :one
-- Whether the pinned definition of an operation declares it irreversible.
SELECT EXISTS (
    SELECT 1 FROM pc.package_pins p
    JOIN pc.action_definitions d ON d.org_id = p.org_id AND d.version_id = p.version_id
    WHERE p.org_id = sqlc.arg(org_id) AND d.operation = sqlc.arg(operation)
        AND convert_from(d.canonical, 'UTF8')::jsonb ->> 'reversibility' = 'irreversible'
)::bool;

-- name: AutomationExecutionInfo :one
-- What a retry needs to know (D59, D75): the execution and whether a step
-- of an irreversible operation ended with an unknown outcome.
SELECT e.automation_id, e.version_id, e.state, e.trigger_id,
       EXISTS (SELECT 1 FROM pc.automation_step_attempts a
               WHERE a.org_id = e.org_id AND a.execution_id = e.id AND a.state = 'UNKNOWN'
                   AND a.output ->> 'irreversible' = 'true')::bool AS unknown_irreversible
FROM pc.automation_executions e
WHERE e.org_id = sqlc.arg(org_id) AND e.id = sqlc.arg(id);
