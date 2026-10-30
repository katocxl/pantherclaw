-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Outcome metrics (G0 M21 D303, F774). Each metric reads non-simulated,
-- enforced or LIVE work only; test and range records never count.

-- name: StartOutcomeCollection :exec
INSERT INTO pc.outcome_collection (org_id) VALUES (sqlc.arg(org_id)) ON CONFLICT (org_id) DO NOTHING;

-- name: OutcomeCollectionStarted :one
SELECT started_at FROM pc.outcome_collection WHERE org_id = sqlc.arg(org_id);

-- name: OutcomeSampledFor :one
-- Whether the rollup of the window ending then already ran.
SELECT EXISTS (SELECT 1 FROM pc.outcome_metric_samples
               WHERE org_id = sqlc.arg(org_id) AND window_end = sqlc.arg(window_end)::timestamptz)::boolean;

-- name: InsertOutcomeSample :execrows
INSERT INTO pc.outcome_metric_samples (org_id, id, metric, dimension, window_start, window_end, p50_seconds, p90_seconds, share,
                                       measured, unmeasured, reasons, collected)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(metric), sqlc.arg(dimension), sqlc.arg(window_start), sqlc.arg(window_end),
        sqlc.narg(p50_seconds), sqlc.narg(p90_seconds), sqlc.narg(share), sqlc.arg(measured), sqlc.arg(unmeasured),
        sqlc.arg(reasons), sqlc.arg(collected))
ON CONFLICT (org_id, metric, dimension, window_start, window_end) DO NOTHING;

-- name: ListOutcomeSamples :many
-- Samples of one window length whose window ends in (range_start, range_end].
SELECT * FROM pc.outcome_metric_samples
WHERE org_id = sqlc.arg(org_id) AND metric = ANY (sqlc.arg(metrics)::text[])
  AND window_end > sqlc.arg(range_start)::timestamptz AND window_end <= sqlc.arg(range_end)::timestamptz
  AND window_end - window_start = make_interval(days => sqlc.arg(window_days)::integer)
ORDER BY metric, dimension, window_end;

-- name: RecordEnrolledMilestones :execrows
-- M1: an agent's first enrolment, only once collection had started.
INSERT INTO pc.agent_milestones (org_id, agent_id, kind, at)
SELECT c.org_id, c.agent_id, 'enrolled', min(c.created_at)
FROM pc.agent_changes c
JOIN pc.agents a ON a.org_id = c.org_id AND a.id = c.agent_id
WHERE c.org_id = sqlc.arg(org_id) AND c.kind IN ('instance.enrolled', 'instance.admitted') AND NOT a.range_agent
GROUP BY c.org_id, c.agent_id
HAVING min(c.created_at) >= sqlc.arg(started_at)::timestamptz
ON CONFLICT (org_id, agent_id, kind) DO NOTHING;

-- name: RecordFirstEnforcedMilestones :execrows
-- M1: a tracked agent's first enforced, non-simulated decision.
INSERT INTO pc.agent_milestones (org_id, agent_id, kind, at)
SELECT m.org_id, m.agent_id, 'first_enforced', x.at
FROM pc.agent_milestones m
CROSS JOIN LATERAL (
    SELECT min(t.created_at) AS at
    FROM pc.runs r
    JOIN pc.transactions t ON t.org_id = r.org_id AND t.run_id = r.id
    WHERE r.org_id = m.org_id AND r.agent_id = m.agent_id AND t.mode = 'enforce' AND NOT t.simulated AND t.created_at >= m.at
) x
WHERE m.org_id = sqlc.arg(org_id) AND m.kind = 'enrolled' AND x.at IS NOT NULL
ON CONFLICT (org_id, agent_id, kind) DO NOTHING;

-- name: OutcomeAgentJourneys :many
-- M1: tracked agents, and whether they were only ever observed.
SELECT m.agent_id, m.at AS enrolled_at, f.at AS enforced_at,
       EXISTS (SELECT 1 FROM pc.runs r
               JOIN pc.transactions t ON t.org_id = r.org_id AND t.run_id = r.id
               WHERE r.org_id = m.org_id AND r.agent_id = m.agent_id AND t.mode = 'monitor' AND NOT t.simulated)::boolean AS observed
FROM pc.agent_milestones m
JOIN pc.agents a ON a.org_id = m.org_id AND a.id = m.agent_id
LEFT JOIN pc.agent_milestones f ON f.org_id = m.org_id AND f.agent_id = m.agent_id AND f.kind = 'first_enforced'
WHERE m.org_id = sqlc.arg(org_id) AND m.kind = 'enrolled' AND a.state <> 'RETIRED'
ORDER BY m.agent_id;

-- name: OutcomeAgentsBeforeTracking :one
-- M1: agents enrolled before collection started, which are never measured.
SELECT count(*)::bigint FROM pc.agents a
WHERE a.org_id = sqlc.arg(org_id) AND NOT a.range_agent AND a.state <> 'RETIRED'
  AND EXISTS (SELECT 1 FROM pc.agent_changes c
              WHERE c.org_id = a.org_id AND c.agent_id = a.id AND c.kind IN ('instance.enrolled', 'instance.admitted')
                AND c.created_at < sqlc.arg(started_at)::timestamptz);

-- name: OutcomeExplanationDelivery :one
-- M2, agent side: non-ALLOW decisions, and those with a decision receipt.
-- The Authority builds the explanation with the receipt, in the response.
SELECT count(*)::bigint AS decisions,
       count(*) FILTER (WHERE EXISTS (SELECT 1 FROM pc.decision_receipts r
                                      WHERE r.org_id = t.org_id AND r.transaction_id = t.id))::bigint AS delivered
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.mode = 'enforce' AND NOT t.simulated AND t.decision <> 'ALLOW'
  AND t.created_at >= sqlc.arg(start_at)::timestamptz AND t.created_at < sqlc.arg(end_at)::timestamptz;

-- name: OutcomeExplanationSeconds :many
-- M2, people side: from a non-ALLOW decision to its first evidence read.
SELECT extract(epoch FROM v.first_viewed_at - t.created_at)::double precision AS seconds
FROM pc.transactions t
JOIN pc.explanation_views v ON v.org_id = t.org_id AND v.transaction_id = t.id
WHERE t.org_id = sqlc.arg(org_id) AND t.mode = 'enforce' AND NOT t.simulated AND t.decision <> 'ALLOW'
  AND t.created_at >= sqlc.arg(start_at)::timestamptz AND t.created_at < sqlc.arg(end_at)::timestamptz
  AND v.first_viewed_at < sqlc.arg(end_at)::timestamptz;

-- name: OutcomeExplanationUnread :one
-- M2: non-ALLOW decisions nobody had opened by the end of the window.
SELECT count(*)::bigint AS n,
       coalesce(extract(epoch FROM sqlc.arg(end_at)::timestamptz - min(t.created_at)), 0)::double precision AS oldest_age_seconds
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.mode = 'enforce' AND NOT t.simulated AND t.decision <> 'ALLOW'
  AND t.created_at >= sqlc.arg(start_at)::timestamptz AND t.created_at < sqlc.arg(end_at)::timestamptz
  AND NOT EXISTS (SELECT 1 FROM pc.explanation_views v
                  WHERE v.org_id = t.org_id AND v.transaction_id = t.id AND v.first_viewed_at < sqlc.arg(end_at)::timestamptz);

-- name: OutcomeContainmentEpisodes :many
-- M3: every case, and every incident without a case, from the earliest of
-- its alert, incident and case to its first confirmed containment. Only a
-- CONFIRMED action, a case's confirmed close or a linked grant revoke
-- confirms; a REQUESTED action or a declared incident never does (HR-538).
WITH episodes AS (
    SELECT c.org_id, c.id AS case_id, c.incident_id, c.contained_at,
           least(c.created_at, i.created_at, a.created_at)::timestamptz AS started_at,
           i.contained_at AS declared_at, (c.state = 'CLOSED')::boolean AS ended,
           EXISTS (SELECT 1 FROM pc.case_entries e
                   WHERE e.org_id = c.org_id AND e.case_id = c.id AND e.no_containment_needed)::boolean AS no_containment_needed
    FROM pc.cases c
    LEFT JOIN pc.incidents i ON i.org_id = c.org_id AND i.id = c.incident_id
    LEFT JOIN pc.alerts a ON a.org_id = c.org_id AND a.id = c.alert_id
    WHERE c.org_id = sqlc.arg(org_id) AND NOT coalesce(i.test, false) AND NOT coalesce(a.test, false)
    UNION ALL
    SELECT i.org_id, NULL::uuid, i.id, NULL::timestamptz,
           least(i.created_at, (SELECT min(x.created_at) FROM pc.alerts x
                                WHERE x.org_id = i.org_id AND x.incident_id = i.id AND NOT x.test))::timestamptz,
           i.contained_at, (i.state = 'RESOLVED')::boolean, false
    FROM pc.incidents i
    WHERE i.org_id = sqlc.arg(org_id) AND NOT i.test
      AND NOT EXISTS (SELECT 1 FROM pc.cases c WHERE c.org_id = i.org_id AND c.incident_id = i.id)
)
SELECT e.started_at, e.ended, e.no_containment_needed, (e.declared_at IS NOT NULL)::boolean AS declared,
       (least(e.contained_at, r.confirmed_at, g.revoked_at) IS NOT NULL)::boolean AS confirmed,
       coalesce(least(e.contained_at, r.confirmed_at, g.revoked_at), e.started_at)::timestamptz AS confirmed_at,
       r.open_requests, r.failed
FROM episodes e
CROSS JOIN LATERAL (
    SELECT min(ra.settled_at) FILTER (WHERE ra.status = 'CONFIRMED') AS confirmed_at,
           count(*) FILTER (WHERE ra.status IN ('REQUESTED', 'PARTIAL'))::bigint AS open_requests,
           count(*) FILTER (WHERE ra.status IN ('FAILED', 'UNSUPPORTED'))::bigint AS failed
    FROM pc.response_actions ra
    WHERE ra.org_id = e.org_id AND (ra.case_id = e.case_id OR ra.incident_id = e.incident_id
          OR ra.id::text IN (SELECT lower(l.ref_id) FROM pc.case_entries l
                             WHERE l.org_id = e.org_id AND l.case_id = e.case_id AND l.kind = 'LINK'
                               AND l.ref_kind = 'response_action' AND NOT pc.case_entry_superseded(l.org_id, l.id)))
) r
CROSS JOIN LATERAL (
    SELECT min(x.revoked_at) AS revoked_at
    FROM pc.grants x
    WHERE x.org_id = e.org_id AND x.state = 'REVOKED'
      AND x.id::text IN (SELECT lower(l.ref_id) FROM pc.case_entries l
                         WHERE l.org_id = e.org_id AND l.case_id = e.case_id AND l.kind = 'LINK'
                           AND l.ref_kind = 'grant' AND NOT pc.case_entry_superseded(l.org_id, l.id))
) g;

-- name: OutcomeGrantRevokesUnlinked :one
-- M3: grants revoked in the window that no case links.
SELECT count(*)::bigint FROM pc.grants x
WHERE x.org_id = sqlc.arg(org_id) AND x.state = 'REVOKED'
  AND x.revoked_at >= sqlc.arg(start_at)::timestamptz AND x.revoked_at < sqlc.arg(end_at)::timestamptz
  AND NOT EXISTS (SELECT 1 FROM pc.case_entries l
                  WHERE l.org_id = x.org_id AND l.kind = 'LINK' AND l.ref_kind = 'grant' AND lower(l.ref_id) = x.id::text
                    AND NOT pc.case_entry_superseded(l.org_id, l.id));

-- name: OutcomeRequestedToConfirmed :many
-- M3: requested to confirmed, for actions confirmed in the window.
SELECT extract(epoch FROM a.settled_at - a.requested_at)::double precision AS seconds
FROM pc.response_actions a
WHERE a.org_id = sqlc.arg(org_id) AND a.status = 'CONFIRMED'
  AND a.settled_at >= sqlc.arg(start_at)::timestamptz AND a.settled_at < sqlc.arg(end_at)::timestamptz;

-- name: OutcomeActionsNotConfirmed :many
-- M3: actions that stand unconfirmed at the end of the window, or settled
-- in it without being confirmed. They are listed, never counted as contained.
SELECT a.status, count(*)::bigint AS n,
       extract(epoch FROM sqlc.arg(end_at)::timestamptz - min(a.requested_at))::double precision AS oldest_age_seconds
FROM pc.response_actions a
WHERE a.org_id = sqlc.arg(org_id) AND a.requested_at < sqlc.arg(end_at)::timestamptz
  AND ((a.status IN ('REQUESTED', 'PARTIAL'))
       OR (a.status IN ('FAILED', 'UNSUPPORTED') AND a.settled_at >= sqlc.arg(start_at)::timestamptz
           AND a.settled_at < sqlc.arg(end_at)::timestamptz))
GROUP BY a.status
ORDER BY a.status;

-- name: OutcomeApprovalWaits :many
-- M4: from a request to its first decision.
SELECT extract(epoch FROM r.first_decided_at - r.created_at)::double precision AS seconds
FROM pc.approval_requests r
WHERE r.org_id = sqlc.arg(org_id)
  AND r.first_decided_at >= sqlc.arg(start_at)::timestamptz AND r.first_decided_at < sqlc.arg(end_at)::timestamptz;

-- name: OutcomeApprovalsUndecided :many
-- M4: requests of the window without a first decision by its end.
SELECT (r.ended_at IS NOT NULL AND r.ended_at < sqlc.arg(end_at)::timestamptz)::boolean AS ended, count(*)::bigint AS n,
       extract(epoch FROM sqlc.arg(end_at)::timestamptz - min(r.created_at))::double precision AS oldest_age_seconds
FROM pc.approval_requests r
WHERE r.org_id = sqlc.arg(org_id)
  AND r.created_at >= sqlc.arg(start_at)::timestamptz AND r.created_at < sqlc.arg(end_at)::timestamptz
  AND (r.first_decided_at IS NULL OR r.first_decided_at >= sqlc.arg(end_at)::timestamptz)
GROUP BY 1
ORDER BY 1;

-- name: OutcomeHolds :one
-- M4: held decisions over decisions in enforce mode.
SELECT count(*)::bigint AS decisions,
       count(*) FILTER (WHERE t.decision IN ('REQUIRE_APPROVAL', 'REQUIRE_STEP_UP'))::bigint AS held
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.mode = 'enforce' AND NOT t.simulated
  AND t.created_at >= sqlc.arg(start_at)::timestamptz AND t.created_at < sqlc.arg(end_at)::timestamptz;

-- name: OutcomeOverrides :one
-- M4: DENYs whose 7 days after ended inside the window, those followed by
-- an activated exception for the agent and operation, and the DENYs whose
-- 7 days are still running. A decision's rule is not stored in a column.
SELECT count(*) FILTER (WHERE t.created_at < sqlc.arg(settled_before)::timestamptz)::bigint AS denies,
       count(*) FILTER (WHERE t.created_at < sqlc.arg(settled_before)::timestamptz AND EXISTS (
           SELECT 1 FROM pc.policy_exceptions x
           WHERE x.org_id = t.org_id AND x.agent_id = r.agent_id AND t.operation = ANY (x.operations)
             AND x.activated_at IS NOT NULL AND x.created_at >= t.created_at
             AND x.created_at < t.created_at + interval '7 days'))::bigint AS overridden,
       count(*) FILTER (WHERE t.created_at >= sqlc.arg(settled_before)::timestamptz)::bigint AS following
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND t.mode = 'enforce' AND NOT t.simulated AND t.decision = 'DENY'
  AND t.created_at >= sqlc.arg(start_at)::timestamptz AND t.created_at < sqlc.arg(end_at)::timestamptz;

-- name: OutcomePolicyChecks :many
-- M5: what each policy version published in the window had before it was.
SELECT v.id,
       EXISTS (SELECT 1 FROM pc.policy_validations c
               WHERE c.org_id = v.org_id AND c.version_id = v.id AND c.passed AND c.created_at <= v.published_at)::boolean AS validated,
       EXISTS (SELECT 1 FROM pc.policy_test_runs c
               WHERE c.org_id = v.org_id AND c.version_id = v.id AND c.passed AND c.created_at <= v.published_at)::boolean AS tested,
       EXISTS (SELECT 1 FROM pc.policy_simulations c
               WHERE c.org_id = v.org_id AND c.version_id = v.id AND c.state = 'DONE' AND c.created_at <= v.published_at)::boolean AS simulated,
       EXISTS (SELECT 1 FROM pc.policy_rollouts c
               WHERE c.org_id = v.org_id AND c.version_id = v.id AND c.stage <> 'CANCELLED' AND c.created_at <= v.published_at)::boolean AS staged,
       EXISTS (SELECT 1 FROM pc.policy_rollouts c
               WHERE c.org_id = v.org_id AND c.version_id = v.id
                 AND NOT EXISTS (SELECT 1 FROM pc.policy_rollout_stage_events s
                                 WHERE s.org_id = c.org_id AND s.rollout_id = c.id))::boolean AS history_missing
FROM pc.policy_versions v
WHERE v.org_id = sqlc.arg(org_id)
  AND v.published_at >= sqlc.arg(start_at)::timestamptz AND v.published_at < sqlc.arg(end_at)::timestamptz
ORDER BY v.id;

-- name: OutcomeAutomationChecks :many
-- M5: what each automation version published in the window had before it was.
SELECT v.id, (v.validated_at IS NOT NULL)::boolean AS validated, (v.tested_at IS NOT NULL)::boolean AS tested,
       EXISTS (SELECT 1 FROM pc.automation_simulations c
               WHERE c.org_id = v.org_id AND c.version_id = v.id AND c.state = 'DONE' AND c.created_at <= v.published_at)::boolean AS simulated
FROM pc.automation_versions v
WHERE v.org_id = sqlc.arg(org_id)
  AND v.published_at >= sqlc.arg(start_at)::timestamptz AND v.published_at < sqlc.arg(end_at)::timestamptz
ORDER BY v.id;

-- name: OutcomeEmergencyChanges :one
-- M5: emergency changes, listed apart.
SELECT count(*)::bigint FROM pc.protected_changes c
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'EMERGENCY'
  AND c.created_at >= sqlc.arg(start_at)::timestamptz AND c.created_at < sqlc.arg(end_at)::timestamptz;

-- name: OutcomeRolloutTargets :one
-- M5: the targets of rollouts started in the window, and those FAILED.
SELECT count(*)::bigint AS targets, count(*) FILTER (WHERE t.state = 'FAILED')::bigint AS failed
FROM pc.policy_rollouts r
JOIN pc.policy_rollout_targets t ON t.org_id = r.org_id AND t.rollout_id = r.id
WHERE r.org_id = sqlc.arg(org_id)
  AND r.created_at >= sqlc.arg(start_at)::timestamptz AND r.created_at < sqlc.arg(end_at)::timestamptz;

-- name: OutcomeAutomationRates :many
-- M6: per automation, its LIVE executions ended in the window, and those
-- a person gated, that compensated, and that a person reverted. Only a
-- revert linked to the execution through its action counts.
SELECT e.automation_id, count(*)::bigint AS executions,
       count(*) FILTER (WHERE EXISTS (SELECT 1 FROM pc.approval_requests g
                                      WHERE g.org_id = e.org_id AND g.execution_id = e.id AND g.first_decided_at IS NOT NULL))::bigint AS intervened,
       count(*) FILTER (WHERE EXISTS (SELECT 1 FROM pc.automation_step_attempts x
                                      WHERE x.org_id = e.org_id AND x.execution_id = e.id AND x.compensation))::bigint AS compensated,
       count(*) FILTER (WHERE EXISTS (SELECT 1 FROM pc.response_actions a
                                      JOIN pc.containment_controls c ON c.org_id = a.org_id AND c.action_id = a.id
                                      WHERE a.org_id = e.org_id AND a.execution_id = e.id AND c.lifted_at IS NOT NULL))::bigint AS reverted
FROM pc.automation_executions e
WHERE e.org_id = sqlc.arg(org_id) AND e.mode = 'LIVE'
  AND e.ended_at >= sqlc.arg(start_at)::timestamptz AND e.ended_at < sqlc.arg(end_at)::timestamptz
GROUP BY e.automation_id
ORDER BY e.automation_id;

-- name: RecordExplanationView :exec
-- M2: the first read of a non-ALLOW decision's evidence.
INSERT INTO pc.explanation_views (org_id, transaction_id)
SELECT t.org_id, t.id FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id) AND t.decision <> 'ALLOW'
ON CONFLICT (org_id, transaction_id) DO NOTHING;
