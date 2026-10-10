-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Agent Waitlist reads (PN-004.1), by priority and then deadline. Entries are
-- decided by the service that owns their subject. evidence holds two
-- objects, "trusted" (established by PantherClaw) and "untrusted" (reported
-- by a workload or observed at a gateway), which are never mixed.

-- name: ListWaitlistEntries :many
SELECT e.* FROM pc.waitlist_entries e
WHERE e.org_id = sqlc.arg(org_id) AND e.state = ANY (sqlc.arg(states)::text[])
  AND (sqlc.narg(agent_id)::uuid IS NULL OR e.agent_id = sqlc.narg(agent_id)::uuid)
  AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR e.kind = ANY (sqlc.arg(kinds)::text[]))
  AND (cardinality(sqlc.arg(priorities)::smallint[]) = 0 OR e.priority = ANY (sqlc.arg(priorities)::smallint[]))
  AND (sqlc.narg(assignee)::uuid IS NULL OR e.assignee_user_id = sqlc.narg(assignee)::uuid)
  AND (NOT sqlc.arg(overdue)::boolean
       OR (e.state = 'OPEN' AND (e.next_step_at <= now() OR e.deadline_at - now() <= (e.deadline_at - e.created_at) / 10)))
  AND (sqlc.narg(after)::uuid IS NULL OR (e.priority, e.deadline_at, e.id) >
       (SELECT a.priority, a.deadline_at, a.id FROM pc.waitlist_entries a WHERE a.org_id = e.org_id AND a.id = sqlc.narg(after)::uuid))
ORDER BY e.priority, e.deadline_at, e.id
LIMIT sqlc.arg(page_limit);

-- name: GetWaitlistEntry :one
SELECT * FROM pc.waitlist_entries WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- Producers (G0 M5 part 2 slice 210). Each entry is opened in the
-- transaction that creates its subject; there is at most one open entry per
-- subject, so a producer that finds one returns it.
-- name: OpenWaitlistEntry :one
INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id, transaction_id, requested_by,
    evidence, priority, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(subject_type), sqlc.arg(subject_id), sqlc.narg(agent_id),
    sqlc.narg(run_id), sqlc.narg(transaction_id), sqlc.narg(requested_by), sqlc.arg(evidence), sqlc.arg(priority),
    sqlc.arg(deadline_at))
ON CONFLICT (org_id, subject_type, subject_id) WHERE state = 'OPEN' DO NOTHING
RETURNING id;

-- name: OpenEntryOf :one
SELECT id FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND subject_type = sqlc.arg(subject_type) AND subject_id = sqlc.arg(subject_id)
  AND state = 'OPEN';

-- name: CloseEntryOf :execrows
UPDATE pc.waitlist_entries
SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_at = now(), decision_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND subject_type = sqlc.arg(subject_type)
  AND subject_id = sqlc.arg(subject_id) AND state = 'OPEN';

-- An unknown outcome's run and agent, for its RECONCILIATION entry.
-- name: TransactionOfRun :one
SELECT t.run_id, r.agent_id, t.operation
FROM pc.transactions t JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id);

-- Open entries past their deadline whose kind ends there (HR-177): an
-- access request or a tool review changes nothing when it expires.
-- name: ExpireWaitlistEntries :many
UPDATE pc.waitlist_entries
SET state = 'EXPIRED', decided_by = 'system', decided_at = now(), decision_reason = 'EXPIRED'
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN' AND kind = ANY (sqlc.arg(kinds)::text[]) AND deadline_at <= now()
RETURNING id, kind;

-- Assignment only shows who is working on an entry (HR-177).
-- name: AssignWaitlistEntry :execrows
UPDATE pc.waitlist_entries
SET assignee_user_id = sqlc.narg(assignee), assigned_at = CASE WHEN sqlc.narg(assignee)::uuid IS NULL THEN NULL ELSE now() END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN';

-- Access requests (decision 10). They grant nothing: a grant revision
-- citing the entry settles it, or a grant.issue holder dismisses it.
-- name: SettleAccessRequest :execrows
UPDATE pc.waitlist_entries
SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_at = now(), decision_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'ACCESS_REQUEST' AND subject_type = 'grant'
  AND subject_id = sqlc.arg(grant_id) AND state = 'OPEN';

-- name: CountWorkloadAccessRequests :one
SELECT count(*)::integer FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND run_id = sqlc.arg(run_id) AND kind = 'ACCESS_REQUEST' AND requested_by LIKE 'instance:%';

-- A transaction of the run, with its decision and decisive reason.
-- name: RunTransaction :one
SELECT decision, reason_code FROM pc.transactions
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND run_id = sqlc.arg(run_id);

-- name: GrantCurrentRevision :one
SELECT current_revision FROM pc.grants WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- Routing (G0 M5 part 2 slice 211, HR-173, decision 8). An open entry that
-- has taken no escalation step has not been routed yet.
-- name: UnroutedEntries :many
SELECT id FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN' AND escalation_step = 0
ORDER BY priority, deadline_at, id
LIMIT sqlc.arg(lim);

-- name: EntryForRouting :one
SELECT e.id, e.kind, e.subject_type, e.subject_id, e.agent_id, e.requested_by, e.deadline_at, e.created_at, e.escalation_step,
       a.team_id, t.business_unit_id, a.environment_id
FROM pc.waitlist_entries e
LEFT JOIN pc.agents a ON a.org_id = e.org_id AND a.id = e.agent_id
LEFT JOIN pc.teams t ON t.org_id = a.org_id AND t.id = a.team_id
WHERE e.org_id = sqlc.arg(org_id) AND e.id = sqlc.arg(id) AND e.state = 'OPEN'
FOR UPDATE OF e;

-- The enabled people holding one of roles where the agent lives, with the
-- rank of their nearest binding: 0 environment or team, 1 business unit,
-- 2 org. An entry about no agent matches org bindings only.
-- name: DeciderCandidates :many
SELECT b.user_id::uuid AS user_id,
       min(CASE b.scope_type WHEN 'ORG' THEN 2 WHEN 'BUSINESS_UNIT' THEN 1 ELSE 0 END)::integer AS rank
FROM pc.role_bindings b
JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id AND u.state = 'ACTIVE'
WHERE b.org_id = sqlc.arg(org_id) AND b.role = ANY (sqlc.arg(roles)::text[])
  AND (b.scope_type = 'ORG'
    OR (b.scope_type = 'BUSINESS_UNIT' AND b.business_unit_id = sqlc.narg(business_unit_id)::uuid)
    OR (b.scope_type = 'TEAM' AND b.team_id = sqlc.narg(team_id)::uuid)
    OR (b.scope_type = 'ENVIRONMENT' AND b.environment_id = sqlc.narg(environment_id)::uuid))
GROUP BY b.user_id
ORDER BY rank, b.user_id
LIMIT sqlc.arg(lim);

-- name: InsertWaitlistRoute :exec
INSERT INTO pc.waitlist_routes (org_id, id, entry_id, step, kind, user_id, channel_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(entry_id), sqlc.arg(step), sqlc.arg(kind), sqlc.narg(user_id),
    sqlc.narg(channel_id));

-- name: SetEntryRouting :execrows
UPDATE pc.waitlist_entries
SET routing_health = sqlc.arg(health), escalation_step = sqlc.arg(step), next_step_at = sqlc.narg(next_step_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN';

-- The enabled people holding one of roles at org scope (the org's admins
-- for an unroutable entry).
-- name: OrgUsersWithRoles :many
SELECT DISTINCT u.id
FROM pc.role_bindings b
JOIN pc.users u ON u.org_id = b.org_id AND u.id = b.user_id
WHERE b.org_id = sqlc.arg(org_id) AND b.role = ANY (sqlc.arg(roles)::text[]) AND b.scope_type = 'ORG' AND u.state = 'ACTIVE'
ORDER BY u.id
LIMIT 50;

-- Escalation (slice 211b, decision 8). escalation_step counts the steps an
-- entry has taken; 0 means it has not been routed yet.
-- name: CurrentChain :one
SELECT revision, steps, created_by, created_at FROM pc.escalation_chains
WHERE org_id = sqlc.arg(org_id) AND team_id IS NOT DISTINCT FROM sqlc.narg(team_id)::uuid
ORDER BY revision DESC
LIMIT 1;

-- name: InsertChain :exec
INSERT INTO pc.escalation_chains (org_id, id, team_id, revision, steps, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.narg(team_id), sqlc.arg(revision), sqlc.arg(steps), sqlc.arg(created_by));

-- name: DueEscalations :many
SELECT id FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN' AND escalation_step > 0 AND next_step_at <= now()
  AND deadline_at > now()
ORDER BY priority, next_step_at, id
LIMIT sqlc.arg(lim);

-- name: EntryRecipients :many
SELECT DISTINCT user_id::uuid AS user_id FROM pc.waitlist_routes
WHERE org_id = sqlc.arg(org_id) AND entry_id = sqlc.arg(entry_id) AND user_id IS NOT NULL;

-- The routed open entries whose health is OK, to check their deliveries.
-- name: HealthyRoutedEntries :many
SELECT id FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN' AND escalation_step > 0 AND routing_health = 'OK'
ORDER BY id
LIMIT 500;

-- A failed delivery of an open entry's notice marks it DELIVERY_FAILING;
-- it never counts as a decision (HR-039).
-- name: MarkDeliveryFailing :many
UPDATE pc.waitlist_entries SET routing_health = 'DELIVERY_FAILING'
WHERE org_id = sqlc.arg(org_id) AND id = ANY (sqlc.arg(entry_ids)::uuid[]) AND state = 'OPEN' AND routing_health = 'OK'
RETURNING id;

-- Settings (slice 213): one row per org; NULL means the default. The
-- schema keeps each value within its decision-6 and decision-7 bounds.
-- name: UpsertWaitlistSettings :exec
INSERT INTO pc.waitlist_settings (org_id, batch_ceilings, hold_deadline_s, consume_window_s, access_request_deadline_s,
    tool_review_deadline_s, restoration_deadline_s, reconciliation_deadline_s, max_holds_per_grant, max_holds_per_run,
    min_account_age_s, min_role_age_s, min_credential_age_s, self_grant_delay_s, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(batch_ceilings), sqlc.narg(hold_deadline_s), sqlc.narg(consume_window_s),
    sqlc.narg(access_request_deadline_s), sqlc.narg(tool_review_deadline_s), sqlc.narg(restoration_deadline_s),
    sqlc.narg(reconciliation_deadline_s), sqlc.narg(max_holds_per_grant), sqlc.narg(max_holds_per_run),
    sqlc.narg(min_account_age_s), sqlc.narg(min_role_age_s), sqlc.narg(min_credential_age_s), sqlc.narg(self_grant_delay_s),
    sqlc.arg(updated_by))
ON CONFLICT (org_id) DO UPDATE SET
    batch_ceilings = EXCLUDED.batch_ceilings, hold_deadline_s = EXCLUDED.hold_deadline_s,
    consume_window_s = EXCLUDED.consume_window_s, access_request_deadline_s = EXCLUDED.access_request_deadline_s,
    tool_review_deadline_s = EXCLUDED.tool_review_deadline_s, restoration_deadline_s = EXCLUDED.restoration_deadline_s,
    reconciliation_deadline_s = EXCLUDED.reconciliation_deadline_s, max_holds_per_grant = EXCLUDED.max_holds_per_grant,
    max_holds_per_run = EXCLUDED.max_holds_per_run, min_account_age_s = EXCLUDED.min_account_age_s,
    min_role_age_s = EXCLUDED.min_role_age_s, min_credential_age_s = EXCLUDED.min_credential_age_s,
    self_grant_delay_s = EXCLUDED.self_grant_delay_s, updated_by = EXCLUDED.updated_by, updated_at = now();

-- SLA metrics (slice 214c, Team). An entry's first response is the first
-- response to its approval request, or else a person's decision; its time
-- to decision counts approvals and rejections only. Entries are kept to
-- the agents the caller may read before anything is aggregated (T-042).
-- name: WaitlistMetricAgents :many
SELECT DISTINCT agent_id::uuid AS agent_id FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND created_at >= sqlc.arg(since) AND created_at < sqlc.arg(until) AND agent_id IS NOT NULL
LIMIT 10000;

-- name: WaitlistMetricsByKind :many
WITH e AS (
    SELECT e.kind, e.state, e.escalation_step, e.routing_health,
        extract(epoch FROM COALESCE(e.first_response_at,
            CASE WHEN e.state IN ('APPROVED', 'REJECTED') AND e.decided_by LIKE 'user:%' THEN e.decided_at END) - e.created_at)
            AS first_s,
        CASE WHEN e.state IN ('APPROVED', 'REJECTED') THEN extract(epoch FROM e.decided_at - e.created_at) END AS decision_s
    FROM pc.waitlist_entries e
    WHERE e.org_id = sqlc.arg(org_id) AND e.created_at >= sqlc.arg(since) AND e.created_at < sqlc.arg(until)
      AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR e.kind = ANY (sqlc.arg(kinds)::text[]))
      AND (sqlc.arg(all_agents)::boolean OR e.agent_id = ANY (sqlc.arg(agents)::uuid[]))
)
SELECT kind, count(*) AS entries, count(decision_s) AS decided,
    COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY first_s), 0)::float8 AS first_p50,
    COALESCE(percentile_cont(0.9) WITHIN GROUP (ORDER BY first_s), 0)::float8 AS first_p90,
    COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY decision_s), 0)::float8 AS decision_p50,
    COALESCE(percentile_cont(0.9) WITHIN GROUP (ORDER BY decision_s), 0)::float8 AS decision_p90,
    avg((state = 'EXPIRED')::int)::float8 AS expiry_rate,
    avg((escalation_step >= 2)::int)::float8 AS escalation_rate,
    count(*) FILTER (WHERE routing_health <> 'OK') AS routing_failures
FROM e
GROUP BY kind
ORDER BY kind;

-- A decider is a person who responded to an entry's approval request or
-- decided the entry; their first response is their own.
-- name: WaitlistMetricsByDecider :many
WITH e AS (
    SELECT e.id, e.kind, e.state, e.subject_type, e.subject_id, e.decided_by, e.decided_at, e.created_at, e.escalation_step,
        e.routing_health
    FROM pc.waitlist_entries e
    WHERE e.org_id = sqlc.arg(org_id) AND e.created_at >= sqlc.arg(since) AND e.created_at < sqlc.arg(until)
      AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR e.kind = ANY (sqlc.arg(kinds)::text[]))
      AND (sqlc.arg(all_agents)::boolean OR e.agent_id = ANY (sqlc.arg(agents)::uuid[]))
), acts AS (
    SELECT e.id, r.user_id, r.created_at AS at
    FROM e JOIN pc.approval_responses r ON r.org_id = sqlc.arg(org_id) AND r.request_id = e.subject_id
    WHERE e.subject_type = 'approval_request'
    UNION ALL
    SELECT e.id, substring(e.decided_by FROM 6)::uuid, e.decided_at FROM e
    WHERE e.state IN ('APPROVED', 'REJECTED') AND e.decided_by ~ '^user:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
), per AS (
    SELECT id, user_id, min(at) AS at FROM acts GROUP BY id, user_id
)
SELECT e.kind, per.user_id::uuid AS user_id, count(*) AS entries,
    count(*) FILTER (WHERE e.state IN ('APPROVED', 'REJECTED')) AS decided,
    COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM per.at - e.created_at)), 0)::float8 AS first_p50,
    COALESCE(percentile_cont(0.9) WITHIN GROUP (ORDER BY extract(epoch FROM per.at - e.created_at)), 0)::float8 AS first_p90,
    COALESCE(percentile_cont(0.5) WITHIN GROUP (ORDER BY CASE WHEN e.state IN ('APPROVED', 'REJECTED')
        THEN extract(epoch FROM e.decided_at - e.created_at) END), 0)::float8 AS decision_p50,
    COALESCE(percentile_cont(0.9) WITHIN GROUP (ORDER BY CASE WHEN e.state IN ('APPROVED', 'REJECTED')
        THEN extract(epoch FROM e.decided_at - e.created_at) END), 0)::float8 AS decision_p90,
    avg((e.state = 'EXPIRED')::int)::float8 AS expiry_rate,
    avg((e.escalation_step >= 2)::int)::float8 AS escalation_rate,
    count(*) FILTER (WHERE e.routing_health <> 'OK') AS routing_failures
FROM per JOIN e ON e.id = per.id
GROUP BY e.kind, per.user_id
ORDER BY e.kind, per.user_id
LIMIT 1000;

-- Entries decided or expired in [since, until), for the server's
-- histograms (no org leaves the query); first_s is -1 when nobody
-- responded.
-- name: ClosedEntriesBetween :many
SELECT kind, state,
    COALESCE(extract(epoch FROM COALESCE(first_response_at,
        CASE WHEN state IN ('APPROVED', 'REJECTED') AND decided_by LIKE 'user:%' THEN decided_at END) - created_at), -1)::float8
        AS first_s,
    extract(epoch FROM decided_at - created_at)::float8 AS decision_s
FROM pc.waitlist_entries
WHERE org_id = sqlc.arg(org_id) AND state IN ('APPROVED', 'REJECTED', 'EXPIRED') AND decided_at >= sqlc.arg(since)
  AND decided_at < sqlc.arg(until)
LIMIT 10000;
