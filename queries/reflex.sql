-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Reflex core queries (G0 M10 D2, D10, D14–D18). Every query runs inside
-- db.InTenantTx and also filters by org_id explicitly.

-- name: FeedTransactions :many
-- The context of the transactions a feed batch names: run, agent, instance,
-- environment, grant, principal, operation, connection and its class.
SELECT t.id, t.run_id, r.agent_id, r.instance_id, r.environment_id, r.grant_id, r.principal_user_id,
       r.principal_sa_id, r.parent_run_id, r.depth, t.operation, t.connection_id, t.mode, t.budget_id, t.simulated,
       coalesce(c.destination_class, '')::text AS destination_class
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.connections c ON c.org_id = t.org_id AND c.id = t.connection_id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = ANY (sqlc.arg(ids)::uuid[]);

-- name: FeedHead :one
SELECT coalesce((SELECT seq FROM pc.ledger_heads WHERE org_id = sqlc.arg(org_id)), 0)::bigint AS seq;

-- name: UpsertAlert :one
-- A new alert, or a repeat of the open one with the same dedupe key: the
-- repeat counts and moves last_seen, nothing else (HR-243).
INSERT INTO pc.alerts (org_id, id, source, rule_id, rule_version, rule_digest, pack_version, title, summary, severity,
                       attention, basis, subjects, atlas, owasp, facts, group_key, dedupe_key, state, suppression_id,
                       first_seen, last_seen, test)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(source), sqlc.arg(rule_id), sqlc.arg(rule_version), sqlc.arg(rule_digest),
        sqlc.arg(pack_version), sqlc.arg(title), sqlc.arg(summary), sqlc.arg(severity), sqlc.arg(attention), sqlc.arg(basis),
        sqlc.arg(subjects), sqlc.arg(atlas)::text[], sqlc.arg(owasp)::text[], sqlc.arg(facts), sqlc.arg(group_key),
        sqlc.arg(dedupe_key), sqlc.arg(state), sqlc.narg(suppression_id), sqlc.arg(occurred_at), sqlc.arg(occurred_at),
        sqlc.arg(test))
ON CONFLICT (org_id, dedupe_key) WHERE state IN ('OPEN', 'ACKNOWLEDGED', 'SUPPRESSED')
DO UPDATE SET count = pc.alerts.count + 1, last_seen = greatest(pc.alerts.last_seen, EXCLUDED.last_seen),
              updated_at = now()
RETURNING id, state, severity, incident_id, suppression_id, count, (xmax = 0) AS inserted;

-- name: InsertAlertEvidence :exec
INSERT INTO pc.alert_evidence (org_id, id, alert_id, kind, ref_id, occurred_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(alert_id), sqlc.arg(kind), sqlc.arg(ref_id), sqlc.arg(occurred_at));

-- name: InsertAlertEvent :exec
INSERT INTO pc.alert_events (org_id, id, alert_id, kind, actor_type, actor_id, from_value, to_value, note)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(alert_id), sqlc.arg(kind), sqlc.arg(actor_type), sqlc.arg(actor_id),
        sqlc.narg(from_value), sqlc.narg(to_value), sqlc.narg(note));

-- name: UpsertFailure :one
-- A new owned failure, or a repeat of the open one with the same dedupe
-- key, which counts and moves last_seen.
INSERT INTO pc.operational_failures (org_id, id, kind, summary, next_step, scope, owner_type, owner_id, deadline, dedupe_key,
                                     state)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(summary), sqlc.arg(next_step), sqlc.arg(scope),
        sqlc.narg(owner_type), sqlc.narg(owner_id), sqlc.arg(deadline), sqlc.arg(dedupe_key), sqlc.arg(state))
ON CONFLICT (org_id, dedupe_key) WHERE state <> 'RESOLVED'
DO UPDATE SET count = pc.operational_failures.count + 1, last_seen = now()
RETURNING id, (xmax = 0) AS inserted;

-- name: ScopeAgentPlacements :many
-- Every agent's placement, for computing the agents a scoped viewer may
-- read (D60); at most max_rows.
SELECT id, team_id, environment_id FROM pc.agents
WHERE org_id = sqlc.arg(org_id)
ORDER BY id
LIMIT sqlc.arg(max_rows);
