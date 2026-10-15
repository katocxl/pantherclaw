-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Operations surface (G0 M10 D33; F211, F212, F219; HR-258). Each query
-- returns the agents a row is about, so the caller filters by the viewer's
-- scope before ranking or counting (D8). Each reads at most 1000 rows; a
-- full read is reported as truncated, never as complete.

-- name: OpsActiveIncidents :many
SELECT i.id, i.title, i.severity, i.state, i.owner_id, i.created_at, i.updated_at, i.test,
       coalesce((SELECT array_agg(DISTINCT s ->> 'id')
                 FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                 WHERE a.org_id = i.org_id AND a.incident_id = i.id AND s ->> 'type' = 'agent'), '{}')::text[] AS agents
FROM pc.incidents i
WHERE i.org_id = $1 AND i.state <> 'RESOLVED'
ORDER BY i.id DESC
LIMIT 1000;

-- name: OpsOpenAlerts :many
-- Open alerts not yet attached to an incident (attached ones are listed
-- with their incident).
SELECT a.id, a.title, a.severity, a.attention, a.state, a.source, a.rule_id, a.count, a.first_seen, a.last_seen, a.test,
       coalesce((SELECT array_agg(DISTINCT s ->> 'id') FROM jsonb_array_elements(a.subjects) s
                 WHERE s ->> 'type' = 'agent'), '{}')::text[] AS agents
FROM pc.alerts a
WHERE a.org_id = $1 AND a.state IN ('OPEN', 'ACKNOWLEDGED') AND a.incident_id IS NULL
  AND a.attention IN ('ALERT', 'INCIDENT', 'PAGE')
ORDER BY a.id DESC
LIMIT 1000;

-- name: OpsWaitingApprovals :many
-- Approval requests still waiting for a person, soonest deadline first.
SELECT a.id, a.agent_id, a.operation, a.state, a.created_at, a.deadline_at, a.transaction_id
FROM pc.approval_requests a
WHERE a.org_id = $1 AND a.state IN ('PENDING', 'EVIDENCE_REQUESTED') AND a.deadline_at > now()
ORDER BY a.deadline_at
LIMIT 1000;

-- name: OpsOpenFailures :many
SELECT f.id, f.kind, f.summary, f.next_step, f.scope, f.owner_type, f.owner_id, f.deadline, f.state, f.count,
       f.first_seen, f.last_seen,
       coalesce((SELECT array_agg(DISTINCT s ->> 'id') FROM jsonb_array_elements(f.scope) s
                 WHERE s ->> 'type' = 'agent'), '{}')::text[] AS agents
FROM pc.operational_failures f
WHERE f.org_id = $1 AND f.state <> 'RESOLVED'
ORDER BY f.id DESC
LIMIT 1000;

-- name: OpsAuthorityExpansion :many
-- New grants and widening revisions since a time.
SELECT v.id, v.grant_id, g.agent_id, v.revision, v.widens, v.created_by, v.created_at
FROM pc.grant_revisions v
JOIN pc.grants g ON g.org_id = v.org_id AND g.id = v.grant_id
WHERE v.org_id = sqlc.arg(org_id) AND g.state = 'ACTIVE' AND (v.widens OR v.revision = 1)
  AND v.created_at >= sqlc.arg(since)::timestamptz
ORDER BY v.id DESC
LIMIT 1000;

-- name: OpsGatewaysLastSeen :many
-- (The epoch stands for never.)
-- Each active gateway with the last time it was seen: its latest decision
-- request or certificate renewal.
SELECT g.id, g.name, g.created_at,
       coalesce(greatest((SELECT max(t.created_at) FROM pc.transactions t WHERE t.org_id = g.org_id AND t.gateway_id = g.id::text),
                (SELECT max(c.issued_at) FROM pc.gateway_certs c WHERE c.org_id = g.org_id AND c.gateway_id = g.id)), 'epoch')::timestamptz
           AS last_seen
FROM pc.gateways g
WHERE g.org_id = $1 AND g.state = 'ACTIVE'
ORDER BY g.id;

-- name: OpsChannelLastSeen :one
-- The last transaction through a channel among the viewer's agents.
SELECT coalesce(max(t.created_at), 'epoch')::timestamptz AS last_seen
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND t.channel = sqlc.arg(channel)::text
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]));

-- name: OpsLedgerKindLastSeen :one
SELECT coalesce(max(e.occurred_at), 'epoch')::timestamptz AS last_seen
FROM pc.ledger_entries e
WHERE e.org_id = $1 AND e.kind = $2;

-- name: OpsChainState :one
SELECT coalesce(max(c.seq), 0)::bigint AS head, coalesce(max(c.chained_at), 'epoch')::timestamptz AS last_chained
FROM pc.ledger_chain c
WHERE c.org_id = $1;

-- name: OpsDetectionCursor :one
SELECT d.seq, d.updated_at FROM pc.detection_cursors d WHERE d.org_id = $1;

-- name: OpsDBNow :one
SELECT now()::timestamptz AS now;
