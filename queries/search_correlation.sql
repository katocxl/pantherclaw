-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Incident correlation (G0 M11 part 2 coordinator decision D47; F316):
-- what an incident's runs share with other runs in a window. Sharing is a
-- correlation, never a cause. A scoped viewer sees only visible agents'
-- runs, filtered before every limit (D60).

-- The runs an incident is about: run subjects of its alerts and the runs
-- of its alerts' run and transaction evidence.
-- name: CorrIncidentRuns :many
SELECT r.id, r.agent_id, r.created_at
FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id)
  AND (r.id::text IN (SELECT s ->> 'id' FROM pc.alerts a, jsonb_array_elements(a.subjects) s
                      WHERE a.org_id = sqlc.arg(org_id) AND a.incident_id = sqlc.arg(incident_id) AND s ->> 'type' = 'run')
       OR r.id IN (SELECT e.ref_id FROM pc.alert_evidence e
                   JOIN pc.alerts a ON a.org_id = e.org_id AND a.id = e.alert_id
                   WHERE e.org_id = sqlc.arg(org_id) AND a.incident_id = sqlc.arg(incident_id) AND e.kind = 'run')
       OR r.id IN (SELECT t.run_id FROM pc.alert_evidence e
                   JOIN pc.alerts a ON a.org_id = e.org_id AND a.id = e.alert_id
                   JOIN pc.transactions t ON t.org_id = e.org_id AND t.id = e.ref_id
                   WHERE e.org_id = sqlc.arg(org_id) AND a.incident_id = sqlc.arg(incident_id) AND e.kind = 'transaction'))
ORDER BY r.created_at, r.id
LIMIT 200;

-- The agents an incident's alerts name.
-- name: CorrIncidentAgents :many
SELECT DISTINCT g.id
FROM pc.alerts a, jsonb_array_elements(a.subjects) s, pc.agents g
WHERE a.org_id = sqlc.arg(org_id) AND a.incident_id = sqlc.arg(incident_id) AND s ->> 'type' = 'agent'
  AND g.org_id = a.org_id AND g.id::text = s ->> 'id'
ORDER BY g.id;

-- The runs a case links, directly or through a linked transaction.
-- name: CorrCaseRuns :many
SELECT r.id, r.agent_id, r.created_at
FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id)
  AND (r.id::text IN (SELECT lower(l.ref_id) FROM pc.case_entries l
                      WHERE l.org_id = sqlc.arg(org_id) AND l.case_id = sqlc.arg(case_id) AND l.kind = 'LINK'
                        AND l.ref_kind = 'run' AND NOT pc.case_entry_superseded(l.org_id, l.id))
       OR r.id IN (SELECT t.run_id FROM pc.case_entries l
                   JOIN pc.transactions t ON t.org_id = l.org_id AND t.id::text = lower(l.ref_id)
                   WHERE l.org_id = sqlc.arg(org_id) AND l.case_id = sqlc.arg(case_id) AND l.kind = 'LINK'
                     AND l.ref_kind = 'transaction' AND NOT pc.case_entry_superseded(l.org_id, l.id)))
ORDER BY r.created_at, r.id
LIMIT 200;

-- Other runs in the window that reached a destination host (the permit's
-- outbound URL, else the connection's base URL) one of the subject runs
-- reached, with the destination class of the connection used.
-- name: CorrSharedDestinations :many
SELECT t.run_id, r.agent_id, lower(substring(coalesce(p.outbound_url, c.base_url) FROM '^https?://([^/:?#@]+)'))::text AS host,
       min(c.destination_class)::text AS destination_class,
       (array_agg(c.id ORDER BY t.created_at))[1]::uuid AS connection_id, count(*)::bigint AS actions,
       min(t.created_at)::timestamptz AS first_at, max(t.created_at)::timestamptz AS last_at
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
JOIN pc.connections c ON c.org_id = t.org_id AND c.id = t.connection_id
LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id
WHERE t.org_id = sqlc.arg(org_id)
  AND NOT t.run_id = ANY (sqlc.arg(run_ids)::uuid[])
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND t.created_at >= sqlc.arg(start_time) AND t.created_at < sqlc.arg(end_time)
  AND lower(substring(coalesce(p.outbound_url, c.base_url) FROM '^https?://([^/:?#@]+)')) IN (
      SELECT lower(substring(coalesce(sp.outbound_url, sc.base_url) FROM '^https?://([^/:?#@]+)'))
      FROM pc.transactions st
      JOIN pc.connections sc ON sc.org_id = st.org_id AND sc.id = st.connection_id
      LEFT JOIN pc.permits sp ON sp.org_id = st.org_id AND sp.transaction_id = st.id
      WHERE st.org_id = sqlc.arg(org_id) AND st.run_id = ANY (sqlc.arg(run_ids)::uuid[]))
GROUP BY t.run_id, r.agent_id, 3
ORDER BY min(t.created_at), t.run_id
LIMIT 200;

-- Other runs in the window that used, on the same connection, a credential
-- version one of the subject runs used. Which version an action used is
-- inferred from the versions' lifetimes, never recorded per action.
-- name: CorrSharedCredentials :many
SELECT t.run_id, r.agent_id, cr.id AS credential_id, cr.connection_id, cr.version, count(*)::bigint AS actions,
       min(t.created_at)::timestamptz AS first_at, max(t.created_at)::timestamptz AS last_at
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
JOIN pc.credentials cr ON cr.org_id = t.org_id AND cr.connection_id = t.connection_id AND cr.created_at <= t.created_at
                      AND coalesce(cr.superseded_at, cr.revoked_at, 'infinity'::timestamptz) > t.created_at
WHERE t.org_id = sqlc.arg(org_id)
  AND NOT t.run_id = ANY (sqlc.arg(run_ids)::uuid[])
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND t.created_at >= sqlc.arg(start_time) AND t.created_at < sqlc.arg(end_time)
  AND cr.id IN (
      SELECT sr.id FROM pc.transactions st
      JOIN pc.credentials sr ON sr.org_id = st.org_id AND sr.connection_id = st.connection_id AND sr.created_at <= st.created_at
                            AND coalesce(sr.superseded_at, sr.revoked_at, 'infinity'::timestamptz) > st.created_at
      WHERE st.org_id = sqlc.arg(org_id) AND st.run_id = ANY (sqlc.arg(run_ids)::uuid[]))
GROUP BY t.run_id, r.agent_id, cr.id, cr.connection_id, cr.version
ORDER BY min(t.created_at), t.run_id
LIMIT 200;


-- The operations of the subject runs and of the other runs in the window,
-- in order, for the shared-sequence comparison (at most 500 runs, 200
-- operations each).
-- name: CorrRunOperations :many
SELECT t.run_id, r.agent_id,
       (array_agg(t.operation ORDER BY t.created_at, t.id))[1:200]::text[] AS operations,
       min(t.created_at)::timestamptz AS first_at, max(t.created_at)::timestamptz AS last_at
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agents)::uuid[]))
  AND (t.run_id = ANY (sqlc.arg(run_ids)::uuid[])
       OR (t.created_at >= sqlc.arg(start_time) AND t.created_at < sqlc.arg(end_time)))
GROUP BY t.run_id, r.agent_id
ORDER BY bool_or(t.run_id = ANY (sqlc.arg(run_ids)::uuid[])) DESC, min(t.created_at), t.run_id
LIMIT 501;

-- The connections the subject runs used.
-- name: CorrRunConnections :many
SELECT DISTINCT t.connection_id::uuid AS connection_id
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.run_id = ANY (sqlc.arg(run_ids)::uuid[]) AND t.connection_id IS NOT NULL
ORDER BY 1;
