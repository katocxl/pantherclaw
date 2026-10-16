-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Breach radius (G0 M10 D27–D31): what a computation reads, and the
-- snapshots it writes.

-- ExposureGrants lists the org's grants at their current revision: active
-- ones, those whose window ended and those revoked in the last 30 days
-- (EXPIRED reach is kept as history, D31).
-- name: ExposureGrants :many
SELECT g.id, g.agent_id, g.created_at, r.bounds, r.not_before, r.expires_at, r.delegation_depth, (g.state = 'REVOKED')::boolean AS revoked,
    ce.automation_id AS automation_id
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
-- An automation-issued grant names its ceiling's automation (D37a).
LEFT JOIN pc.automation_ceilings ce ON ce.org_id = g.org_id AND ce.id = g.ceiling_id
WHERE g.org_id = sqlc.arg(org_id)
  AND ((g.state = 'ACTIVE' AND r.expires_at > now() - interval '30 days')
       OR (g.state = 'REVOKED' AND g.revoked_at > now() - interval '30 days'))
ORDER BY g.id;

-- ExposureConnections lists the org's connections that are not retired,
-- with their pinned package, active credential and GitHub App reading.
-- name: ExposureConnections :many
SELECT c.id, c.name, c.state, c.access_mode, c.destination_class,
    v.raw AS package_raw,
    cr.kind AS credential_kind, cr.version AS credential_version, cr.created_at AS credential_created_at,
    gh.permissions AS github_permissions, gh.read_at AS github_read_at,
    cap.approved AS capabilities
FROM pc.connections c
LEFT JOIN pc.tool_packages tp ON tp.org_id = c.org_id AND tp.name = c.package
LEFT JOIN pc.package_pins p ON p.org_id = c.org_id AND p.package_id = tp.id
LEFT JOIN pc.package_versions v ON v.org_id = c.org_id AND v.id = p.version_id
LEFT JOIN pc.credentials cr ON cr.org_id = c.org_id AND cr.connection_id = c.id AND cr.state = 'ACTIVE'
LEFT JOIN pc.connection_github gh ON gh.org_id = c.org_id AND gh.connection_id = c.id
LEFT JOIN pc.connection_capabilities cap ON cap.org_id = c.org_id AND cap.connection_id = c.id AND cap.state = 'APPROVED'
WHERE c.org_id = sqlc.arg(org_id) AND c.state <> 'RETIRED'
ORDER BY c.id;

-- ExposureRouteAgents lists the agents with a coverage route on each
-- connection.
-- name: ExposureRouteAgents :many
SELECT DISTINCT connection_id, agent_id::uuid AS agent_id FROM pc.coverage_routes
WHERE org_id = sqlc.arg(org_id) AND agent_id IS NOT NULL
ORDER BY connection_id, agent_id;

-- ExposureOutsideRoutes lists the coverage routes that are not a channel.
-- name: ExposureOutsideRoutes :many
SELECT agent_id, connection_id, kind, operation FROM pc.coverage_routes
WHERE org_id = sqlc.arg(org_id) AND kind <> 'channel'
ORDER BY id;

-- ExposureCoverage is the latest coverage snapshot of every path.
-- name: ExposureCoverage :many
SELECT DISTINCT ON (agent_id, connection_id, operation) agent_id, connection_id, operation, state,
    expires_at
FROM pc.coverage_snapshots
WHERE org_id = sqlc.arg(org_id)
ORDER BY agent_id, connection_id, operation, id DESC;

-- ExposureDispatches counts the operations dispatched through each
-- connection per agent in the last 30 days.
-- name: ExposureDispatches :many
SELECT r.agent_id, t.connection_id::uuid AS connection_id, t.operation::text AS operation, count(*)::integer AS dispatches,
    max(t.created_at)::timestamptz AS last_at
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND t.connection_id IS NOT NULL AND t.created_at > now() - interval '30 days'
  AND EXISTS (SELECT 1 FROM pc.execution_attempts a WHERE a.org_id = t.org_id AND a.transaction_id = t.id)
GROUP BY r.agent_id, t.connection_id, t.operation
ORDER BY r.agent_id, t.connection_id, t.operation;

-- ExposureOverreach lists the open credential-overreach findings.
-- name: ExposureOverreach :many
SELECT id, connection_id, agent_id, subject, excess, severity FROM pc.coverage_findings
WHERE org_id = sqlc.arg(org_id) AND state = 'OPEN' AND kind = 'credential_overreach'
ORDER BY id;

-- ExposureAgents lists the org's agents with whether they have an owner.
-- name: ExposureAgents :many
SELECT id, (owner_user_id IS NOT NULL)::boolean AS owned FROM pc.agents
WHERE org_id = sqlc.arg(org_id)
ORDER BY id;

-- ExposureGrantLineage lists every grant delegated from each grant.
-- name: ExposureGrantLineage :many
SELECT ancestor_id, grant_id FROM pc.grant_lineage
WHERE org_id = sqlc.arg(org_id) AND distance > 0
ORDER BY ancestor_id, grant_id;

-- name: InsertExposureSnapshot :one
INSERT INTO pc.exposure_snapshots (org_id, id, feed_seq, cause, rights, truncated, gaps, rights_sha256)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(feed_seq), sqlc.arg(cause), sqlc.arg(rights), sqlc.arg(truncated),
    sqlc.arg(gaps), sqlc.arg(rights_sha256))
RETURNING computed_at;

-- InsertExposureRights inserts a batch of a snapshot's rights, given as a
-- JSON array of rows (COPY is not allowed under row-level security).
-- name: InsertExposureRights :exec
INSERT INTO pc.exposure_rights (org_id, snapshot_id, seq, reach_view, label, agent_id, connection_id, grant_id, operation,
    resource_group, verb, coverage, reasons, depth, expires_at, observed_at, observations, basis, irreversible, automation_id)
SELECT sqlc.arg(org_id), sqlc.arg(snapshot_id), x.seq, x.reach_view, x.label, x.agent_id, x.connection_id, x.grant_id,
    x.operation, x.resource_group, x.verb, x.coverage, COALESCE(x.reasons, '{}'), x.depth, x.expires_at, x.observed_at,
    x.observations, x.basis, x.irreversible, x.automation_id
FROM jsonb_to_recordset(sqlc.arg(rows)::jsonb) AS x(seq integer, reach_view text, label text, agent_id uuid,
    connection_id uuid, grant_id uuid, operation text, resource_group text, verb text, coverage text, reasons text[],
    depth smallint, expires_at timestamptz, observed_at timestamptz, observations integer, basis text, irreversible boolean,
    automation_id uuid);

-- LatestExposureSnapshot is the org's current snapshot, with whether a
-- change was recorded after it was computed.
-- name: LatestExposureSnapshot :one
SELECT s.id, s.feed_seq, s.cause, s.rights, s.truncated, s.gaps, s.rights_sha256, s.computed_at,
    COALESCE(ch.changed_at > s.computed_at, false)::boolean AS stale,
    ch.changed_at AS changed_at
FROM pc.exposure_snapshots s
LEFT JOIN pc.exposure_changes ch ON ch.org_id = s.org_id
WHERE s.org_id = sqlc.arg(org_id)
ORDER BY s.computed_at DESC, s.id DESC
LIMIT 1;

-- ListExposureRights lists a snapshot's rights, optionally of one agent or
-- connection, in seq order after a cursor.
-- name: ListExposureRights :many
SELECT * FROM pc.exposure_rights
WHERE org_id = sqlc.arg(org_id) AND snapshot_id = sqlc.arg(snapshot_id) AND seq > sqlc.arg(after)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR agent_id = sqlc.narg(agent_id))
  AND (sqlc.narg(connection_id)::uuid IS NULL OR connection_id = sqlc.narg(connection_id))
ORDER BY seq
LIMIT sqlc.arg(max_rows);

-- RecordExposureChange records that the feed showed a change moving reach.
-- name: RecordExposureChange :exec
INSERT INTO pc.exposure_changes (org_id, change_seq, changed_at)
VALUES (sqlc.arg(org_id), sqlc.arg(change_seq), now())
ON CONFLICT (org_id) DO UPDATE SET change_seq = GREATEST(pc.exposure_changes.change_seq, EXCLUDED.change_seq),
    changed_at = now();

-- AdvanceExposureRead moves the recompute job's feed position forward,
-- compare-and-set.
-- name: AdvanceExposureRead :execrows
INSERT INTO pc.exposure_changes (org_id, read_seq, changed_at)
VALUES (sqlc.arg(org_id), sqlc.arg(read_seq), 'epoch')
ON CONFLICT (org_id) DO UPDATE SET read_seq = EXCLUDED.read_seq
WHERE pc.exposure_changes.read_seq = sqlc.arg(expected);

-- name: GetExposureChanges :one
SELECT * FROM pc.exposure_changes WHERE org_id = sqlc.arg(org_id);

-- PruneExposureSnapshots deletes snapshots older than the given time that
-- are neither the latest nor a finding's evidence.
-- name: PruneExposureSnapshots :execrows
DELETE FROM pc.exposure_snapshots s
WHERE s.org_id = sqlc.arg(org_id) AND s.computed_at < sqlc.arg(before)
  AND s.id <> (SELECT id FROM pc.exposure_snapshots l WHERE l.org_id = sqlc.arg(org_id)
               ORDER BY l.computed_at DESC, l.id DESC LIMIT 1)
  AND NOT EXISTS (SELECT 1 FROM pc.posture_findings f WHERE f.org_id = s.org_id
                  AND (f.last_snapshot_id = s.id OR f.remediated_snapshot_id = s.id))
  AND NOT EXISTS (SELECT 1 FROM pc.posture_finding_events e WHERE e.org_id = s.org_id AND e.snapshot_id = s.id);

-- name: ExposureCredentialConnection :one
SELECT connection_id FROM pc.credentials WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ExposureRunGrant :one
SELECT agent_id, grant_id FROM pc.runs WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- ExposurePrincipalGrants lists the active grants that represent a person.
-- name: ExposurePrincipalGrants :many
SELECT id FROM pc.grants
WHERE org_id = sqlc.arg(org_id) AND principal_user_id = sqlc.arg(user_id) AND state = 'ACTIVE'
ORDER BY id;

-- GraphActivity lists the transactions of a run (and its child runs) or
-- of agents, in a window, oldest first, with their latest execution
-- outcome and whether a decision receipt was recorded.
-- name: GraphActivity :many
SELECT t.id, t.run_id, r.agent_id, r.parent_run_id, p.agent_id AS parent_agent_id, r.principal_user_id, t.operation::text AS operation,
    COALESCE(t.target_type, '')::text AS target_type, t.decision, t.effect_state, t.created_at,
    COALESCE((SELECT a.outcome FROM pc.execution_attempts a WHERE a.org_id = t.org_id AND a.transaction_id = t.id
     ORDER BY a.id DESC LIMIT 1), '')::text AS outcome,
    EXISTS (SELECT 1 FROM pc.decision_receipts d WHERE d.org_id = t.org_id AND d.transaction_id = t.id)::boolean AS has_receipt
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.runs p ON p.org_id = r.org_id AND p.id = r.parent_run_id
WHERE t.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(run_id)::uuid IS NULL OR t.run_id = sqlc.narg(run_id) OR r.parent_run_id = sqlc.narg(run_id))
  AND (sqlc.arg(all_agents)::boolean OR r.agent_id = ANY (sqlc.arg(agent_ids)::uuid[]))
  AND t.created_at >= sqlc.arg(start_time) AND t.created_at <= sqlc.arg(end_time)
ORDER BY t.created_at, t.id
LIMIT sqlc.arg(max_rows);

-- GraphGrantChanges lists the revisions of agents' grants in a window.
-- name: GraphGrantChanges :many
SELECT g.id AS grant_id, g.agent_id, r.revision, r.created_by, r.created_at,
    (r.revision = g.current_revision AND g.state = 'ACTIVE')::boolean AS current
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id
WHERE g.org_id = sqlc.arg(org_id)
  AND (sqlc.arg(all_agents)::boolean OR g.agent_id = ANY (sqlc.arg(agent_ids)::uuid[]))
  AND r.created_at >= sqlc.arg(start_time) AND r.created_at <= sqlc.arg(end_time)
ORDER BY r.created_at, g.id
LIMIT sqlc.arg(max_rows);

-- IncidentAgents lists the agents an incident's alerts are about.
-- name: IncidentAgents :many
SELECT DISTINCT (s ->> 'id')::text AS agent_id
FROM pc.alerts a, jsonb_array_elements(a.subjects) s
WHERE a.org_id = sqlc.arg(org_id) AND a.incident_id = sqlc.arg(incident_id) AND s ->> 'type' = 'agent'
ORDER BY 1;

-- ExposureCeilings lists the org's ACTIVE issuance ceilings before their
-- review date, with the version that defines their bounds and agents
-- (D37a). Any other ceiling can issue nothing and has no reach.
-- name: ExposureCeilings :many
SELECT c.id, c.automation_id, c.review_by, v.definition
FROM pc.automation_ceilings c
JOIN pc.automation_versions v ON v.org_id = c.org_id AND v.id = c.version_id
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'ACTIVE' AND c.review_by > now()
ORDER BY c.id;
