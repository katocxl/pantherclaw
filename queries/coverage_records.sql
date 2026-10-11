-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Coverage records (G0 M9 track A; migration 00085). Everything runs as
-- pc_app in a tenant transaction. Closures and snapshots are only
-- inserted (HR-055).

-- A route seen again keeps its first sighting. A weaker sighting (proposed
-- after declared, declared after observed) changes nothing; one as strong
-- takes over its source, mode and attributes unless its reference is older
-- (source references are UUIDv7, so a replayed sighting is ignored). Only
-- observations are counted, each source reference once.
-- name: UpsertCoverageRoute :one
INSERT INTO pc.coverage_routes AS r (org_id, id, agent_id, connection_id, operation, kind, channel, locator, observation, source,
    source_ref, mode, attributes)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.narg(agent_id), sqlc.arg(connection_id), sqlc.narg(operation), sqlc.arg(kind),
    sqlc.narg(channel), sqlc.narg(locator), sqlc.arg(observation), sqlc.arg(source), sqlc.narg(source_ref), sqlc.narg(mode),
    sqlc.arg(attributes))
ON CONFLICT (org_id, connection_id, agent_id, operation, kind, channel, locator) DO UPDATE SET
    observation  = CASE WHEN pc.coverage_rank(EXCLUDED.observation) > pc.coverage_rank(r.observation)
                        THEN EXCLUDED.observation ELSE r.observation END,
    source       = CASE WHEN pc.coverage_rank(EXCLUDED.observation) > pc.coverage_rank(r.observation)
                          OR (EXCLUDED.observation = r.observation AND (EXCLUDED.source_ref < r.source_ref) IS NOT TRUE)
                        THEN EXCLUDED.source ELSE r.source END,
    source_ref   = CASE WHEN pc.coverage_rank(EXCLUDED.observation) > pc.coverage_rank(r.observation)
                        THEN coalesce(EXCLUDED.source_ref, r.source_ref)
                        WHEN EXCLUDED.observation = r.observation THEN greatest(r.source_ref, EXCLUDED.source_ref)
                        ELSE r.source_ref END,
    mode         = CASE WHEN pc.coverage_rank(EXCLUDED.observation) > pc.coverage_rank(r.observation)
                          OR (EXCLUDED.observation = r.observation AND (EXCLUDED.source_ref < r.source_ref) IS NOT TRUE)
                        THEN coalesce(EXCLUDED.mode, r.mode) ELSE r.mode END,
    attributes   = CASE WHEN pc.coverage_rank(EXCLUDED.observation) > pc.coverage_rank(r.observation)
                          OR (EXCLUDED.observation = r.observation AND (EXCLUDED.source_ref < r.source_ref) IS NOT TRUE)
                        THEN EXCLUDED.attributes ELSE r.attributes END,
    seen_count   = CASE WHEN EXCLUDED.observation <> 'observed' THEN r.seen_count
                        WHEN r.observation <> 'observed' THEN 1
                        WHEN (EXCLUDED.source_ref <= r.source_ref) IS NOT TRUE THEN r.seen_count + 1
                        ELSE r.seen_count END,
    last_seen_at = CASE WHEN EXCLUDED.observation = 'observed'
                          AND (r.observation <> 'observed' OR (EXCLUDED.source_ref <= r.source_ref) IS NOT TRUE)
                        THEN now() ELSE r.last_seen_at END
RETURNING *;

-- The routes of one scope: its own rows and those that apply to every
-- agent or every operation of the connection.
-- name: CoverageRoutesForScope :many
SELECT * FROM pc.coverage_routes
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
  AND (agent_id IS NULL OR agent_id = sqlc.arg(agent_id))
  AND (operation IS NULL OR operation = sqlc.arg(operation)::text)
ORDER BY kind, channel NULLS FIRST, locator NULLS FIRST, id;

-- An agent's routes include those of every agent of the connection.
-- name: ListCoverageRoutesPage :many
SELECT * FROM pc.coverage_routes
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(connection_id)::uuid IS NULL OR connection_id = sqlc.narg(connection_id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR agent_id = sqlc.narg(agent_id)::uuid OR agent_id IS NULL)
  AND (sqlc.narg(after)::uuid IS NULL OR id > sqlc.narg(after)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- A replayed result set (the same server nonce) inserts nothing, so the
-- caller's transaction stays usable (HR-215).
-- name: InsertCoverageClosure :one
INSERT INTO pc.coverage_closures (org_id, id, agent_id, connection_id, sandbox_session_id, result, probes,
    positive_controls_passed, negative_controls_passed, canary_passed, signing_key_jkt, server_nonce, results_sha256,
    engine_version, api_version, runtime, image_digests, config_sha256, config_checks, gateway_id, connection_revision,
    package_version_id, credential_version, session_started_at, observed_at, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(connection_id), sqlc.arg(sandbox_session_id),
    sqlc.arg(result), sqlc.arg(probes), sqlc.arg(positive_controls_passed), sqlc.arg(negative_controls_passed),
    sqlc.arg(canary_passed), sqlc.arg(signing_key_jkt), sqlc.arg(server_nonce), sqlc.arg(results_sha256),
    sqlc.arg(engine_version), sqlc.arg(api_version), sqlc.arg(runtime), sqlc.arg(image_digests)::text[],
    sqlc.arg(config_sha256), sqlc.arg(config_checks), sqlc.arg(gateway_id), sqlc.arg(connection_revision),
    sqlc.arg(package_version_id), sqlc.narg(credential_version), sqlc.arg(session_started_at), sqlc.arg(observed_at),
    sqlc.arg(expires_at))
ON CONFLICT (org_id, agent_id, connection_id, server_nonce) DO NOTHING
RETURNING *;

-- name: GetCoverageClosure :one
SELECT * FROM pc.coverage_closures WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- The newest closure of an agent and connection, passed or failed: a
-- failed newer closure supersedes an older pass.
-- name: LatestCoverageClosure :one
SELECT * FROM pc.coverage_closures
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND connection_id = sqlc.arg(connection_id)
ORDER BY id DESC
LIMIT 1;

-- name: ListCoverageClosuresPage :many
SELECT * FROM pc.coverage_closures
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(connection_id)::uuid IS NULL OR connection_id = sqlc.narg(connection_id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- What a closure is bound to now: the connection's revision and gateway,
-- its package's pinned version (NULL when nothing is pinned) and its
-- active credential's version.
-- name: CoverageBinding :one
SELECT c.revision, c.gateway_id, c.state, c.kind, c.access_mode, c.default_mode, p.version_id AS package_version_id,
    cr.version AS credential_version
FROM pc.connections c
LEFT JOIN pc.tool_packages tp ON tp.org_id = c.org_id AND tp.name = c.package
LEFT JOIN pc.package_pins p ON p.org_id = c.org_id AND p.package_id = tp.id
LEFT JOIN pc.credentials cr ON cr.org_id = c.org_id AND cr.connection_id = c.id AND cr.state = 'ACTIVE'
WHERE c.org_id = sqlc.arg(org_id) AND c.id = sqlc.arg(connection_id);

-- name: InsertCoverageInvalidation :one
INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, agent_id, subject_id, detail)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(connection_id), sqlc.narg(agent_id), sqlc.narg(subject_id),
    sqlc.narg(detail))
RETURNING *;

-- The changes to a scope at or after a point in time that invalidate a
-- closure taken before them, oldest first (HR-211). A new route, an
-- exclusion and an expiry only make the scope be recomputed: the closure
-- still closes what its probes closed.
-- name: CoverageInvalidationsSince :many
SELECT * FROM pc.coverage_invalidations
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
  AND (agent_id IS NULL OR agent_id = sqlc.arg(agent_id))
  AND occurred_at >= sqlc.arg(since)
  AND kind NOT IN ('route', 'exclusion', 'evidence_expired')
ORDER BY occurred_at, id
LIMIT 64;

-- name: PendingCoverageInvalidations :many
SELECT * FROM pc.coverage_invalidations
WHERE org_id = sqlc.arg(org_id) AND reassessed_at IS NULL
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: MarkCoverageInvalidationsReassessed :execrows
UPDATE pc.coverage_invalidations SET reassessed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = ANY (sqlc.arg(invalidation_ids)::uuid[]) AND reassessed_at IS NULL;

-- name: InsertCoverageSnapshot :one
INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, closure_id, last_valid_id,
    invalidation_id, body, body_sha256, ledger_entry_id, expires_at, computed_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(connection_id), sqlc.arg(operation), sqlc.arg(state),
    sqlc.arg(reasons)::text[], sqlc.narg(closure_id), sqlc.narg(last_valid_id), sqlc.narg(invalidation_id), sqlc.arg(body),
    sqlc.arg(body_sha256), sqlc.arg(ledger_entry_id), sqlc.narg(expires_at), sqlc.arg(computed_at))
RETURNING *;

-- name: GetCoverageSnapshot :one
SELECT * FROM pc.coverage_snapshots WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: CurrentCoverageSnapshot :one
SELECT * FROM pc.coverage_snapshots
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND connection_id = sqlc.arg(connection_id)
  AND operation = sqlc.arg(operation)
ORDER BY id DESC
LIMIT 1;

-- The newest ENFORCED snapshot of a scope: the last valid record a
-- downgrade keeps (F442).
-- name: LastEnforcedCoverageSnapshot :one
SELECT * FROM pc.coverage_snapshots
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND connection_id = sqlc.arg(connection_id)
  AND operation = sqlc.arg(operation) AND state = 'ENFORCED'
ORDER BY id DESC
LIMIT 1;

-- The current snapshot of every scope, by scope. The cursor filters whole
-- scopes, so it applies before DISTINCT ON and the scan stops at the page.
-- name: ListCurrentCoverageSnapshotsPage :many
SELECT DISTINCT ON (agent_id, connection_id, operation) *
FROM pc.coverage_snapshots
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(connection_id)::uuid IS NULL OR connection_id = sqlc.narg(connection_id)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(after_agent)::uuid IS NULL
       OR (agent_id, connection_id, operation) > (sqlc.narg(after_agent)::uuid, sqlc.narg(after_connection)::uuid,
                                                 sqlc.narg(after_operation)::text))
ORDER BY agent_id, connection_id, operation, id DESC
LIMIT sqlc.arg(max_rows);

-- name: InsertCoverageExclusion :one
INSERT INTO pc.coverage_exclusions (org_id, id, agent_id, connection_id, operation, route_kind, reason, created_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.narg(agent_id), sqlc.arg(connection_id), sqlc.narg(operation),
    sqlc.narg(route_kind), sqlc.arg(reason), sqlc.arg(created_by), now() + make_interval(days => sqlc.arg(expires_in_days)::int))
RETURNING *;

-- name: RevokeCoverageExclusion :one
UPDATE pc.coverage_exclusions SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by), revoked_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- The active, unexpired exclusions that apply to a scope.
-- name: CoverageExclusionsForScope :many
SELECT * FROM pc.coverage_exclusions
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'ACTIVE' AND expires_at > now()
  AND (agent_id IS NULL OR agent_id = sqlc.arg(agent_id))
  AND (operation IS NULL OR operation = sqlc.arg(operation)::text)
ORDER BY id;

-- Newest first; an ACTIVE exclusion past its expiry reads as EXPIRED.
-- name: ListCoverageExclusionsPage :many
SELECT e.*, (CASE WHEN e.state = 'ACTIVE' AND e.expires_at <= now() THEN 'EXPIRED' ELSE e.state END)::text AS effective_state
FROM pc.coverage_exclusions e
WHERE e.org_id = sqlc.arg(org_id)
  AND (sqlc.narg(connection_id)::uuid IS NULL OR e.connection_id = sqlc.narg(connection_id)::uuid)
  AND (sqlc.narg(before)::uuid IS NULL OR e.id < sqlc.narg(before)::uuid)
ORDER BY e.id DESC
LIMIT sqlc.arg(max_rows);

-- A finding seen again is refreshed; a resolved one reopens, a dismissed
-- one stays dismissed.
-- name: UpsertCoverageFinding :one
INSERT INTO pc.coverage_findings (org_id, id, kind, connection_id, agent_id, subject, declared, held, used, excess, severity,
    fingerprint)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.narg(connection_id), sqlc.narg(agent_id), sqlc.arg(subject),
    sqlc.arg(declared)::text[], sqlc.arg(held)::text[], sqlc.arg(used)::text[], sqlc.arg(excess)::text[], sqlc.arg(severity),
    sqlc.arg(fingerprint))
ON CONFLICT (org_id, kind, fingerprint) DO UPDATE SET
    declared     = EXCLUDED.declared,
    held         = EXCLUDED.held,
    used         = EXCLUDED.used,
    excess       = EXCLUDED.excess,
    severity     = EXCLUDED.severity,
    state        = CASE WHEN pc.coverage_findings.state = 'DISMISSED' THEN 'DISMISSED' ELSE 'OPEN' END,
    resolved_at  = CASE WHEN pc.coverage_findings.state = 'DISMISSED' THEN pc.coverage_findings.resolved_at END,
    last_seen_at = now()
RETURNING *;

-- Open findings of a kind for a connection that the latest pass no longer
-- found are resolved.
-- name: ResolveCoverageFindings :execrows
UPDATE pc.coverage_findings SET state = 'RESOLVED', resolved_at = now()
WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND connection_id = sqlc.arg(connection_id) AND state = 'OPEN'
  AND NOT (fingerprint = ANY (sqlc.arg(keep)::bytea[]));

-- name: DismissCoverageFinding :one
UPDATE pc.coverage_findings SET state = 'DISMISSED', dismissed_by = sqlc.arg(dismissed_by),
    dismiss_reason = sqlc.arg(dismiss_reason), resolved_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN'
RETURNING *;

-- name: ListCoverageFindingsPage :many
SELECT * FROM pc.coverage_findings
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
  AND (sqlc.narg(connection_id)::uuid IS NULL OR connection_id = sqlc.narg(connection_id)::uuid)
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: CoverageInventoryWatermark :one
SELECT transactions_after FROM pc.coverage_inventory WHERE org_id = sqlc.arg(org_id);

-- name: SetCoverageInventoryWatermark :exec
INSERT INTO pc.coverage_inventory (org_id, transactions_after) VALUES (sqlc.arg(org_id), sqlc.arg(transactions_after))
ON CONFLICT (org_id) DO UPDATE SET transactions_after = EXCLUDED.transactions_after, refreshed_at = now();

-- The org's transactions after a point and up to another, in id order and
-- a minute behind the clock, with the agent of their run; connection and
-- channel are NULL for an action that did not come through a gateway.
-- name: CoverageTrafficAfter :many
SELECT t.id, r.agent_id, t.connection_id, t.operation, t.channel, t.mode
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND (sqlc.narg(after)::uuid IS NULL OR t.id > sqlc.narg(after)::uuid)
  AND (sqlc.narg(until)::uuid IS NULL OR t.id <= sqlc.narg(until)::uuid)
  AND t.created_at < now() - interval '1 minute'
ORDER BY t.id
LIMIT sqlc.arg(max_rows);

-- The scopes known for a connection: the agents and operations its
-- traffic or its snapshots name.
-- name: CoverageScopesOfConnection :many
SELECT DISTINCT x.agent_id::uuid AS agent_id, x.operation::text AS operation FROM (
    SELECT r.agent_id, r.operation FROM pc.coverage_routes r
    WHERE r.org_id = sqlc.arg(org_id) AND r.connection_id = sqlc.arg(connection_id) AND r.kind = 'channel'
      AND r.agent_id IS NOT NULL AND r.operation IS NOT NULL
    UNION
    SELECT s.agent_id, s.operation FROM pc.coverage_snapshots s
    WHERE s.org_id = sqlc.arg(org_id) AND s.connection_id = sqlc.arg(connection_id)
) x
WHERE sqlc.narg(agent_id)::uuid IS NULL OR x.agent_id = sqlc.narg(agent_id)::uuid
ORDER BY 1, 2
LIMIT 1000;

-- Current ENFORCED snapshots past their expiry: their scopes read PARTIAL
-- now, and the reassess job records it (F441).
-- name: ExpiredEnforcedCoverageScopes :many
SELECT s.agent_id, s.connection_id, s.operation FROM pc.coverage_snapshots s
WHERE s.org_id = sqlc.arg(org_id) AND s.state = 'ENFORCED' AND s.expires_at <= now()
  AND NOT EXISTS (SELECT 1 FROM pc.coverage_snapshots n
                  WHERE n.org_id = s.org_id AND n.agent_id = s.agent_id AND n.connection_id = s.connection_id
                    AND n.operation = s.operation AND n.id > s.id)
ORDER BY s.id
LIMIT sqlc.arg(max_rows);

-- The agent's admitted, unexpired instances and the sandbox session of
-- each, empty outside a sandbox (design decision 2). sandbox_session_id
-- comes with 00090; it is read through to_jsonb, so this works before and
-- after.
-- name: CoverageInstancesOfAgent :many
SELECT i.id, coalesce(to_jsonb(i) ->> 'sandbox_session_id', '')::text AS sandbox_session_id
FROM pc.agent_instances i
WHERE i.org_id = sqlc.arg(org_id) AND i.agent_id = sqlc.arg(agent_id) AND i.state = 'ADMITTED'
  AND (i.expires_at IS NULL OR i.expires_at > now())
ORDER BY i.id;

-- Serializes the reassessments and closure recordings of one agent and
-- connection until the transaction ends, so two never append snapshots
-- from the same current one.
-- name: LockCoverageScope :exec
SELECT pg_advisory_xact_lock(hashtextextended(
    (sqlc.arg(org_id)::uuid)::text || '/' || (sqlc.arg(agent_id)::uuid)::text || '/' || (sqlc.arg(connection_id)::uuid)::text,
    85));

-- The changes to a scope no reassessment has seen yet, oldest first: a
-- snapshot lapses while one is pending (HR-211).
-- name: CoverageChangesPending :many
SELECT * FROM pc.coverage_invalidations
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
  AND (agent_id IS NULL OR agent_id = sqlc.narg(agent_id)::uuid) AND reassessed_at IS NULL
ORDER BY occurred_at, id
LIMIT 64;

-- Marks one invalidation reassessed with its ledger entry; a second call
-- changes nothing.
-- name: EnterCoverageInvalidation :execrows
UPDATE pc.coverage_invalidations SET reassessed_at = now(), ledger_entry_id = sqlc.arg(ledger_entry_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND reassessed_at IS NULL;

-- The ledger entries an evidence bundle carries beside a receipt that
-- claims a coverage snapshot (HR-217): the snapshot's, the next snapshot of
-- its scope, and the scope's invalidations from the snapshot's computation
-- up to the decision.
-- name: CoverageClaimEntries :many
SELECT s.ledger_entry_id FROM pc.coverage_snapshots s WHERE s.org_id = sqlc.arg(org_id) AND s.id = sqlc.arg(snapshot_id)
UNION ALL
(SELECT n.ledger_entry_id
 FROM pc.coverage_snapshots s
 JOIN pc.coverage_snapshots n ON n.org_id = s.org_id AND n.agent_id = s.agent_id AND n.connection_id = s.connection_id
                             AND n.operation = s.operation AND n.id > s.id
 WHERE s.org_id = sqlc.arg(org_id) AND s.id = sqlc.arg(snapshot_id)
 ORDER BY n.id
 LIMIT 1)
UNION ALL
(SELECT i.ledger_entry_id
 FROM pc.coverage_snapshots s
 JOIN pc.coverage_invalidations i ON i.org_id = s.org_id AND i.connection_id = s.connection_id
                                 AND (i.agent_id IS NULL OR i.agent_id = s.agent_id)
 WHERE s.org_id = sqlc.arg(org_id) AND s.id = sqlc.arg(snapshot_id) AND i.ledger_entry_id IS NOT NULL
   AND i.occurred_at >= s.computed_at AND i.occurred_at < sqlc.arg(until)
 ORDER BY i.occurred_at
 LIMIT 256);

-- The bounds of the agent's active grants in effect now: the operations
-- they allow are the scopes its protection is derived from (F021).
-- name: CoverageGrantBoundsOfAgent :many
SELECT r.bounds FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.agent_id = sqlc.arg(agent_id) AND g.state = 'ACTIVE'
  AND r.not_before <= now() AND r.expires_at > now();

-- The org's agents that coverage holds protected or partially protected:
-- each reassess job derives them again, so a grant that starts, ends or
-- changes lowers them within one run although it writes no coverage change
-- (F021).
-- name: CoverageProtectedAgents :many
SELECT id FROM pc.agents
WHERE org_id = sqlc.arg(org_id) AND state IN ('PROTECTED', 'PARTIALLY_PROTECTED')
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- The org's connections that can carry actions, with their pinned package
-- version.
-- name: CoverageConnectionPackages :many
SELECT c.id, p.version_id FROM pc.connections c
JOIN pc.tool_packages tp ON tp.org_id = c.org_id AND tp.name = c.package
JOIN pc.package_pins p ON p.org_id = c.org_id AND p.package_id = tp.id
WHERE c.org_id = sqlc.arg(org_id) AND c.state <> 'RETIRED'
ORDER BY c.id
LIMIT 1000;

-- The agents with coverage on a connection.
-- name: CoverageAgentsOfConnection :many
SELECT DISTINCT agent_id FROM pc.coverage_snapshots
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
ORDER BY agent_id
LIMIT 200;

-- The bounds of the org's active grants in effect now: the operations
-- they allow are what a connection's credential is declared to need
-- (F048).
-- name: CoverageGrantBoundsOfOrg :many
SELECT r.bounds FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.state = 'ACTIVE' AND r.not_before <= now() AND r.expires_at > now()
LIMIT 1000;

-- The operations executed through a connection in the last 30 days: the
-- ones a dispatch was attempted for (F048 "used").
-- name: CoverageExecutedOperations :many
SELECT DISTINCT t.operation::text FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.connection_id = sqlc.arg(connection_id)
  AND t.created_at > now() - interval '30 days'
  AND EXISTS (SELECT 1 FROM pc.execution_attempts a WHERE a.org_id = t.org_id AND a.transaction_id = t.id)
ORDER BY 1;

-- The credentials the org scan found for a connection, with the
-- permissions they actually hold (G0 M8 G5: github_app findings name the
-- connection they were scanned through). UNTRUSTED metadata. A dismissed
-- discovery still counts: dismissing it does not remove the reach.
-- name: CoverageReachOfConnection :many
SELECT id, observed FROM pc.discoveries
WHERE org_id = sqlc.arg(org_id) AND source IN ('scan', 'github_scan')
  AND observed ->> 'kind' = 'github_app' AND observed ->> 'connection' = sqlc.arg(connection)::text
ORDER BY id
LIMIT 500;

-- The org-scan findings that show a route of one of the org's connections
-- and were not recorded yet, with the route (G0 M8 G5 kinds; UNTRUSTED
-- metadata, HR-209: they only describe a route, never grant or close one):
--   - a GitHub App installation is target-side authority beyond the
--     connection (F449);
--   - a workflow that writes or deploys is an intermediary that can produce
--     the effect (F448);
--   - a committed MCP configuration is an MCP server reaching the target
--     outside the gateway (F444).
-- Only findings that are recorded are selected, so findings that show no
-- route never hold back the ones after them. Each is recorded once, as the
-- source of its route. A dismissed discovery still counts: dismissing it
-- does not remove the route.
-- name: CoverageScanFindingsToRecord :many
SELECT s.id, s.connection_id, s.kind::text AS kind, s.locator::text AS locator FROM (
    SELECT d.id, c.id AS connection_id,
        CASE d.observed ->> 'kind'
            WHEN 'github_app' THEN 'target_side'
            WHEN 'github_workflow' THEN 'intermediary'
            WHEN 'github_mcp_config' THEN 'direct_api'
        END AS kind,
        left(btrim(CASE d.observed ->> 'kind'
            WHEN 'github_app' THEN 'GitHub App ' || coalesce(d.observed ->> 'app_slug', '')
            ELSE coalesce(d.observed ->> 'repo', '') || ' ' || coalesce(d.observed ->> 'path', '')
        END), 512) AS locator
    FROM pc.discoveries d
    JOIN pc.connections c ON c.org_id = d.org_id AND c.id::text = lower(d.observed ->> 'connection')
    WHERE d.org_id = sqlc.arg(org_id) AND d.source IN ('scan', 'github_scan')
      AND d.observed ->> 'kind' IN ('github_app', 'github_workflow', 'github_mcp_config')
      AND (d.observed ->> 'kind' <> 'github_workflow' OR d.observed ->> 'writes' = 'true' OR d.observed ->> 'deploys' = 'true')
      AND NOT EXISTS (SELECT 1 FROM pc.coverage_routes r
                      WHERE r.org_id = d.org_id AND r.source = 'scan' AND r.source_ref = d.id)
) s
WHERE s.kind = 'target_side' OR s.locator <> ''
ORDER BY s.id
LIMIT 200;

-- A scope's snapshots, newest first: its coverage history.
-- name: ListCoverageSnapshotsPage :many
SELECT * FROM pc.coverage_snapshots
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND connection_id = sqlc.arg(connection_id)
  AND operation = sqlc.arg(operation)
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- The GitHub App installation behind a connection, with the permissions it
-- held when last read (G0 M8 G3, connection_github): the reach of the
-- connection's own credential (F048). UNTRUSTED metadata read from GitHub.
-- name: CoverageInstallationOfConnection :one
SELECT app_client_id, installation_id, account_login, permissions FROM pc.connection_github
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id);
