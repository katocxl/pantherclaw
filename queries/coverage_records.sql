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
-- its package's pinned version and its active credential's version.
-- name: CoverageBinding :one
SELECT c.revision, c.gateway_id, c.state, c.kind, c.access_mode, p.version_id AS package_version_id,
    cr.version AS credential_version
FROM pc.connections c
JOIN pc.tool_packages tp ON tp.org_id = c.org_id AND tp.name = c.package
JOIN pc.package_pins p ON p.org_id = c.org_id AND p.package_id = tp.id
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
    invalidation_id, body, body_sha256, ledger_entry_id, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(connection_id), sqlc.arg(operation), sqlc.arg(state),
    sqlc.arg(reasons)::text[], sqlc.narg(closure_id), sqlc.narg(last_valid_id), sqlc.narg(invalidation_id), sqlc.arg(body),
    sqlc.arg(body_sha256), sqlc.arg(ledger_entry_id), sqlc.narg(expires_at))
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
