-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Shared threat-intel indicators (G0 M38 D1103..D1105).

-- name: GetIntelSettings :one
SELECT consume, share, updated_by, updated_at FROM pc.intel_settings WHERE org_id = sqlc.arg(org_id);

-- name: UpsertIntelSettings :one
INSERT INTO pc.intel_settings (org_id, consume, share, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(consume), sqlc.arg(share), sqlc.arg(updated_by))
ON CONFLICT (org_id) DO UPDATE SET consume = EXCLUDED.consume, share = EXCLUDED.share,
    updated_by = EXCLUDED.updated_by, updated_at = now()
RETURNING consume, share, updated_by, updated_at;

-- name: EnsureIntelSettings :exec
-- Creates the org's row at the defaults (OFF, not shared) so it can be locked.
INSERT INTO pc.intel_settings (org_id, updated_by) VALUES (sqlc.arg(org_id), sqlc.arg(updated_by))
ON CONFLICT (org_id) DO NOTHING;

-- name: LockIntelSettings :one
-- Serializes changes of an org's settings (D1104a).
SELECT consume, share, updated_by, updated_at FROM pc.intel_settings WHERE org_id = sqlc.arg(org_id) FOR UPDATE;

-- name: GetIntelState :one
SELECT feed_version, feed_digest, kid, issued_at, expires_at, source, updated_at FROM pc.intel_state WHERE id = 1;

-- name: LockIntelState :one
-- Serializes imports: the row, or nothing, under a lock.
SELECT feed_version, feed_digest FROM pc.intel_state WHERE id = 1 FOR UPDATE;

-- name: PutIntelState :exec
INSERT INTO pc.intel_state (id, feed_version, feed_digest, kid, issued_at, expires_at, source)
VALUES (1, sqlc.arg(feed_version), sqlc.arg(feed_digest), sqlc.arg(kid), sqlc.arg(issued_at), sqlc.arg(expires_at), sqlc.arg(source))
ON CONFLICT (id) DO UPDATE SET feed_version = EXCLUDED.feed_version, feed_digest = EXCLUDED.feed_digest,
    kid = EXCLUDED.kid, issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at, source = EXCLUDED.source,
    updated_at = now();

-- name: DeleteIntelIndicators :exec
DELETE FROM pc.intel_indicators;

-- name: InsertIntelIndicator :exec
INSERT INTO pc.intel_indicators (id, kind, sha256, shingles, severity, techniques, first_seen, summary, feed_version)
VALUES (sqlc.arg(id), sqlc.arg(kind), sqlc.narg(sha256), sqlc.arg(shingles), sqlc.arg(severity), sqlc.arg(techniques),
        sqlc.arg(first_seen), sqlc.arg(summary), sqlc.arg(feed_version));

-- name: CountIntelIndicators :one
SELECT count(*)::integer FROM pc.intel_indicators;

-- name: ListIntelIndicators :many
SELECT id, kind, sha256, shingles, severity, techniques, first_seen, summary FROM pc.intel_indicators ORDER BY id;

-- name: IntelHashHits :many
-- The current indicators of a kind with one of the hashes.
SELECT id, kind, severity FROM pc.intel_indicators
WHERE kind = sqlc.arg(kind) AND sha256 = ANY (sqlc.arg(hashes)::text[]) ORDER BY id;

-- name: IntelShingleCandidates :many
-- The current injection_text indicators sharing a shingle with a text.
SELECT id, severity, shingles FROM pc.intel_indicators
WHERE kind = 'injection_text' AND shingles && sqlc.arg(shingles)::text[] ORDER BY id;

-- name: GetIntelIndicator :one
SELECT id, kind, severity FROM pc.intel_indicators WHERE id = sqlc.arg(id);

-- name: IntelTextIndicators :many
-- Every current injection_text indicator, for gateways.
SELECT id, shingles FROM pc.intel_indicators WHERE kind = 'injection_text' ORDER BY id;

-- name: InsertIntelMatch :exec
INSERT INTO pc.intel_matches (org_id, id, indicator_id, kind, object_type, object_ref, connection_id, tool, mode)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(indicator_id), sqlc.arg(kind), sqlc.arg(object_type),
        sqlc.arg(object_ref), sqlc.narg(connection_id), sqlc.narg(tool), sqlc.arg(mode));

-- name: ListIntelMatches :many
SELECT id, indicator_id, kind, object_type, object_ref, connection_id, tool, mode, at FROM pc.intel_matches
WHERE org_id = sqlc.arg(org_id) AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
ORDER BY id DESC LIMIT sqlc.arg(max_rows);

-- name: IntelMatchSeen :one
-- Whether an object already matched an indicator, so a repeated report
-- records it once.
SELECT EXISTS (
    SELECT 1 FROM pc.intel_matches
    WHERE org_id = sqlc.arg(org_id) AND indicator_id = sqlc.arg(indicator_id)
      AND object_type = sqlc.arg(object_type) AND object_ref = sqlc.arg(object_ref)
)::boolean;

-- name: IntelToolDescription :one
-- The description a connection's upstream server last listed for a tool.
SELECT description FROM pc.connection_inventory
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND kind = 'TOOL' AND name = sqlc.arg(name)
  AND state <> 'VANISHED'
ORDER BY last_seen DESC LIMIT 1;

-- name: SetConnectionServerInfo :exec
UPDATE pc.connections SET upstream_server_info = sqlc.arg(info)::jsonb
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND upstream_server_info IS DISTINCT FROM sqlc.arg(info)::jsonb;

-- name: IntelSourceConnection :one
-- A connection with its upstream server's word and its pinned package
-- version, when one is pinned.
SELECT c.id, c.kind, c.package, c.upstream_server_info, p.version AS pinned_version, v.state AS pinned_state
FROM pc.connections c
LEFT JOIN pc.tool_packages t ON t.org_id = c.org_id AND t.name = c.package
LEFT JOIN pc.package_pins p ON p.org_id = t.org_id AND p.package_id = t.id
LEFT JOIN pc.package_versions v ON v.org_id = p.org_id AND v.id = p.version_id
WHERE c.org_id = sqlc.arg(org_id) AND c.id = sqlc.arg(id);

-- name: IntelSourcePackageVersion :one
SELECT t.name, v.version, v.state FROM pc.package_versions v
JOIN pc.tool_packages t ON t.org_id = v.org_id AND t.id = v.package_id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id);

-- name: IntelSourceInventoryItem :one
SELECT i.connection_id, i.kind, i.name, i.description, i.description_scan FROM pc.connection_inventory i
WHERE i.org_id = sqlc.arg(org_id) AND i.id = sqlc.arg(id);

-- name: InsertIntelContribution :one
INSERT INTO pc.intel_contributions (org_id, id, kind, sha256, shingles, severity, techniques)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.narg(sha256), sqlc.arg(shingles), sqlc.arg(severity),
        sqlc.arg(techniques))
RETURNING id, kind, sha256, shingles, severity, techniques, created_day, state;

-- name: ListIntelContributions :many
SELECT id, kind, sha256, shingles, severity, techniques, created_day, state FROM pc.intel_contributions
WHERE org_id = sqlc.arg(org_id) ORDER BY id DESC LIMIT 500;

-- name: QueuedIntelContributions :many
SELECT id, kind, sha256, shingles, severity, techniques, created_day FROM pc.intel_contributions
WHERE org_id = sqlc.arg(org_id) AND state = 'QUEUED' ORDER BY id;

-- name: MarkIntelContributionsExported :exec
UPDATE pc.intel_contributions SET state = 'EXPORTED'
WHERE org_id = sqlc.arg(org_id) AND state = 'QUEUED' AND id = ANY (sqlc.arg(contribution_ids)::uuid[]);
