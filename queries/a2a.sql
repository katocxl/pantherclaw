-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- A2A connections and peer runs (G0 M14 D30, D33, D64). A pin is written
-- with the connection, in its transaction; a refresh replaces it and clears
-- recorded drift. A peer run is created once per (requester run,
-- connection, context) and reused after.

-- name: InsertA2AConnection :exec
INSERT INTO pc.a2a_connections (org_id, connection_id, card_url, binding, interface_url, pinned_card, card_digest,
                                card_keys, skills, peer_agent_id, peer_bounds, peer_limits, max_answer_bytes,
                                max_stream_seconds, pinned_by)
VALUES (sqlc.arg(org_id), sqlc.arg(connection_id), sqlc.arg(card_url), sqlc.arg(binding), sqlc.arg(interface_url),
        sqlc.arg(pinned_card), sqlc.arg(card_digest), sqlc.narg(card_keys), sqlc.arg(skills), sqlc.narg(peer_agent_id),
        sqlc.narg(peer_bounds), sqlc.narg(peer_limits), sqlc.arg(max_answer_bytes), sqlc.arg(max_stream_seconds),
        sqlc.arg(pinned_by));

-- name: UpdateA2AConnection :execrows
UPDATE pc.a2a_connections
SET card_url = sqlc.arg(card_url), binding = sqlc.arg(binding), interface_url = sqlc.arg(interface_url),
    pinned_card = sqlc.arg(pinned_card), card_digest = sqlc.arg(card_digest), card_keys = sqlc.narg(card_keys),
    skills = sqlc.arg(skills), peer_agent_id = sqlc.narg(peer_agent_id), peer_bounds = sqlc.narg(peer_bounds),
    peer_limits = sqlc.narg(peer_limits), max_answer_bytes = sqlc.arg(max_answer_bytes),
    max_stream_seconds = sqlc.arg(max_stream_seconds), pinned_by = sqlc.arg(pinned_by), pinned_at = now(),
    drifted_at = NULL, observed_digest = NULL
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id);

-- name: GetA2AConnection :one
SELECT card_url, binding, interface_url, pinned_card, card_digest, card_keys, skills, peer_agent_id, peer_bounds,
       peer_limits, max_answer_bytes, max_stream_seconds, pinned_by, pinned_at, drifted_at, observed_digest
FROM pc.a2a_connections
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id);

-- name: MarkA2ADrift :execrows
UPDATE pc.a2a_connections SET drifted_at = now(), observed_digest = sqlc.arg(observed_digest)
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND card_digest = sqlc.arg(pinned_digest)
  AND drifted_at IS NULL;

-- name: GetA2APeerRun :one
SELECT child_run_id, child_grant_id, created_at
FROM pc.a2a_peer_runs
WHERE org_id = sqlc.arg(org_id) AND requester_run_id = sqlc.arg(requester_run_id)
  AND connection_id = sqlc.arg(connection_id) AND context_id = sqlc.arg(context_id);

-- name: InsertA2APeerRun :execrows
INSERT INTO pc.a2a_peer_runs (org_id, requester_run_id, connection_id, context_id, child_run_id, child_grant_id)
VALUES (sqlc.arg(org_id), sqlc.arg(requester_run_id), sqlc.arg(connection_id), sqlc.arg(context_id),
        sqlc.arg(child_run_id), sqlc.arg(child_grant_id))
ON CONFLICT (org_id, requester_run_id, connection_id, context_id) DO NOTHING;

-- name: ListA2APeerRuns :many
SELECT requester_run_id, context_id, child_run_id, child_grant_id, created_at
FROM pc.a2a_peer_runs
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
ORDER BY created_at DESC, child_run_id DESC
LIMIT 200;

-- name: GetA2AConnectionWriter :one
SELECT simulated, updated_by, revision
FROM pc.connections
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'a2a';
