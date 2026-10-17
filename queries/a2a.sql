-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- A2A pins and peer runs (G0 M14 D30, D33, D64, D85). A pin is proposed
-- with the connection, in its transaction, and serves once confirmed; a
-- newer proposal voids an older one. A peer run is created once per
-- (requester run, connection, context) and reused after.

-- name: VoidA2AProposals :execrows
UPDATE pc.a2a_pins SET state = 'VOIDED'
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'PROPOSED';

-- name: InsertA2APin :exec
INSERT INTO pc.a2a_pins (org_id, id, connection_id, card_url, binding, interface_url, pinned_card, card_digest,
                         card_keys, skills, peer_agent_id, peer_bounds, peer_limits, max_answer_bytes,
                         max_stream_seconds, proposed_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(card_url), sqlc.arg(binding),
        sqlc.arg(interface_url), sqlc.arg(pinned_card), sqlc.arg(card_digest), sqlc.narg(card_keys), sqlc.arg(skills),
        sqlc.narg(peer_agent_id), sqlc.narg(peer_bounds), sqlc.narg(peer_limits), sqlc.arg(max_answer_bytes),
        sqlc.arg(max_stream_seconds), sqlc.arg(proposed_by));

-- name: GetA2APin :one
SELECT *
FROM pc.a2a_pins
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = sqlc.arg(state);

-- name: LockA2AProposal :one
SELECT *
FROM pc.a2a_pins
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND id = sqlc.arg(id) AND state = 'PROPOSED'
FOR UPDATE;

-- name: SupersedeA2APin :execrows
UPDATE pc.a2a_pins SET state = 'SUPERSEDED'
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'ACTIVE';

-- name: ActivateA2APin :execrows
UPDATE pc.a2a_pins
SET state = 'ACTIVE', confirmed_by = sqlc.arg(confirmed_by), confirmed_credential = sqlc.arg(confirmed_credential)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PROPOSED';

-- name: MarkA2ADrift :execrows
UPDATE pc.a2a_pins SET drifted_at = now(), observed_digest = sqlc.arg(observed_digest)
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'ACTIVE'
  AND card_digest = sqlc.arg(pinned_digest) AND drifted_at IS NULL;

-- name: GetA2AConnectionWriter :one
SELECT simulated, updated_by, revision, gateway_id, name
FROM pc.connections
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'a2a';

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
