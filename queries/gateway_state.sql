-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Gateway status reports (00186) and shared MCP state (00187), G0 M15
-- D10..D12.

-- name: ListGatewayServedConnectionIDs :many
SELECT id FROM pc.connections
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND state <> 'RETIRED';

-- name: UpsertGatewayReplica :exec
INSERT INTO pc.gateway_replicas (org_id, gateway_id, replica_id, version, build, start_time, config_version, connections, last_seen)
VALUES (sqlc.arg(org_id), sqlc.arg(gateway_id), sqlc.arg(replica_id), sqlc.arg(version), sqlc.arg(build), sqlc.narg(start_time),
        sqlc.arg(config_version), sqlc.arg(connections), sqlc.arg(last_seen))
ON CONFLICT (org_id, gateway_id, replica_id) DO UPDATE
SET version = EXCLUDED.version, build = EXCLUDED.build, start_time = EXCLUDED.start_time,
    config_version = EXCLUDED.config_version, connections = EXCLUDED.connections, last_seen = EXCLUDED.last_seen;

-- name: ListGatewayReplicas :many
SELECT * FROM pc.gateway_replicas
WHERE org_id = sqlc.arg(org_id) AND gateway_id = ANY(sqlc.arg(gateway_ids)::uuid[]) AND last_seen > sqlc.arg(seen_after)
ORDER BY gateway_id, last_seen DESC, replica_id;

-- name: PruneGatewayReplicas :execrows
DELETE FROM pc.gateway_replicas WHERE org_id = sqlc.arg(org_id) AND last_seen < sqlc.arg(seen_before);

-- name: LockGatewayMCPState :exec
SELECT pg_advisory_xact_lock(hashtextextended('pc.gateway_mcp_state:' || sqlc.arg(gateway_id)::uuid::text, 0));

-- name: GetGatewayMCPState :one
SELECT * FROM pc.gateway_mcp_state
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND kind = sqlc.arg(kind) AND key = sqlc.arg(key);

-- name: InsertGatewayMCPState :exec
INSERT INTO pc.gateway_mcp_state (org_id, gateway_id, kind, key, connection_id, run_id, instance_id, jkt, action_id, status, busy,
                                  sealed_body, version, expire_time, update_time)
VALUES (sqlc.arg(org_id), sqlc.arg(gateway_id), sqlc.arg(kind), sqlc.arg(key), sqlc.arg(connection_id), sqlc.narg(run_id),
        sqlc.narg(instance_id), sqlc.narg(jkt), sqlc.narg(action_id), sqlc.narg(status), sqlc.arg(busy), sqlc.narg(sealed_body),
        1, sqlc.arg(expire_time), sqlc.arg(update_time));

-- name: UpdateGatewayMCPState :execrows
UPDATE pc.gateway_mcp_state
SET action_id = sqlc.narg(action_id), status = sqlc.narg(status), busy = sqlc.arg(busy), sealed_body = sqlc.narg(sealed_body),
    version = version + 1, expire_time = sqlc.arg(expire_time), update_time = sqlc.arg(update_time)
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND kind = sqlc.arg(kind) AND key = sqlc.arg(key)
  AND version = sqlc.arg(if_version);

-- name: DeleteGatewayMCPState :execrows
-- A versioned delete matches only an unexpired row (D42).
DELETE FROM pc.gateway_mcp_state
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND kind = sqlc.arg(kind) AND key = sqlc.arg(key)
  AND (sqlc.arg(if_version)::bigint = 0 OR (version = sqlc.arg(if_version)::bigint AND expire_time > sqlc.arg(now)));

-- name: CountGatewayMCPState :one
-- The live entries of a gateway: holds, tasks and elicitations in all and of one
-- instance, sessions in all, and the bytes of sealed task bodies.
SELECT count(*) FILTER (WHERE kind IN ('HOLD', 'TASK', 'ELICITATION'))::bigint AS entries,
       count(*) FILTER (WHERE kind IN ('HOLD', 'TASK', 'ELICITATION') AND instance_id IS NOT DISTINCT FROM sqlc.narg(instance_id)::uuid)::bigint AS instance_entries,
       count(*) FILTER (WHERE kind = 'SESSION')::bigint AS sessions,
       coalesce(sum(octet_length(sealed_body)), 0)::bigint AS body_bytes
FROM pc.gateway_mcp_state
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND expire_time > sqlc.arg(now);

-- name: ListInstanceMCPSessions :many
-- An instance's live sessions, least recently updated first.
SELECT key FROM pc.gateway_mcp_state
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND kind = 'SESSION'
  AND instance_id IS NOT DISTINCT FROM sqlc.narg(instance_id)::uuid AND expire_time > sqlc.arg(now)
ORDER BY update_time, key;

-- name: PurgeGatewayMCPState :execrows
DELETE FROM pc.gateway_mcp_state WHERE org_id = sqlc.arg(org_id) AND expire_time <= sqlc.arg(now);

-- name: CountGatewayMCPStateOfKind :one
-- The live entries of one A2A kind (G0 M19 D211, D218): each kind has the
-- TASK bounds of its own, in all and of one caller: its agent instance, or
-- its run when it names no instance.
SELECT count(*)::bigint AS entries,
       count(*) FILTER (WHERE CASE WHEN sqlc.narg(instance_id)::uuid IS NULL
                                   THEN instance_id IS NULL AND run_id IS NOT DISTINCT FROM sqlc.narg(run_id)::uuid
                                   ELSE instance_id = sqlc.narg(instance_id)::uuid END)::bigint AS caller_entries
FROM pc.gateway_mcp_state
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND kind = sqlc.arg(kind)
  AND expire_time > sqlc.arg(now);
