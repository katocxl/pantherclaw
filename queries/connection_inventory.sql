-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- F352 discovery inventory (G0 M15 D21, D22): what a gateway found an
-- upstream MCP server listing behind a connection. Callers lock the
-- connection first, so one report or reconcile of a connection runs at a
-- time; every state move is conditional on the state read.

-- name: GetInventoryItemByKey :one
SELECT * FROM pc.connection_inventory
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND kind = sqlc.arg(kind)
  AND name = sqlc.arg(name) AND digest = sqlc.arg(digest);

-- name: InsertInventoryItem :exec
INSERT INTO pc.connection_inventory (org_id, id, connection_id, kind, name, display_name, mime_type, display_truncated, digest,
                                     description, description_scan, state, input_schema, input_schema_digest,
                                     input_schema_truncated)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(connection_id), sqlc.arg(kind), sqlc.arg(name), sqlc.arg(display_name),
        sqlc.arg(mime_type), sqlc.arg(display_truncated), sqlc.arg(digest), sqlc.arg(description), sqlc.arg(description_scan),
        sqlc.arg(state), sqlc.arg(input_schema), sqlc.arg(input_schema_digest), sqlc.arg(input_schema_truncated));

-- SetInventorySchema fills in the schema of an item first listed by a gateway
-- that did not report one (G0 M24 D211). The digest of the item covers it, so
-- this adds nothing the item did not already say.
-- name: SetInventorySchema :execresult
UPDATE pc.connection_inventory
SET input_schema = sqlc.arg(input_schema), input_schema_digest = sqlc.arg(input_schema_digest),
    input_schema_truncated = sqlc.arg(input_schema_truncated), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND input_schema_digest = '';

-- name: SeeInventoryItem :exec
UPDATE pc.connection_inventory SET last_seen = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- MoveInventoryItem moves an item from one state to another; a lost race
-- changes nothing (no row).
-- name: MoveInventoryItem :execresult
UPDATE pc.connection_inventory
SET state = sqlc.arg(to_state), review_entry_id = coalesce(sqlc.narg(review_entry_id)::uuid, review_entry_id),
    updated_at = now(), last_seen = CASE WHEN sqlc.arg(seen)::boolean THEN now() ELSE last_seen END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state);

-- VanishInventory ends the NEW and COVERED items of a connection that a
-- complete listing no longer has.
-- name: VanishInventory :many
UPDATE pc.connection_inventory SET state = 'VANISHED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state IN ('NEW', 'COVERED')
  AND NOT (id = ANY (sqlc.arg(seen)::uuid[]))
RETURNING id, kind, name;

-- name: ListNewInventory :many
SELECT * FROM pc.connection_inventory
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND state = 'NEW'
ORDER BY id;

-- name: ListConnectionInventory :many
SELECT * FROM pc.connection_inventory
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
  AND (cardinality(sqlc.arg(kinds)::text[]) = 0 OR kind = ANY (sqlc.arg(kinds)::text[]))
  AND id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: LockInventoryItem :one
SELECT * FROM pc.connection_inventory WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: DismissInventoryItem :execresult
UPDATE pc.connection_inventory
SET state = 'DISMISSED', dismissed_by = sqlc.arg(dismissed_by), dismiss_reason = sqlc.arg(dismiss_reason), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'NEW';

-- name: SetInventoryNote :execresult
UPDATE pc.connection_inventory
SET operator_note = sqlc.arg(operator_note), operator_note_by = sqlc.arg(operator_note_by), operator_note_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: GetInventoryItems :many
SELECT * FROM pc.connection_inventory
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND id = ANY (sqlc.arg(ids)::uuid[])
ORDER BY kind, name, id;
