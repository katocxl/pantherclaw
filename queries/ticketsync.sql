-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Ticket sync (G0 M20 D255; migrations 00242, 00243). The sync reads and
-- writes only these tables, case entries and incident events; nothing here
-- touches containment, restoration, approvals or kill switches (HR-527).

-- name: InsertTicketSyncConfig :one
INSERT INTO pc.ticket_sync_configs (org_id, id, system, connection_id, project_key, webhook_secret, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(system), sqlc.arg(connection_id), sqlc.arg(project_key),
    sqlc.arg(webhook_secret), sqlc.arg(created_by))
RETURNING *;

-- name: GetTicketSyncConfig :one
SELECT * FROM pc.ticket_sync_configs WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListTicketSyncConfigs :many
SELECT * FROM pc.ticket_sync_configs WHERE org_id = sqlc.arg(org_id) ORDER BY created_at, id;

-- The current secret becomes the previous one for 24 hours.
-- name: RotateTicketSyncSecret :execrows
UPDATE pc.ticket_sync_configs
SET prev_webhook_secret = sqlc.arg(prev_webhook_secret), prev_secret_expires_at = now() + interval '24 hours',
    webhook_secret = sqlc.arg(webhook_secret), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SetTicketSyncConfigState :execrows
UPDATE pc.ticket_sync_configs SET state = sqlc.arg(state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> sqlc.arg(state);

-- name: InsertExternalRef :one
INSERT INTO pc.external_refs (org_id, id, case_id, incident_id, system, connection_id, external_key, external_id, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.narg(case_id), sqlc.narg(incident_id), sqlc.arg(system), sqlc.arg(connection_id),
    sqlc.arg(external_key), sqlc.narg(external_id), sqlc.arg(created_by))
RETURNING *;

-- name: ExternalRefByTicket :one
SELECT * FROM pc.external_refs
WHERE org_id = sqlc.arg(org_id) AND system = sqlc.arg(system) AND connection_id = sqlc.arg(connection_id)
  AND external_key = sqlc.arg(external_key)
FOR UPDATE;

-- name: ExternalRefsOfCase :many
SELECT * FROM pc.external_refs WHERE org_id = sqlc.arg(org_id) AND case_id = sqlc.arg(case_id) ORDER BY created_at, id;

-- name: ExternalRefsOfIncident :many
SELECT * FROM pc.external_refs WHERE org_id = sqlc.arg(org_id) AND incident_id = sqlc.arg(incident_id) ORDER BY created_at, id;

-- name: AdvanceExternalRef :execrows
UPDATE pc.external_refs SET remote_updated_at = sqlc.arg(remote_updated_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND (remote_updated_at IS NULL OR remote_updated_at < sqlc.arg(remote_updated_at));

-- name: TicketFieldOwners :many
SELECT * FROM pc.ticket_field_owners WHERE org_id = sqlc.arg(org_id) ORDER BY field;

-- name: SetTicketFieldOwner :exec
INSERT INTO pc.ticket_field_owners (org_id, field, owner, changed_by)
VALUES (sqlc.arg(org_id), sqlc.arg(field), sqlc.arg(owner), sqlc.arg(changed_by))
ON CONFLICT (org_id, field) DO UPDATE SET owner = EXCLUDED.owner, changed_by = EXCLUDED.changed_by, changed_at = now();

-- A delivery seen before inserts nothing (a replay).
-- name: InsertTicketInboundEvent :execrows
INSERT INTO pc.ticket_inbound_events (org_id, id, config_id, delivery_id, body_sha256, issue_key, outcome)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(config_id), sqlc.arg(delivery_id), sqlc.arg(body_sha256),
    sqlc.narg(issue_key), sqlc.arg(outcome))
ON CONFLICT (org_id, config_id, delivery_id) DO NOTHING;

-- name: TicketInboundDeliverySeen :one
SELECT EXISTS (SELECT 1 FROM pc.ticket_inbound_events
               WHERE org_id = sqlc.arg(org_id) AND config_id = sqlc.arg(config_id) AND delivery_id = sqlc.arg(delivery_id));

-- name: IncidentForTicketSync :one
SELECT id, state, severity FROM pc.incidents WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
