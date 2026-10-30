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

-- A ticket sync call is a verification task of its own purpose, with no
-- transaction (00243).
-- name: InsertTicketSyncVerification :exec
INSERT INTO pc.verifications (org_id, id, purpose, connection_id, operation, request, next_at, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'ticket_sync', sqlc.arg(connection_id), sqlc.arg(operation), sqlc.arg(request),
    now(), now() + interval '1 hour');

-- name: InsertTicketOutbound :exec
INSERT INTO pc.ticket_outbound (org_id, id, config_id, case_id, incident_id, action, verification_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(config_id), sqlc.narg(case_id), sqlc.narg(incident_id), sqlc.arg(action),
    sqlc.arg(verification_id));

-- A ticket sync task under a live lease of this gateway, with what it was
-- for: nothing else accepts its report.
-- name: LeasedTicketSync :one
SELECT v.id AS verification_id, v.connection_id, v.operation, o.id AS outbound_id, o.config_id, o.case_id, o.incident_id, o.action,
       c.system, c.project_key
FROM pc.verifications v
JOIN pc.ticket_outbound o ON o.org_id = v.org_id AND o.verification_id = v.id
JOIN pc.ticket_sync_configs c ON c.org_id = o.org_id AND c.id = o.config_id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id) AND v.purpose = 'ticket_sync' AND v.state = 'LEASED'
  AND v.leased_by = sqlc.arg(gateway_id) AND v.lease_hash = sqlc.arg(lease_hash) AND v.lease_expires_at >= now()
  AND o.state = 'PENDING'
FOR UPDATE OF v, o;

-- name: FinishTicketOutbound :execrows
UPDATE pc.ticket_outbound SET state = sqlc.arg(state), result_code = sqlc.narg(result_code), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: TicketOutboundOf :many
SELECT * FROM pc.ticket_outbound
WHERE org_id = sqlc.arg(org_id) AND (case_id = sqlc.narg(case_id) OR incident_id = sqlc.narg(incident_id))
ORDER BY created_at DESC, id
LIMIT 20;

-- name: IncidentTitle :one
SELECT title FROM pc.incidents WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);
