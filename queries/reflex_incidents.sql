-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Alerts, incidents, suppressions, owned failures and digests (G0 M10
-- D14–D18; HR-242, HR-243). Every query runs inside db.InTenantTx and also
-- filters by org_id explicitly.

-- name: ReopenSuppressedAlert :execrows
-- A suppressed alert reopens when a signal bypasses or outlives its
-- suppression (D16, HR-242).
UPDATE pc.alerts SET state = 'OPEN', suppression_id = NULL, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'SUPPRESSED';

-- name: ActiveSuppressions :many
SELECT * FROM pc.suppressions
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND ended_at IS NULL AND expires_at > now()
ORDER BY id;

-- name: SuppressionBroken :one
SELECT EXISTS (SELECT 1 FROM pc.suppression_breaks
               WHERE org_id = sqlc.arg(org_id) AND suppression_id = sqlc.arg(suppression_id) AND subject = sqlc.arg(subject))::bool;

-- name: InsertSuppressionBreak :exec
INSERT INTO pc.suppression_breaks (org_id, id, suppression_id, subject, alert_id, reason)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(suppression_id), sqlc.arg(subject), sqlc.arg(alert_id), sqlc.arg(reason));

-- name: InsertSuppression :one
INSERT INTO pc.suppressions (org_id, id, rule_id, subjects, max_severity, reason, created_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(rule_id), sqlc.arg(subjects), sqlc.arg(max_severity), sqlc.arg(reason),
        sqlc.arg(created_by), sqlc.arg(expires_at))
RETURNING *;

-- name: GetSuppression :one
SELECT * FROM pc.suppressions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListSuppressions :many
SELECT * FROM pc.suppressions
WHERE org_id = sqlc.arg(org_id)
  AND (NOT sqlc.arg(active_only)::bool OR (ended_at IS NULL AND expires_at > now()))
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000'
       OR id < sqlc.arg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: EndSuppression :execrows
UPDATE pc.suppressions SET ended_at = now(), ended_by = sqlc.arg(ended_by), end_reason = sqlc.arg(end_reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND ended_at IS NULL;

-- name: SuppressionBreaks :many
SELECT * FROM pc.suppression_breaks WHERE org_id = sqlc.arg(org_id) AND suppression_id = sqlc.arg(suppression_id) ORDER BY id;

-- name: FindGroupIncident :one
-- The open incident of an evidence-based group seen within the window
-- (F603).
SELECT i.id, i.severity FROM pc.incidents i
WHERE i.org_id = sqlc.arg(org_id) AND i.group_key = sqlc.arg(group_key) AND i.state <> 'RESOLVED' AND NOT i.test
  AND (i.created_at > sqlc.arg(since) OR EXISTS (
      SELECT 1 FROM pc.alerts a WHERE a.org_id = i.org_id AND a.incident_id = i.id AND a.last_seen > sqlc.arg(since)))
ORDER BY i.id DESC
LIMIT 1;

-- name: InsertIncident :one
INSERT INTO pc.incidents (org_id, id, title, severity, group_key, opened_by, test, owner_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(title), sqlc.arg(severity), sqlc.arg(group_key), sqlc.arg(opened_by),
        sqlc.arg(test), sqlc.narg(owner_id))
RETURNING *;

-- name: InsertIncidentEvent :exec
INSERT INTO pc.incident_events (org_id, id, incident_id, kind, actor_type, actor_id, from_value, to_value, alert_id, note)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(incident_id), sqlc.arg(kind), sqlc.arg(actor_type), sqlc.arg(actor_id),
        sqlc.narg(from_value), sqlc.narg(to_value), sqlc.narg(alert_id), sqlc.narg(note));

-- name: AttachAlert :execrows
UPDATE pc.alerts SET incident_id = sqlc.arg(incident_id), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND incident_id IS NULL;

-- name: RaiseIncidentSeverity :execrows
-- Severity only goes up as alerts attach.
UPDATE pc.incidents SET severity = sqlc.arg(severity)::text, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND array_position(ARRAY['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], severity)
      < array_position(ARRAY['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], sqlc.arg(severity)::text);

-- name: GetAlert :one
SELECT * FROM pc.alerts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockAlert :one
SELECT * FROM pc.alerts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListAlerts :many
SELECT * FROM pc.alerts
WHERE org_id = sqlc.arg(org_id)
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000'
       OR id < sqlc.arg(before)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.arg(rule_id)::text = '' OR rule_id = sqlc.arg(rule_id)::text)
  AND (sqlc.narg(incident_id)::uuid IS NULL OR incident_id = sqlc.narg(incident_id)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: AlertEvidence :many
SELECT * FROM pc.alert_evidence WHERE org_id = sqlc.arg(org_id) AND alert_id = sqlc.arg(alert_id) ORDER BY id LIMIT 500;

-- name: AlertEvents :many
SELECT * FROM pc.alert_events WHERE org_id = sqlc.arg(org_id) AND alert_id = sqlc.arg(alert_id) ORDER BY id LIMIT 500;

-- name: PossibleRelatedAlerts :many
-- The same rule on other subjects within a day: listed, never attached
-- (D15).
SELECT * FROM pc.alerts
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND rule_id <> '' AND id <> sqlc.arg(id)
  AND dedupe_key <> sqlc.arg(dedupe_key) AND last_seen > sqlc.arg(since)
ORDER BY id DESC
LIMIT 50;

-- name: SetAlertState :execrows
UPDATE pc.alerts SET state = sqlc.arg(to_state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state);

-- name: GetIncident :one
SELECT * FROM pc.incidents WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockIncident :one
SELECT * FROM pc.incidents WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListIncidents :many
SELECT * FROM pc.incidents
WHERE org_id = sqlc.arg(org_id)
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000'
       OR id < sqlc.arg(before)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: IncidentEvents :many
SELECT * FROM pc.incident_events WHERE org_id = sqlc.arg(org_id) AND incident_id = sqlc.arg(incident_id) ORDER BY id LIMIT 1000;

-- name: IncidentAlerts :many
SELECT * FROM pc.alerts WHERE org_id = sqlc.arg(org_id) AND incident_id = sqlc.arg(incident_id) ORDER BY id LIMIT 500;

-- name: SetIncidentState :execrows
UPDATE pc.incidents SET state = sqlc.arg(to_state), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state);

-- name: AssignIncident :execrows
UPDATE pc.incidents SET owner_id = sqlc.arg(owner_id), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: GetFailure :one
SELECT * FROM pc.operational_failures WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListFailures :many
SELECT * FROM pc.operational_failures
WHERE org_id = sqlc.arg(org_id)
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000'
       OR id < sqlc.arg(before)::uuid)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: AssignFailure :execrows
UPDATE pc.operational_failures SET state = 'ASSIGNED', owner_type = sqlc.arg(owner_type), owner_id = sqlc.arg(owner_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'RESOLVED';

-- name: ResolveFailure :execrows
UPDATE pc.operational_failures SET state = 'RESOLVED', resolved_by = sqlc.arg(resolved_by), resolved_at = now(),
    resolution = sqlc.arg(resolution)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'RESOLVED';

-- name: InsertDigest :one
INSERT INTO pc.reflex_digests (org_id, day, decisions, authority_changes, alerts)
SELECT sqlc.arg(org_id), sqlc.arg(day)::date,
       count(*) FILTER (WHERE e.kind = 'receipt.decision'),
       count(*) FILTER (WHERE e.kind IN ('audit.grant.issued', 'audit.grant.revised', 'audit.grant.delegated', 'audit.grant.revoked',
                                         'audit.guardrails.changed', 'audit.policy.published')),
       count(*) FILTER (WHERE e.kind = 'reflex.alert')
FROM pc.ledger_entries e
WHERE e.org_id = sqlc.arg(org_id) AND e.occurred_at >= sqlc.arg(day)::date AND e.occurred_at < sqlc.arg(day)::date + 1
ON CONFLICT (org_id, day) DO NOTHING
RETURNING decisions, authority_changes, alerts;

-- name: MarkDigest :exec
UPDATE pc.reflex_digests SET state = sqlc.arg(state)::text,
    sent_at = CASE WHEN sqlc.arg(state)::text = 'SENT' THEN now() END
WHERE org_id = sqlc.arg(org_id) AND day = sqlc.arg(day)::date;
