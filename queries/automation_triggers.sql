-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Automation triggers (G0 M11 part 2 D16-D23): the trigger log, dedupe
-- claims, schedules, the platform-event cursor, condition episodes,
-- threshold counts, inbound event sources and their receipts, automation
-- destinations and their deliveries. Every state change is a conditional
-- UPDATE (HR-004).

-- name: InsertAutomationTrigger :exec
INSERT INTO pc.automation_triggers (org_id, id, automation_id, version_id, kind, mode, source_ref, authenticity,
                                    authenticity_detail, params, subjects, evidence, root_trigger_id, ancestry, depth,
                                    state, reason, retried_from, queued_until, occurred_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(automation_id), sqlc.arg(version_id), sqlc.arg(kind), sqlc.arg(mode),
        sqlc.arg(source_ref), sqlc.arg(authenticity), sqlc.arg(authenticity_detail), sqlc.arg(params),
        sqlc.arg(subjects), sqlc.arg(evidence), sqlc.arg(root_trigger_id), sqlc.arg(ancestry)::uuid[], sqlc.arg(depth),
        sqlc.arg(state), sqlc.narg(reason), sqlc.narg(retried_from), sqlc.narg(queued_until), sqlc.arg(occurred_at));

-- name: AttachTriggerExecution :execrows
UPDATE pc.automation_triggers SET execution_id = sqlc.arg(execution_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('ACCEPTED', 'SHADOW') AND execution_id IS NULL;

-- name: SetTriggerState :execrows
UPDATE pc.automation_triggers
SET state = sqlc.arg(to_state), reason = sqlc.narg(reason),
    queued_until = CASE WHEN sqlc.arg(to_state)::text = 'QUEUED' THEN queued_until END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state) AND execution_id IS NULL;

-- name: GetAutomationTrigger :one
SELECT t.org_id, t.id, t.automation_id, t.version_id, t.kind, t.mode, t.source_ref, t.authenticity, t.authenticity_detail,
       t.params, t.subjects, t.evidence, t.root_trigger_id, t.ancestry, t.depth, t.state, t.reason, t.execution_id,
       t.retried_from, t.queued_until, t.occurred_at, t.received_at, t.decided_at
FROM pc.automation_triggers t
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id);

-- name: ListAutomationTriggers :many
-- Newest first, keyset by (received_at, id).
SELECT t.org_id, t.id, t.automation_id, t.version_id, t.kind, t.mode, t.source_ref, t.authenticity, t.authenticity_detail,
       t.params, t.subjects, t.evidence, t.root_trigger_id, t.ancestry, t.depth, t.state, t.reason, t.execution_id,
       t.retried_from, t.queued_until, t.occurred_at, t.received_at, t.decided_at
FROM pc.automation_triggers t
WHERE t.org_id = sqlc.arg(org_id) AND t.automation_id = sqlc.arg(automation_id)
  AND (sqlc.narg(state)::text IS NULL OR t.state = sqlc.narg(state)::text)
  AND (sqlc.narg(before_at)::timestamptz IS NULL
       OR (t.received_at, t.id) < (sqlc.narg(before_at)::timestamptz, sqlc.arg(before_id)::uuid))
ORDER BY t.received_at DESC, t.id DESC
LIMIT sqlc.arg(max_rows);

-- name: TriggerOfExecution :one
-- The trigger that started an execution: its ancestry is inherited by the
-- events the execution causes (D23).
SELECT t.id, t.automation_id, t.root_trigger_id, t.ancestry, t.depth, t.version_id, t.params, t.mode, t.kind
FROM pc.automation_triggers t
WHERE t.org_id = sqlc.arg(org_id) AND t.execution_id = sqlc.arg(execution_id);

-- name: CountStartedTriggersSince :one
-- Accepted (LIVE) triggers in the last hour (D23 per-hour cap, D87 L4).
SELECT count(*)::int AS n FROM pc.automation_triggers
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND state = 'ACCEPTED'
  AND received_at >= sqlc.arg(since);

-- name: CountQueuedTriggers :one
SELECT count(*)::int AS n FROM pc.automation_triggers
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND state = 'QUEUED';

-- name: LockQueuedTriggers :many
SELECT t.id, t.version_id, t.kind, t.mode, t.source_ref, t.authenticity, t.params, t.subjects, t.evidence,
       t.root_trigger_id, t.ancestry, t.depth, t.queued_until, t.occurred_at
FROM pc.automation_triggers t
WHERE t.org_id = sqlc.arg(org_id) AND t.automation_id = sqlc.arg(automation_id) AND t.state = 'QUEUED'
ORDER BY t.received_at, t.id
LIMIT 100
FOR UPDATE;

-- name: ExpireQueuedTriggers :execrows
-- Queued triggers past their time to live (paused_triggers EXPIRE, D23)
-- expire and give their dedupe keys back: nothing ran (D87 P5).
WITH x AS (
    UPDATE pc.automation_triggers t SET state = 'EXPIRED', reason = 'QUEUE_TTL', queued_until = NULL
    WHERE t.org_id = sqlc.arg(org_id) AND t.state = 'QUEUED' AND t.queued_until IS NOT NULL AND t.queued_until <= now()
    RETURNING t.id
)
DELETE FROM pc.automation_dedupe d USING x WHERE d.org_id = sqlc.arg(org_id) AND d.trigger_id = x.id;

-- name: DiscardQueuedTriggers :execrows
-- Discarded queued triggers give their dedupe keys back (D87 P5).
WITH x AS (
    UPDATE pc.automation_triggers t SET state = 'DISCARDED', reason = sqlc.arg(reason), queued_until = NULL
    WHERE t.org_id = sqlc.arg(org_id) AND t.automation_id = sqlc.arg(automation_id) AND t.state = 'QUEUED'
    RETURNING t.id
)
DELETE FROM pc.automation_dedupe d USING x WHERE d.org_id = sqlc.arg(org_id) AND d.trigger_id = x.id;

-- name: ActiveAutomationsWithTrigger :many
-- ACTIVE or PAUSED automations whose enabled version has a trigger of
-- the named kind (the `when` member: schedule, event, inbound, condition,
-- threshold, manual).
SELECT a.id, a.name, a.state, a.rollout, a.service_account_id, a.owner_user_id, a.enabled_version_id::uuid AS version_id,
       v.definition
FROM pc.automations a
JOIN pc.automation_versions v ON v.org_id = a.org_id AND v.id = a.enabled_version_id
WHERE a.org_id = sqlc.arg(org_id) AND a.state IN ('ACTIVE', 'PAUSED')
  AND v.definition -> 'when' -> sqlc.arg(member)::text IS NOT NULL
ORDER BY a.id;

-- name: InboundAutomations :many
-- ACTIVE or PAUSED automations listening to one source and type (D21).
SELECT a.id, a.name, a.state, a.rollout, a.service_account_id, a.owner_user_id, a.enabled_version_id::uuid AS version_id,
       v.definition
FROM pc.automations a
JOIN pc.automation_versions v ON v.org_id = a.org_id AND v.id = a.enabled_version_id
WHERE a.org_id = sqlc.arg(org_id) AND a.state IN ('ACTIVE', 'PAUSED')
  AND v.definition -> 'when' -> 'inbound' ->> 'source' = sqlc.arg(source)::text
  AND v.definition -> 'when' -> 'inbound' ->> 'type' = sqlc.arg(type)::text
ORDER BY a.id;

-- name: AutomationForTrigger :one
SELECT a.id, a.name, a.state, a.rollout, a.service_account_id, a.owner_user_id, a.enabled_version_id::uuid AS version_id,
       v.definition
FROM pc.automations a
JOIN pc.automation_versions v ON v.org_id = a.org_id AND v.id = a.enabled_version_id
WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(id) AND a.state IN ('ACTIVE', 'PAUSED');

-- name: AutomationVersionDefinition :one
SELECT v.automation_id, v.definition, v.state FROM pc.automation_versions v
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id);

-- name: DedupeKeyHeld :one
SELECT EXISTS (
    SELECT 1 FROM pc.automation_dedupe
    WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND key = sqlc.arg(key)
      AND expires_at > now()
) AS held;

-- name: ClaimDedupeKey :one
-- Claims key for trigger_id unless a live claim exists (HR-277); no row
-- means a duplicate.
INSERT INTO pc.automation_dedupe AS d (org_id, automation_id, key, trigger_id, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(automation_id), sqlc.arg(key), sqlc.arg(trigger_id), sqlc.arg(expires_at))
ON CONFLICT (org_id, automation_id, key) DO UPDATE SET trigger_id = EXCLUDED.trigger_id, expires_at = EXCLUDED.expires_at
WHERE d.expires_at <= now()
RETURNING d.trigger_id;

-- name: ReleaseDedupeKeys :exec
-- A trigger whose start was refused gives its keys back.
DELETE FROM pc.automation_dedupe WHERE org_id = sqlc.arg(org_id) AND trigger_id = sqlc.arg(trigger_id);

-- name: PruneAutomationDedupe :execrows
DELETE FROM pc.automation_dedupe
WHERE org_id = sqlc.arg(org_id) AND expires_at <= now();

-- name: UpsertAutomationSchedule :exec
INSERT INTO pc.automation_schedules (org_id, automation_id, version_id, cron, timezone, next_fire_at, state)
VALUES (sqlc.arg(org_id), sqlc.arg(automation_id), sqlc.arg(version_id), sqlc.arg(cron), sqlc.arg(timezone),
        sqlc.narg(next_fire_at), 'ACTIVE')
ON CONFLICT (org_id, automation_id) DO UPDATE
SET version_id = EXCLUDED.version_id, cron = EXCLUDED.cron, timezone = EXCLUDED.timezone,
    next_fire_at = EXCLUDED.next_fire_at, state = 'ACTIVE', updated_at = now();

-- name: DeleteAutomationSchedule :exec
DELETE FROM pc.automation_schedules WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id);

-- name: GetAutomationSchedule :one
SELECT s.org_id, s.automation_id, s.version_id, s.cron, s.timezone, s.next_fire_at, s.last_fire_at, s.state, s.updated_at
FROM pc.automation_schedules s
WHERE s.org_id = sqlc.arg(org_id) AND s.automation_id = sqlc.arg(automation_id);

-- name: SetAutomationScheduleState :execrows
UPDATE pc.automation_schedules
SET state = sqlc.arg(state), next_fire_at = coalesce(sqlc.narg(next_fire_at), next_fire_at), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id);

-- name: ClaimDueSchedules :many
SELECT s.automation_id, s.version_id, s.cron, s.timezone, s.next_fire_at::timestamptz AS next_fire_at, s.last_fire_at
FROM pc.automation_schedules s
WHERE s.org_id = sqlc.arg(org_id) AND s.state = 'ACTIVE' AND s.next_fire_at <= sqlc.arg(now)
ORDER BY s.next_fire_at
LIMIT 100
FOR UPDATE SKIP LOCKED;

-- name: AdvanceAutomationSchedule :execrows
UPDATE pc.automation_schedules
SET next_fire_at = sqlc.narg(next_fire_at), last_fire_at = coalesce(sqlc.narg(last_fire_at), last_fire_at), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND next_fire_at = sqlc.arg(expected);

-- name: EnsureAutomationFeedCursor :one
-- A new cursor starts at the feed's head: nothing recorded before it
-- triggers anything.
WITH ins AS (
    INSERT INTO pc.automation_feed_cursors (org_id, seq) VALUES (sqlc.arg(org_id), sqlc.arg(head))
    ON CONFLICT (org_id) DO NOTHING
    RETURNING seq
)
SELECT seq FROM ins
UNION ALL
SELECT c.seq FROM pc.automation_feed_cursors c WHERE c.org_id = sqlc.arg(org_id)
LIMIT 1;

-- name: AdvanceAutomationFeedCursor :execrows
UPDATE pc.automation_feed_cursors SET seq = sqlc.arg(seq)
WHERE org_id = sqlc.arg(org_id) AND seq = sqlc.arg(expected);

-- name: RunsAutomationExecution :many
-- Runs started by automation executions (D23 ancestry).
SELECT r.id, r.automation_execution_id::uuid AS execution_id FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id) AND r.id = ANY (sqlc.arg(ids)::uuid[]) AND r.automation_execution_id IS NOT NULL;

-- name: GrantsAutomationExecution :many
SELECT g.id, g.automation_execution_id::uuid AS execution_id FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.id = ANY (sqlc.arg(ids)::uuid[]) AND g.automation_execution_id IS NOT NULL;

-- name: ApprovalsAutomationExecution :many
-- Gate requests of automation executions (D23 ancestry, D87 L6).
SELECT a.id, a.execution_id::uuid AS execution_id FROM pc.approval_requests a
WHERE a.org_id = sqlc.arg(org_id) AND a.id = ANY (sqlc.arg(ids)::uuid[]) AND a.execution_id IS NOT NULL;

-- name: ServiceAccountAutomations :many
SELECT s.id, s.automation_id::uuid AS automation_id FROM pc.service_accounts s
WHERE s.org_id = sqlc.arg(org_id) AND s.id = ANY (sqlc.arg(ids)::uuid[]) AND s.automation_id IS NOT NULL;

-- name: UpsertConditionEpisode :one
-- Starts or continues an episode; returns its start and whether it fired.
INSERT INTO pc.automation_condition_state AS c (org_id, automation_id, subject_key, since, seen_at)
VALUES (sqlc.arg(org_id), sqlc.arg(automation_id), sqlc.arg(subject_key), sqlc.arg(now), sqlc.arg(now))
ON CONFLICT (org_id, automation_id, subject_key) DO UPDATE SET seen_at = EXCLUDED.seen_at
RETURNING c.since, c.fired_at;

-- name: MarkConditionFired :execrows
UPDATE pc.automation_condition_state SET fired_at = sqlc.arg(now)
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND subject_key = sqlc.arg(subject_key)
  AND fired_at IS NULL;

-- name: EndConditionEpisodes :execrows
-- Subjects not seen in this evaluation no longer hold: their episodes end.
DELETE FROM pc.automation_condition_state
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND seen_at < sqlc.arg(now);

-- name: ClearConditionEpisodes :exec
DELETE FROM pc.automation_condition_state WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id);

-- name: AddThresholdCount :exec
INSERT INTO pc.automation_threshold_counts AS t (org_id, automation_id, group_key, minute, count, ancestry, depth,
                                                 root_trigger_id)
VALUES (sqlc.arg(org_id), sqlc.arg(automation_id), sqlc.arg(group_key), sqlc.arg(minute), 1, sqlc.arg(ancestry)::uuid[],
        sqlc.arg(depth), sqlc.narg(root_trigger_id))
ON CONFLICT (org_id, automation_id, group_key, minute) DO UPDATE
SET count = t.count + 1,
    -- The distinct union, one past the bound so a too-wide chain is seen.
    ancestry = (SELECT coalesce(array_agg(x), '{}') FROM (
                    SELECT DISTINCT x FROM unnest(t.ancestry || EXCLUDED.ancestry) AS x LIMIT 9) u),
    depth = greatest(t.depth, EXCLUDED.depth),
    root_trigger_id = coalesce(t.root_trigger_id, EXCLUDED.root_trigger_id);

-- name: CountThresholdGroups :one
SELECT count(DISTINCT group_key)::int AS n FROM pc.automation_threshold_counts
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND minute >= sqlc.arg(since);

-- name: ThresholdGroupWindow :one
SELECT coalesce(sum(count), 0)::int AS total, coalesce(max(depth), 0)::int AS depth,
       (SELECT coalesce(array_agg(x), '{}') FROM (
            SELECT DISTINCT unnest(c.ancestry) AS x FROM pc.automation_threshold_counts c
            WHERE c.org_id = sqlc.arg(org_id) AND c.automation_id = sqlc.arg(automation_id)
              AND c.group_key = sqlc.arg(group_key) AND c.minute >= sqlc.arg(since)
            LIMIT 9) u)::uuid[] AS ancestry,
       coalesce((array_agg(root_trigger_id ORDER BY minute) FILTER (WHERE root_trigger_id IS NOT NULL))[1],
                '00000000-0000-0000-0000-000000000000')::uuid AS root_trigger_id
FROM pc.automation_threshold_counts
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND group_key = sqlc.arg(group_key)
  AND minute >= sqlc.arg(since);

-- name: PruneThresholdCounts :execrows
DELETE FROM pc.automation_threshold_counts WHERE org_id = sqlc.arg(org_id) AND minute < sqlc.arg(before);

-- name: InsertEventSource :exec
INSERT INTO pc.automation_event_sources (org_id, id, name, description, types, secret, rate_per_minute, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(types), sqlc.arg(secret),
        sqlc.arg(rate_per_minute), sqlc.arg(created_by));

-- name: GetEventSource :one
SELECT s.org_id, s.id, s.name, s.description, s.types, s.prev_until, s.rate_per_minute, s.state, s.created_by,
       s.created_at, s.activated_by, s.activated_credential, s.activated_at, s.disabled_by, s.disabled_at, s.updated_at
FROM pc.automation_event_sources s
WHERE s.org_id = sqlc.arg(org_id) AND s.id = sqlc.arg(id);

-- name: ListEventSources :many
SELECT s.org_id, s.id, s.name, s.description, s.types, s.prev_until, s.rate_per_minute, s.state, s.created_by,
       s.created_at, s.activated_by, s.activated_credential, s.activated_at, s.disabled_by, s.disabled_at, s.updated_at
FROM pc.automation_event_sources s
WHERE s.org_id = sqlc.arg(org_id)
ORDER BY s.name, s.id
LIMIT 200;

-- name: LoadEventSourceSecrets :one
SELECT s.state, s.types, s.rate_per_minute, s.secret, s.prev_secret, s.prev_until
FROM pc.automation_event_sources s
WHERE s.org_id = sqlc.arg(org_id) AND s.id = sqlc.arg(id);

-- name: ActivateEventSource :execrows
UPDATE pc.automation_event_sources
SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: RotateEventSourceSecret :execrows
UPDATE pc.automation_event_sources
SET secret = sqlc.arg(secret), prev_secret = sqlc.arg(prev_secret), prev_until = now() + interval '24 hours'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
  AND (prev_until IS NULL OR prev_until <= now());

-- name: DisableEventSource :execrows
UPDATE pc.automation_event_sources SET state = 'DISABLED', disabled_by = sqlc.arg(disabled_by)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED';

-- name: InsertEventReceipt :execrows
-- One receipt per webhook-id for seven days; 0 rows means a replay.
INSERT INTO pc.automation_event_receipts (org_id, source_id, webhook_id, type, body_sha256, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(source_id), sqlc.arg(webhook_id), sqlc.arg(type), sqlc.arg(body_sha256),
        now() + interval '7 days')
ON CONFLICT (org_id, source_id, webhook_id) DO UPDATE
SET type = EXCLUDED.type, body_sha256 = EXCLUDED.body_sha256, received_at = now(), expires_at = EXCLUDED.expires_at
WHERE pc.automation_event_receipts.expires_at <= now();

-- name: PruneEventReceipts :execrows
DELETE FROM pc.automation_event_receipts
WHERE org_id = sqlc.arg(org_id) AND expires_at <= now();

-- name: InsertAutomationDestination :exec
INSERT INTO pc.automation_destinations (org_id, id, name, url, internal, purposes, secret, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(url), sqlc.arg(internal), sqlc.arg(purposes),
        sqlc.arg(secret), sqlc.arg(created_by));

-- name: GetAutomationDestination :one
SELECT d.org_id, d.id, d.name, d.url, d.internal, d.purposes, d.prev_until, d.state, d.created_by, d.created_at,
       d.activated_by, d.activated_credential, d.activated_at, d.disabled_by, d.disabled_at, d.updated_at, d.signature_scheme
FROM pc.automation_destinations d
WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(id);

-- name: ListAutomationDestinations :many
SELECT d.org_id, d.id, d.name, d.url, d.internal, d.purposes, d.prev_until, d.state, d.created_by, d.created_at,
       d.activated_by, d.activated_credential, d.activated_at, d.disabled_by, d.disabled_at, d.updated_at, d.signature_scheme
FROM pc.automation_destinations d
WHERE d.org_id = sqlc.arg(org_id)
ORDER BY d.name, d.id
LIMIT 200;

-- name: LoadAutomationDestinationSecrets :one
SELECT d.state, d.url, d.internal, d.purposes, d.secret, d.prev_secret, d.prev_until, d.signature_scheme
FROM pc.automation_destinations d
WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(id);

-- name: ActivateAutomationDestination :execrows
UPDATE pc.automation_destinations
SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: RotateAutomationDestinationSecret :execrows
UPDATE pc.automation_destinations
SET secret = sqlc.arg(secret), prev_secret = sqlc.arg(prev_secret), prev_until = now() + interval '24 hours'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('ACTIVE', 'PAUSED')
  AND (prev_until IS NULL OR prev_until <= now());

-- name: SetAutomationDestinationState :execrows
UPDATE pc.automation_destinations
SET state = sqlc.arg(state), disabled_by = CASE WHEN sqlc.arg(state)::text = 'DISABLED' THEN sqlc.narg(by)::uuid END
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(expected);

-- name: InsertAutomationDelivery :exec
-- The digest is of the body as stored and sent (jsonb text).
INSERT INTO pc.automation_deliveries (org_id, id, destination_id, execution_id, kind, msg_id, body, body_sha256)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(destination_id), sqlc.arg(execution_id), sqlc.arg(kind), sqlc.arg(msg_id),
        sqlc.arg(body)::jsonb, sha256(convert_to(sqlc.arg(body)::jsonb::text, 'UTF8')));

-- name: GetAutomationDelivery :one
SELECT d.id, d.destination_id, d.execution_id, d.kind, d.msg_id, d.state, d.attempts, d.next_attempt_at, d.last_status,
       d.last_error, d.created_at, d.delivered_at
FROM pc.automation_deliveries d
WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(id);

-- name: LockAutomationDelivery :one
SELECT d.id, d.destination_id, d.execution_id, d.kind, d.msg_id, d.body, d.state, d.attempts, d.next_attempt_at
FROM pc.automation_deliveries d
WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(id) AND d.state = 'PENDING' AND d.next_attempt_at <= now()
FOR UPDATE SKIP LOCKED;

-- name: DueAutomationDeliveries :many
SELECT d.id FROM pc.automation_deliveries d
WHERE d.org_id = sqlc.arg(org_id) AND d.state = 'PENDING' AND d.next_attempt_at <= now()
ORDER BY d.next_attempt_at
LIMIT 100;

-- name: MarkAutomationDeliveryDelivered :execrows
UPDATE pc.automation_deliveries
SET state = 'DELIVERED', body = NULL, last_status = sqlc.arg(status), last_error = NULL,
    delivered_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: MarkAutomationDeliveryAttempt :execrows
UPDATE pc.automation_deliveries
SET last_status = sqlc.narg(status), last_error = sqlc.arg(error),
    next_attempt_at = sqlc.arg(next_attempt_at)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: MarkAutomationDeliveryFailed :execrows
UPDATE pc.automation_deliveries
SET state = 'FAILED', body = NULL, last_status = sqlc.narg(status),
    last_error = sqlc.arg(error)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: CaseStatesOfLedgerEntries :many
-- case.closed (D18): the reflex.case ledger entries that close a case.
SELECT e.ledger_entry_id, e.case_id FROM pc.case_entries e
WHERE e.org_id = sqlc.arg(org_id) AND e.ledger_entry_id = ANY (sqlc.arg(ids)::uuid[]) AND e.kind = 'STATE'
  AND e.to_state = 'CLOSED';

-- Condition probes (D19). Each returns at most max_rows subjects; the
-- caller asks for one more than its bound to detect overflow.

-- name: ProbeGrantsExpiring :many
SELECT g.id, g.agent_id, g.principal_user_id, g.principal_sa_id, r.task_ref, r.expires_at, g.automation_execution_id
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.state = 'ACTIVE'
  AND r.expires_at > now() AND r.expires_at <= sqlc.arg(horizon)::timestamptz
ORDER BY r.expires_at, g.id
LIMIT sqlc.arg(max_rows);

-- name: ProbeApprovalsWaiting :many
-- A gate request carries its own execution (D87 L6); an action request
-- the execution of its run.
SELECT a.id, a.subject_kind, a.operation, a.created_at, a.agent_id, a.run_id, a.execution_id AS gate_execution_id,
       ru.automation_execution_id
FROM pc.approval_requests a
LEFT JOIN pc.runs ru ON ru.org_id = a.org_id AND ru.id = a.run_id
WHERE a.org_id = sqlc.arg(org_id) AND a.state IN ('PENDING', 'EVIDENCE_REQUESTED')
ORDER BY a.created_at, a.id
LIMIT sqlc.arg(max_rows);

-- name: ProbeCoverageBelow :many
SELECT c.agent_id, c.connection_id, c.operation, c.state, c.computed_at, c.expires_at FROM (
    SELECT DISTINCT ON (s.agent_id, s.connection_id, s.operation) s.agent_id, s.connection_id, s.operation, s.state,
           s.computed_at, s.expires_at
    FROM pc.coverage_snapshots s WHERE s.org_id = sqlc.arg(org_id)
    ORDER BY s.agent_id, s.connection_id, s.operation, s.id DESC) c
WHERE c.state <> 'ENFORCED' OR c.expires_at <= now()
ORDER BY c.computed_at, c.agent_id, c.connection_id, c.operation
LIMIT sqlc.arg(max_rows);

-- name: ProbeRunsLongRunning :many
SELECT r.id, r.agent_id, r.created_at, r.automation_execution_id
FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id) AND r.state = 'ACTIVE' AND r.expires_at > now()
ORDER BY r.created_at, r.id
LIMIT sqlc.arg(max_rows);

-- name: ProbeAgentsUnclaimed :many
SELECT a.id, a.created_at FROM pc.agents a
WHERE a.org_id = sqlc.arg(org_id) AND a.state = 'DISCOVERED' AND a.claimed_at IS NULL
ORDER BY a.created_at, a.id
LIMIT sqlc.arg(max_rows);

-- name: CountRefusalsSince :one
-- Grouped refusals (D16, D23): earlier refusals of this state for the
-- automation since a time (LIMIT: the hour), or of this root (LOOP).
SELECT count(*)::int AS n FROM pc.automation_triggers
WHERE org_id = sqlc.arg(org_id) AND state = sqlc.arg(state) AND id <> sqlc.arg(except_id)
  AND (sqlc.narg(automation_id)::uuid IS NULL OR automation_id = sqlc.narg(automation_id)::uuid)
  AND (sqlc.narg(root_trigger_id)::uuid IS NULL OR root_trigger_id = sqlc.narg(root_trigger_id)::uuid)
  AND received_at >= sqlc.arg(since);

-- name: PostponeAutomationDelivery :execrows
-- A paused destination keeps its deliveries waiting without spending
-- attempts.
UPDATE pc.automation_deliveries SET next_attempt_at = sqlc.arg(next_attempt_at), last_error = 'destination_paused'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: DedupeClaim :one
-- The trigger holding a live key (a repeated manual start returns it).
SELECT d.trigger_id FROM pc.automation_dedupe d
WHERE d.org_id = sqlc.arg(org_id) AND d.automation_id = sqlc.arg(automation_id) AND d.key = sqlc.arg(key)
  AND d.expires_at > now();

-- name: LeaseAutomationDelivery :one
-- Takes a delivery for one send (D87 L11): no other sender picks it up
-- before the lease ends, even if this one never records the outcome. The
-- lease counts the attempt before the POST (D97 N1), so a delivery with
-- attempts > 0 may have reached its destination.
UPDATE pc.automation_deliveries SET next_attempt_at = now() + interval '2 minutes', attempts = attempts + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING'
RETURNING attempts;

-- name: CancelAutomationDelivery :execrows
-- The engine's cleanup cancels a delivery that has not been sent (D89):
-- never one an attempt was leased for (D97 N1).
UPDATE pc.automation_deliveries SET state = 'FAILED', body = NULL, last_error = sqlc.arg(code)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND attempts = 0;

-- name: SetAutomationDestinationSignatureScheme :one
-- Opts a destination in to or out of Ed25519 signatures (G0 M20 D251,
-- HR-510); it returns the previous scheme for the audit entry.
WITH old AS (
    SELECT d.id, d.signature_scheme FROM pc.automation_destinations d
    WHERE d.org_id = sqlc.arg(org_id) AND d.id = sqlc.arg(id) AND d.state <> 'DISABLED'
    FOR UPDATE
)
UPDATE pc.automation_destinations d SET signature_scheme = sqlc.arg(scheme), updated_at = now()
FROM old
WHERE d.org_id = sqlc.arg(org_id) AND d.id = old.id
RETURNING old.signature_scheme AS previous;
