-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Detection engine queries (G0 M10 D10, D13; HR-240, HR-241). Every query
-- runs inside db.InTenantTx and also filters by org_id explicitly.

-- name: EnsureDetectionCursor :one
-- A new cursor starts at the feed's head: detection never replays an
-- org's history when it is first enabled (D59 M4).
INSERT INTO pc.detection_cursors (org_id, seq)
VALUES (sqlc.arg(org_id), coalesce((SELECT h.seq FROM pc.ledger_heads h WHERE h.org_id = sqlc.arg(org_id)), 0))
ON CONFLICT (org_id) DO UPDATE SET org_id = EXCLUDED.org_id
RETURNING seq;

-- name: AdvanceDetectionCursor :execrows
-- Compare-and-set: only the job that read old moves the cursor (HR-240).
UPDATE pc.detection_cursors SET seq = sqlc.arg(next_seq), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND seq = sqlc.arg(old_seq) AND sqlc.arg(next_seq) > sqlc.arg(old_seq);

-- name: GetDetectionCursor :one
SELECT seq, updated_at FROM pc.detection_cursors WHERE org_id = sqlc.arg(org_id);

-- name: DetectionRuleStates :many
SELECT rule_id, consecutive_errors, last_error, disabled_at, disabled_reason, overflow_reported_on
FROM pc.detection_rule_state WHERE org_id = sqlc.arg(org_id);

-- name: SetDetectionRuleErrors :exec
INSERT INTO pc.detection_rule_state (org_id, rule_id, consecutive_errors, last_error)
VALUES (sqlc.arg(org_id), sqlc.arg(rule_id), sqlc.arg(consecutive_errors), sqlc.narg(last_error))
ON CONFLICT (org_id, rule_id) DO UPDATE SET consecutive_errors = EXCLUDED.consecutive_errors,
    last_error = coalesce(EXCLUDED.last_error, pc.detection_rule_state.last_error), updated_at = now();

-- name: DisableDetectionRule :execrows
UPDATE pc.detection_rule_state SET disabled_at = now(), disabled_reason = sqlc.arg(reason), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND disabled_at IS NULL;

-- name: EnableDetectionRule :execrows
UPDATE pc.detection_rule_state SET disabled_at = NULL, disabled_reason = NULL, consecutive_errors = 0, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND disabled_at IS NOT NULL;

-- name: MarkDetectionOverflow :execrows
-- One overflow report per rule per day (D10): true only for the first.
INSERT INTO pc.detection_rule_state (org_id, rule_id, overflow_reported_on)
VALUES (sqlc.arg(org_id), sqlc.arg(rule_id), sqlc.arg(day)::date)
ON CONFLICT (org_id, rule_id) DO UPDATE SET overflow_reported_on = EXCLUDED.overflow_reported_on, updated_at = now()
WHERE pc.detection_rule_state.overflow_reported_on IS DISTINCT FROM EXCLUDED.overflow_reported_on;

-- name: DetectionWindowGroupKnown :one
SELECT EXISTS (
    SELECT 1 FROM pc.detection_window_groups
    WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND group_key = sqlc.arg(group_key)
)::bool;

-- name: EnsureDetectionRuleState :one
-- The rule's state row, created on first use, with its counters (D59 M5).
INSERT INTO pc.detection_rule_state (org_id, rule_id) VALUES (sqlc.arg(org_id), sqlc.arg(rule_id))
ON CONFLICT (org_id, rule_id) DO UPDATE SET rule_id = EXCLUDED.rule_id
RETURNING window_groups, seen_keys;

-- name: TouchDetectionWindowGroup :one
-- Records a group as live; inserted reports a new group, counted below.
INSERT INTO pc.detection_window_groups (org_id, rule_id, group_key, last_bucket)
VALUES (sqlc.arg(org_id), sqlc.arg(rule_id), sqlc.arg(group_key), sqlc.arg(bucket))
ON CONFLICT (org_id, rule_id, group_key) DO UPDATE
    SET last_bucket = greatest(pc.detection_window_groups.last_bucket, EXCLUDED.last_bucket)
RETURNING (xmax = 0)::bool AS inserted;

-- name: CountDetectionWindowGroup :exec
UPDATE pc.detection_rule_state SET window_groups = window_groups + 1
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id);

-- name: CountDetectionSeenKey :exec
UPDATE pc.detection_rule_state SET seen_keys = seen_keys + 1
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id);

-- name: PruneDetectionWindowGroups :exec
WITH gone AS (
    DELETE FROM pc.detection_window_groups
    WHERE org_id = sqlc.arg(org_id) AND last_bucket < sqlc.arg(before)
    RETURNING rule_id
), n AS (SELECT rule_id, count(*)::int AS c FROM gone GROUP BY rule_id)
UPDATE pc.detection_rule_state s SET window_groups = greatest(s.window_groups - n.c, 0)
FROM n WHERE s.org_id = sqlc.arg(org_id) AND s.rule_id = n.rule_id;

-- name: AddDetectionWindowEvent :exec
INSERT INTO pc.detection_window_buckets (org_id, rule_id, group_key, bucket, n, distinct_values)
VALUES (sqlc.arg(org_id), sqlc.arg(rule_id), sqlc.arg(group_key), sqlc.arg(bucket), 1,
        CASE WHEN sqlc.arg(distinct_value)::text = '' THEN '{}'::text[] ELSE ARRAY[sqlc.arg(distinct_value)::text] END)
ON CONFLICT (org_id, rule_id, group_key, bucket) DO UPDATE SET
    n = pc.detection_window_buckets.n + 1,
    distinct_values = CASE
        WHEN sqlc.arg(distinct_value)::text = ''
             OR sqlc.arg(distinct_value)::text = ANY (pc.detection_window_buckets.distinct_values)
             OR cardinality(pc.detection_window_buckets.distinct_values) >= 1000
            THEN pc.detection_window_buckets.distinct_values
        ELSE array_append(pc.detection_window_buckets.distinct_values, sqlc.arg(distinct_value)::text)
    END;

-- name: DetectionWindowCount :one
SELECT coalesce(sum(n), 0)::int AS events,
       (SELECT count(DISTINCT v) FROM pc.detection_window_buckets b2, unnest(b2.distinct_values) v
        WHERE b2.org_id = sqlc.arg(org_id) AND b2.rule_id = sqlc.arg(rule_id) AND b2.group_key = sqlc.arg(group_key)
          AND b2.bucket > sqlc.arg(since))::int AS distinct_values
FROM pc.detection_window_buckets
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND group_key = sqlc.arg(group_key) AND bucket > sqlc.arg(since);

-- name: PruneDetectionWindows :execrows
DELETE FROM pc.detection_window_buckets WHERE org_id = sqlc.arg(org_id) AND bucket < sqlc.arg(before);

-- name: GetDetectionSeen :one
SELECT last_seen FROM pc.detection_seen
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND key_hash = sqlc.arg(key_hash);

-- name: UpsertDetectionSeen :exec
INSERT INTO pc.detection_seen (org_id, rule_id, key_hash, first_seen, last_seen)
VALUES (sqlc.arg(org_id), sqlc.arg(rule_id), sqlc.arg(key_hash), sqlc.arg(at), sqlc.arg(at))
ON CONFLICT (org_id, rule_id, key_hash) DO UPDATE SET last_seen = greatest(pc.detection_seen.last_seen, EXCLUDED.last_seen);

-- name: PruneDetectionSeen :exec
WITH gone AS (
    DELETE FROM pc.detection_seen WHERE org_id = sqlc.arg(org_id) AND last_seen < sqlc.arg(before)
    RETURNING rule_id
), n AS (SELECT rule_id, count(*)::int AS c FROM gone GROUP BY rule_id)
UPDATE pc.detection_rule_state s SET seen_keys = greatest(s.seen_keys - n.c, 0)
FROM n WHERE s.org_id = sqlc.arg(org_id) AND s.rule_id = n.rule_id;

-- name: GetDetectionSequence :one
SELECT step, started_at, updated_at, evidence FROM pc.detection_sequences
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND group_key = sqlc.arg(group_key);

-- name: UpsertDetectionSequence :exec
INSERT INTO pc.detection_sequences (org_id, rule_id, group_key, step, started_at, updated_at, evidence)
VALUES (sqlc.arg(org_id), sqlc.arg(rule_id), sqlc.arg(group_key), sqlc.arg(step), sqlc.arg(started_at), sqlc.arg(updated_at),
        sqlc.arg(evidence)::uuid[])
ON CONFLICT (org_id, rule_id, group_key) DO UPDATE SET step = EXCLUDED.step, started_at = EXCLUDED.started_at,
    updated_at = EXCLUDED.updated_at, evidence = EXCLUDED.evidence;

-- name: DeleteDetectionSequence :exec
DELETE FROM pc.detection_sequences WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND group_key = sqlc.arg(group_key);

-- name: PruneDetectionSequences :execrows
DELETE FROM pc.detection_sequences WHERE org_id = sqlc.arg(org_id) AND started_at < sqlc.arg(before);

-- name: PublishedCustomRules :many
-- Published custom rules with the digest their publication recorded: in
-- detection_rule_versions (append-only, retention-safe) and in the ledger
-- entry, bound to its kind and to the rule (HR-241, D59 L2). The ledger
-- digest is empty when retention removed the body.
SELECT r.id, r.rule_id, r.version, r.content, r.content_digest,
       coalesce(v.content_digest, ''::bytea)::bytea AS recorded_digest,
       (e.id IS NOT NULL)::bool AS ledger_present,
       (e.body_removed_at IS NOT NULL)::bool AS ledger_body_removed,
       coalesce(CASE WHEN e.body_removed_at IS NULL
                     THEN convert_from(e.body, 'UTF8')::jsonb -> 'details' ->> 'content_digest' END, '')::text AS ledger_digest
FROM pc.custom_detection_rules r
LEFT JOIN pc.detection_rule_versions v ON v.org_id = r.org_id AND v.rule = r.id
LEFT JOIN pc.ledger_entries e ON e.org_id = r.org_id AND e.id = r.ledger_entry_id
    AND e.kind = 'audit.detection.rule_published'
    AND (e.body_removed_at IS NOT NULL
         OR convert_from(e.body, 'UTF8')::jsonb -> 'object' ->> 'id' = r.rule_id)
WHERE r.org_id = sqlc.arg(org_id) AND r.state = 'PUBLISHED'
ORDER BY r.rule_id;

-- name: InsertCustomRule :one
INSERT INTO pc.custom_detection_rules (org_id, id, rule_id, version, content, content_digest, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(rule_id),
        coalesce((SELECT max(version) FROM pc.custom_detection_rules
                  WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id)), 0) + 1,
        sqlc.arg(content), sqlc.arg(content_digest), sqlc.arg(created_by))
RETURNING *;

-- name: GetCustomRule :one
SELECT * FROM pc.custom_detection_rules WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockCustomRule :one
SELECT * FROM pc.custom_detection_rules WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListCustomRules :many
SELECT * FROM pc.custom_detection_rules
WHERE org_id = sqlc.arg(org_id)
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000'
       OR id < sqlc.arg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: CountPublishedCustomRules :one
SELECT count(*)::int FROM pc.custom_detection_rules WHERE org_id = sqlc.arg(org_id) AND state = 'PUBLISHED';

-- name: PublishCustomRule :execrows
UPDATE pc.custom_detection_rules
SET state = 'PUBLISHED', published_by = sqlc.arg(published_by), published_at = now(), ledger_entry_id = sqlc.arg(ledger_entry_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'DRAFT';

-- name: DisableCustomRule :execrows
UPDATE pc.custom_detection_rules
SET state = 'DISABLED', disabled_by = sqlc.narg(disabled_by), disabled_at = now(), disabled_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('DRAFT', 'PUBLISHED');

-- name: DisablePublishedCustomRule :many
UPDATE pc.custom_detection_rules
SET state = 'DISABLED', disabled_by = sqlc.arg(disabled_by), disabled_at = now(), disabled_reason = 'superseded by a newer version'
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND state = 'PUBLISHED'
RETURNING id;

-- name: InsertCustomRuleTest :exec
INSERT INTO pc.custom_detection_rule_tests (org_id, id, rule, passed, firing, non_firing, results, run_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(rule), sqlc.arg(passed), sqlc.arg(firing), sqlc.arg(non_firing),
        sqlc.arg(results), sqlc.arg(run_by));

-- name: InsertDetectionRuleVersion :exec
INSERT INTO pc.detection_rule_versions (org_id, rule, rule_id, version, content_digest, ledger_entry_id, published_by)
VALUES (sqlc.arg(org_id), sqlc.arg(rule), sqlc.arg(rule_id), sqlc.arg(version), sqlc.arg(content_digest),
        sqlc.arg(ledger_entry_id), sqlc.arg(published_by));

-- name: LockCustomRulePublishing :exec
-- Serialises an org's publishes so the 100-rule cap holds (D59 L3).
SELECT pg_advisory_xact_lock(hashtextextended('detection.publish:' || sqlc.arg(org_id)::uuid::text, 0));
