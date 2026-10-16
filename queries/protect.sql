-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Protected changes and compromised publishers (G0 M11 part 2 D42, D43;
-- HR-292, HR-293).

-- name: ProtectedCategoryMode :one
-- No row: the category is OFF.
SELECT coalesce((SELECT mode FROM pc.protected_change_settings
                 WHERE org_id = sqlc.arg(org_id) AND category = sqlc.arg(category)), 'OFF')::text;

-- name: ListProtectedChangeSettings :many
SELECT category, mode, updated_by, updated_at
FROM pc.protected_change_settings
WHERE org_id = sqlc.arg(org_id)
ORDER BY category;

-- name: LockProtectedChangeSettings :exec
-- Serializes changes to an org's settings (the org row is the lock).
SELECT 1 FROM pc.orgs WHERE id = sqlc.arg(org_id) FOR NO KEY UPDATE;

-- name: SetProtectedCategoryMode :exec
INSERT INTO pc.protected_change_settings (org_id, category, mode, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(category), sqlc.arg(mode), sqlc.arg(updated_by))
ON CONFLICT (org_id, category) DO UPDATE SET mode = excluded.mode, updated_by = excluded.updated_by, updated_at = now();

-- name: InsertProtectedChange :one
INSERT INTO pc.protected_changes (org_id, id, category, surface, subject_id, subject, summary, widening, digest, subject_digest, payload,
                                  author, author_credential, state, publisher)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(category), sqlc.arg(surface), sqlc.arg(subject_id), sqlc.arg(subject),
        sqlc.arg(summary), sqlc.arg(widening)::text[], sqlc.arg(digest), sqlc.arg(subject_digest), sqlc.arg(payload), sqlc.arg(author),
        sqlc.arg(author_credential), sqlc.arg(state), sqlc.narg(publisher))
RETURNING *;

-- name: VoidPendingProtectedChanges :many
-- Voids the pending changes of one subject (a newer change replaces them)
-- and returns their change requests.
UPDATE pc.protected_changes SET state = 'VOIDED', decided_reason = sqlc.arg(reason)::text
WHERE org_id = sqlc.arg(org_id) AND surface = sqlc.arg(surface) AND subject_id = sqlc.arg(subject_id) AND state = 'PENDING'
RETURNING id, change_request_id;

-- name: VoidPendingProtectedChangesBy :many
-- Voids every pending change a person authored (they were marked
-- compromised).
UPDATE pc.protected_changes SET state = 'VOIDED', decided_reason = sqlc.arg(reason)::text
WHERE org_id = sqlc.arg(org_id) AND author = sqlc.arg(author) AND state = 'PENDING'
RETURNING id, change_request_id;

-- name: SetProtectedChangeRequest :execrows
UPDATE pc.protected_changes SET change_request_id = sqlc.arg(change_request_id)::uuid
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND change_request_id IS NULL;

-- name: GetProtectedChange :one
SELECT * FROM pc.protected_changes WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockProtectedChange :one
SELECT * FROM pc.protected_changes WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ProtectedChangeOfRequest :one
SELECT * FROM pc.protected_changes
WHERE org_id = sqlc.arg(org_id) AND (change_request_id = sqlc.arg(request_id)::uuid OR review_request_id = sqlc.arg(request_id)::uuid)
FOR UPDATE;

-- name: DecideProtectedChange :one
-- Moves a pending change to APPLIED, EMERGENCY, DECLINED, EXPIRED or VOIDED.
UPDATE pc.protected_changes
SET state = sqlc.arg(state), publisher = sqlc.narg(publisher), decided_reason = sqlc.narg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING'
RETURNING *;

-- name: SetEmergencyReviewRequest :execrows
UPDATE pc.protected_changes SET review_request_id = sqlc.arg(review_request_id)::uuid
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'EMERGENCY' AND reviewed_by IS NULL;

-- name: ReviewEmergencyChange :execrows
UPDATE pc.protected_changes SET reviewed_by = sqlc.arg(reviewed_by)::uuid
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'EMERGENCY' AND reviewed_by IS NULL
  AND publisher <> sqlc.arg(reviewed_by)::uuid AND author <> sqlc.arg(reviewed_by)::uuid;

-- name: ListProtectedChanges :many
SELECT * FROM pc.protected_changes
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
  AND (sqlc.narg(category)::text IS NULL OR category = sqlc.narg(category)::text)
  AND (sqlc.narg(before_id)::uuid IS NULL OR id < sqlc.narg(before_id)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows)::int;

-- name: OverdueEmergencyChanges :many
-- Emergency changes past their 72-hour review without one.
SELECT * FROM pc.protected_changes
WHERE org_id = sqlc.arg(org_id) AND state = 'EMERGENCY' AND reviewed_by IS NULL AND review_due_at < now()
ORDER BY review_due_at
LIMIT 100;

-- name: InsertCompromisedPublisher :one
INSERT INTO pc.compromised_publishers (org_id, id, user_id, since, reason, marked_by, marked_credential)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(since), sqlc.arg(reason), sqlc.arg(marked_by),
        sqlc.arg(marked_credential))
RETURNING *;

-- name: UserCompromised :one
SELECT EXISTS (SELECT 1 FROM pc.compromised_publishers
               WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND state = 'ACTIVE');

-- name: GetCompromisedPublisher :one
SELECT * FROM pc.compromised_publishers WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockCompromisedPublisher :one
SELECT * FROM pc.compromised_publishers WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: CompromiseOfClearRequest :one
SELECT * FROM pc.compromised_publishers
WHERE org_id = sqlc.arg(org_id) AND clear_request_id = sqlc.arg(request_id)::uuid
FOR UPDATE;

-- name: ListCompromisedPublishers :many
SELECT * FROM pc.compromised_publishers
WHERE org_id = sqlc.arg(org_id) AND (NOT sqlc.arg(active_only)::bool OR state = 'ACTIVE')
ORDER BY marked_at DESC
LIMIT sqlc.arg(max_rows)::int;

-- name: SetCompromiseClearRequest :execrows
UPDATE pc.compromised_publishers SET clear_request_id = sqlc.arg(clear_request_id)::uuid
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: ClearCompromisedPublisher :execrows
UPDATE pc.compromised_publishers SET state = 'CLEARED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: InsertCompromiseReview :execrows
-- Zero rows: the item was already reviewed.
INSERT INTO pc.compromise_reviews (org_id, compromise_id, item_kind, item_id, decision, reviewer, note)
VALUES (sqlc.arg(org_id), sqlc.arg(compromise_id), sqlc.arg(item_kind), sqlc.arg(item_id), sqlc.arg(decision),
        sqlc.arg(reviewer), sqlc.narg(note))
ON CONFLICT (org_id, compromise_id, item_kind, item_id) DO NOTHING;

-- name: ListCompromiseReviews :many
SELECT * FROM pc.compromise_reviews
WHERE org_id = sqlc.arg(org_id) AND compromise_id = sqlc.arg(compromise_id)
ORDER BY reviewed_at;

-- What a person published since a time (D43 ListExposed). Each query
-- returns the item's id, a short label and when.

-- name: ExposedPolicyVersions :many
SELECT id::text AS item_id, ('policy version ' || version::text)::text AS label, published_at AS at
FROM pc.policy_versions
WHERE org_id = sqlc.arg(org_id) AND published_by = sqlc.arg(principal)::text AND published_at >= sqlc.arg(since)::timestamptz
ORDER BY published_at
LIMIT 1000;

-- name: ExposedPolicyChanges :many
SELECT r.id::text AS item_id, (lower(r.kind) || ' ' || r.state)::text AS label, c.created_at AS at
FROM pc.policy_change_confirmations c
JOIN pc.policy_change_requests r ON r.org_id = c.org_id AND r.id = c.request_id
WHERE c.org_id = sqlc.arg(org_id) AND c.principal_id = sqlc.arg(user_id) AND c.created_at >= sqlc.arg(since)
ORDER BY c.created_at
LIMIT 1000;

-- name: ExposedPackageActivations :many
-- package.transitioned to ACTIVE by the person, from the audit trail.
SELECT (convert_from(body, 'UTF8')::jsonb #>> '{object,id}')::text AS item_id,
       ('package ' || (convert_from(body, 'UTF8')::jsonb #>> '{object,id}'))::text AS label, occurred_at AS at
FROM pc.ledger_entries
WHERE org_id = sqlc.arg(org_id) AND kind = 'audit.package.transitioned' AND actor_type = 'user'
  AND actor_id = sqlc.arg(actor_id) AND occurred_at >= sqlc.arg(since)
  AND convert_from(body, 'UTF8')::jsonb #>> '{details,to}' = 'ACTIVE'
ORDER BY occurred_at
LIMIT 1000;

-- name: ExposedPackageKeys :many
SELECT kid AS item_id, ('package-signing key ' || name || ' (' || state || ')')::text AS label, created_at AS at
FROM pc.package_signing_keys
WHERE org_id = sqlc.arg(org_id) AND created_by = sqlc.arg(principal) AND created_at >= sqlc.arg(since)
ORDER BY created_at
LIMIT 1000;

-- name: ExposedProtectedChanges :many
SELECT id::text AS item_id, (lower(category) || ' ' || subject)::text AS label, decided_at::timestamptz AS at
FROM pc.protected_changes
WHERE org_id = sqlc.arg(org_id) AND state IN ('APPLIED', 'EMERGENCY') AND decided_at >= sqlc.arg(since)::timestamptz
  AND (publisher = sqlc.arg(user_id)::uuid OR reviewed_by = sqlc.arg(user_id)::uuid)
ORDER BY decided_at
LIMIT 1000;

-- name: ExposedGrants :many
SELECT id::text AS item_id, ('grant (' || state || ')')::text AS label, created_at AS at
FROM pc.grants
WHERE org_id = sqlc.arg(org_id) AND grantor_kind = 'user' AND grantor_id = sqlc.arg(user_id) AND created_at >= sqlc.arg(since)
ORDER BY created_at
LIMIT 1000;

-- name: GetProtectedChangeByRequest :one
SELECT * FROM pc.protected_changes
WHERE org_id = sqlc.arg(org_id) AND (change_request_id = sqlc.arg(request_id)::uuid OR review_request_id = sqlc.arg(request_id)::uuid);

-- name: CompromisedAmong :many
-- The people among ids marked compromised now (approvals eligibility).
SELECT DISTINCT user_id FROM pc.compromised_publishers
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND user_id = ANY (sqlc.arg(user_ids)::uuid[]);

-- name: PendingPolicyChangeRequestsBy :many
-- A person's pending M11.1 policy change requests (voided when they are
-- marked compromised).
SELECT id FROM pc.policy_change_requests
WHERE org_id = sqlc.arg(org_id) AND requested_by = sqlc.arg(principal)::text AND state = 'PENDING'
FOR UPDATE;

-- name: PolicyRolloutConfirmedBy :one
-- Whether the person created the rollout or confirmed a request of it
-- (its pilot's ROLLOUT, its version's PUBLISH).
SELECT (EXISTS (
    SELECT 1 FROM pc.policy_rollouts r
    WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(rollout_id) AND r.created_by = sqlc.arg(principal)::text
) OR EXISTS (
    SELECT 1 FROM pc.policy_change_confirmations c
    JOIN pc.policy_change_requests q ON q.org_id = c.org_id AND q.id = c.request_id
    WHERE c.org_id = sqlc.arg(org_id) AND c.principal_id = sqlc.arg(user_id)::uuid
      AND ((q.kind = 'ROLLOUT' AND q.subject_id = sqlc.arg(rollout_id)) OR (q.kind = 'PUBLISH' AND q.subject_id = sqlc.arg(version_id)))
))::bool;

-- name: PolicyVersionBefore :one
-- The version published before a version (a ROLLBACK review's target) and
-- whether that version is the published one now.
SELECT p.id AS before_id, (v.state = 'PUBLISHED')::bool AS current
FROM pc.policy_versions v
JOIN pc.policy_versions p ON p.org_id = v.org_id AND p.published_at < v.published_at
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id)
ORDER BY p.published_at DESC
LIMIT 1;
