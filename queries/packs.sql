-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Evidence packs (G0 M7 design decision 15, HR-196). Every query runs
-- inside db.InTenantTx and also filters by org_id explicitly.

-- name: InsertEvidencePack :exec
INSERT INTO pc.evidence_packs (org_id, id, created_by, scope_kind, scope, include)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(created_by), sqlc.arg(scope_kind), sqlc.arg(scope), sqlc.arg(include));

-- name: GetEvidencePack :one
-- A pack without its content.
SELECT id, created_by, scope_kind, scope, include, state, error_code, manifest, content_sha256, content_size, items,
       created_at, ready_at, expires_at
FROM pc.evidence_packs
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListEvidencePacks :many
-- Packs newest first, all of them or one person's, without content.
SELECT id, created_by, scope_kind, scope, include, state, error_code, manifest, content_sha256, content_size, items,
       created_at, ready_at, expires_at
FROM pc.evidence_packs
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(created_by)::uuid IS NULL OR created_by = sqlc.narg(created_by)::uuid)
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000'
       OR id < sqlc.arg(before)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);

-- name: PackCreatorState :one
-- Whether the pack's creator is still an active person of the org.
SELECT state FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: GetEvidencePackContent :one
SELECT created_by, state, content, content_sha256, content_size, expires_at
FROM pc.evidence_packs
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: MarkEvidencePackReady :execrows
-- HR-004: only a pack being built becomes ready, once; it can be
-- downloaded for 7 days.
UPDATE pc.evidence_packs
SET state = 'READY', manifest = sqlc.arg(manifest), manifest_sha256 = sqlc.arg(manifest_sha256), content = sqlc.arg(content),
    content_sha256 = sqlc.arg(content_sha256), content_size = sqlc.arg(content_size), items = sqlc.arg(items),
    ready_at = sqlc.arg(ready_at), expires_at = sqlc.arg(ready_at)::timestamptz + interval '7 days'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'BUILDING';

-- name: MarkEvidencePackFailed :execrows
UPDATE pc.evidence_packs
SET state = 'FAILED', error_code = sqlc.arg(error_code)::text
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'BUILDING';

-- name: ExpireEvidencePacks :execrows
-- Ready packs past their 7 days lose their content.
UPDATE pc.evidence_packs
SET state = 'EXPIRED', content = NULL
WHERE org_id = sqlc.arg(org_id) AND state = 'READY' AND expires_at <= now();

-- name: PackContainmentEvents :many
-- Containment and restoration events of the org in a time window (F529).
SELECT id, kind, occurred_at, body
FROM pc.ledger_entries
WHERE org_id = sqlc.arg(org_id) AND kind = ANY (sqlc.arg(kinds)::text[])
  AND occurred_at >= sqlc.arg(from_time) AND occurred_at < sqlc.arg(to_time)
ORDER BY occurred_at, id
LIMIT sqlc.arg(max_rows);

-- name: PackAgentChanges :many
-- Suspensions, restorations and retirements of the given agents in a time
-- window (F529).
SELECT id, agent_id, kind, created_at
FROM pc.agent_changes
WHERE org_id = sqlc.arg(org_id) AND agent_id = ANY (sqlc.arg(agent_ids)::uuid[])
  AND kind IN ('agent.suspended', 'agent.restored', 'agent.retired')
  AND created_at >= sqlc.arg(from_time) AND created_at < sqlc.arg(to_time)
ORDER BY created_at, id
LIMIT sqlc.arg(max_rows);

-- name: PackApprovalRequests :many
-- The approval requests that held the given transactions.
SELECT id, transaction_id, evaluation, agent_id, operation, state, end_reason, created_at, deadline_at, approved_at,
       consumed_at, ended_at
FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND transaction_id = ANY (sqlc.arg(transaction_ids)::uuid[])
ORDER BY created_at, id;

-- name: PackApprovalResponses :many
-- Who responded to those requests, how, and whether with a security key.
SELECT id, request_id, user_id, kind, requirement, reason_code, alternative_code, (signature IS NOT NULL)::boolean AS asserted,
       created_at, voided_at, void_reason
FROM pc.approval_responses
WHERE org_id = sqlc.arg(org_id) AND request_id = ANY (sqlc.arg(request_ids)::uuid[])
ORDER BY created_at, id;
