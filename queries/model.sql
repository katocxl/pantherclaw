-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Optional model drafting (G0 M21 D304, D309).

-- name: EnsureModelSettings :exec
INSERT INTO pc.model_settings (org_id) VALUES (sqlc.arg(org_id)) ON CONFLICT (org_id) DO NOTHING;

-- name: GetModelSettings :one
SELECT * FROM pc.model_settings WHERE org_id = sqlc.arg(org_id);

-- name: LockModelSettings :one
SELECT * FROM pc.model_settings WHERE org_id = sqlc.arg(org_id) FOR UPDATE;

-- name: EnableModelDrafting :execrows
UPDATE pc.model_settings
SET enabled = true, enabled_at = now(), enabled_by = sqlc.arg(enabled_by), enabled_credential = sqlc.arg(enabled_credential),
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND key_ciphertext IS NOT NULL;

-- name: DisableModelDrafting :execrows
UPDATE pc.model_settings SET enabled = false, updated_at = now() WHERE org_id = sqlc.arg(org_id) AND enabled;

-- name: SetModelKey :exec
UPDATE pc.model_settings
SET key_ciphertext = sqlc.arg(key_ciphertext), key_set_at = now(), key_set_by = sqlc.arg(key_set_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id);

-- name: ClearModelKey :execrows
UPDATE pc.model_settings
SET key_ciphertext = NULL, key_set_at = NULL, key_set_by = NULL, enabled = false, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND key_ciphertext IS NOT NULL;

-- name: SetModelLimits :exec
UPDATE pc.model_settings
SET model = sqlc.arg(model), calls_per_minute = sqlc.narg(calls_per_minute), tokens_per_day = sqlc.narg(tokens_per_day),
    updated_at = now()
WHERE org_id = sqlc.arg(org_id);

-- name: CountModelCallsSince :one
SELECT count(*) FROM pc.model_calls WHERE org_id = sqlc.arg(org_id) AND created_at >= sqlc.arg(since);

-- name: SumModelTokensSince :one
SELECT COALESCE(sum(input_tokens + output_tokens + reserved_tokens), 0)::bigint
FROM pc.model_calls
WHERE org_id = sqlc.arg(org_id) AND created_at >= sqlc.arg(since);

-- name: InsertModelCall :exec
INSERT INTO pc.model_calls (org_id, id, actor, task, model, reserved_tokens)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(actor), sqlc.arg(task), sqlc.arg(model), sqlc.arg(reserved_tokens));

-- name: FinishModelCall :execrows
UPDATE pc.model_calls
SET outcome = sqlc.arg(outcome), input_tokens = sqlc.arg(input_tokens), output_tokens = sqlc.arg(output_tokens),
    reserved_tokens = sqlc.arg(reserved_tokens), finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND outcome = 'PENDING';

-- name: InsertModelDraft :exec
INSERT INTO pc.model_drafts (org_id, version_id, call_id, kind, ambiguities)
VALUES (sqlc.arg(org_id), sqlc.arg(version_id), sqlc.arg(call_id), sqlc.arg(kind), sqlc.arg(ambiguities));

-- name: GetModelDraft :one
SELECT * FROM pc.model_drafts WHERE org_id = sqlc.arg(org_id) AND version_id = sqlc.arg(version_id);

-- ListModelDrafts lists stored drafts of the given kinds, newest first (G0
-- M22 D8). Version ids are v7 and each is drafted once, so the id is the page
-- cursor.
-- name: ListModelDrafts :many
SELECT * FROM pc.model_drafts
WHERE org_id = sqlc.arg(org_id) AND kind = ANY (sqlc.arg(kinds)::text[])
  AND (sqlc.narg(after)::uuid IS NULL OR version_id < sqlc.narg(after)::uuid)
ORDER BY version_id DESC
LIMIT sqlc.arg(page_limit);

-- ModelUsage sums the org's calls since a time by task and outcome: counts
-- and tokens only (G0 M22 D8). pc.model_calls holds no text.
-- name: ModelUsage :many
SELECT task, outcome, count(*)::bigint AS calls, COALESCE(sum(input_tokens), 0)::bigint AS input_tokens,
       COALESCE(sum(output_tokens), 0)::bigint AS output_tokens, COALESCE(sum(reserved_tokens), 0)::bigint AS reserved_tokens
FROM pc.model_calls
WHERE org_id = sqlc.arg(org_id) AND created_at >= sqlc.arg(since)
GROUP BY task, outcome
ORDER BY task, outcome;
