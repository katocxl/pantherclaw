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
SELECT COALESCE(sum(input_tokens + output_tokens), 0)::bigint
FROM pc.model_calls
WHERE org_id = sqlc.arg(org_id) AND created_at >= sqlc.arg(since);

-- name: InsertModelCall :exec
INSERT INTO pc.model_calls (org_id, id, actor, task, model)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(actor), sqlc.arg(task), sqlc.arg(model));

-- name: FinishModelCall :execrows
UPDATE pc.model_calls
SET outcome = sqlc.arg(outcome), input_tokens = sqlc.arg(input_tokens), output_tokens = sqlc.arg(output_tokens),
    finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND outcome = 'PENDING';

-- name: InsertModelDraft :exec
INSERT INTO pc.model_drafts (org_id, version_id, call_id, kind)
VALUES (sqlc.arg(org_id), sqlc.arg(version_id), sqlc.arg(call_id), sqlc.arg(kind));
