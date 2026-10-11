-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Replay inputs (G0 M7 design decision 11): one sealed row per evaluation,
-- written with its decision receipt.

-- name: InsertEvaluationInputs :exec
INSERT INTO pc.evaluation_inputs (org_id, transaction_id, evaluation, format_version, pipeline_version, inputs,
    inputs_sha256, truncated)
VALUES (sqlc.arg(org_id), sqlc.arg(transaction_id), sqlc.arg(evaluation), sqlc.arg(format_version),
    sqlc.arg(pipeline_version), sqlc.narg(inputs), sqlc.arg(inputs_sha256), sqlc.arg(truncated));

-- name: GetEvaluationInputs :one
SELECT format_version, pipeline_version, inputs, inputs_sha256, truncated
FROM pc.evaluation_inputs
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND evaluation = sqlc.arg(evaluation);

-- The decision receipt of one evaluation, which a replay compares with;
-- empty when retention removed its body.
-- name: GetEvaluationReceipt :one
SELECT coalesce(receipt_jws, '')::text AS receipt_jws FROM pc.decision_receipts
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND evaluation = sqlc.arg(evaluation);

-- A stored policy bundle by its id and version number: the version an
-- evaluation recorded as id@version, whatever its state now.
-- name: GetPolicyBundleByNumber :one
SELECT v.bundle
FROM pc.policy_versions v
JOIN pc.policies p ON p.org_id = v.org_id AND p.id = v.policy_id
WHERE v.org_id = sqlc.arg(org_id) AND p.bundle_id = sqlc.arg(bundle_id) AND v.version = sqlc.arg(version);

-- The latest evaluation of a transaction (0: none), which a replay of
-- "the latest" names.
-- name: LatestEvaluation :one
SELECT coalesce(max(evaluation), 0)::integer AS evaluation
FROM pc.decision_receipts
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id);
