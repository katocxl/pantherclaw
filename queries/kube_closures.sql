-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Kubernetes closures (G0 M32 D970, migration 00362): append-only evidence
-- of one verified probe report, valid 24 hours.

-- A replayed report (the same digest) inserts nothing.
-- name: InsertKubeClosure :one
INSERT INTO pc.kube_closures (org_id, id, cluster, namespace, instance_id, kind, report_digest, result, evaluated_at,
    expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(cluster), sqlc.arg(namespace), sqlc.arg(instance_id), sqlc.arg(kind),
    sqlc.arg(report_digest), sqlc.arg(result), sqlc.arg(evaluated_at), sqlc.arg(evaluated_at)::timestamptz + interval '24 hours')
ON CONFLICT (org_id, report_digest) DO NOTHING
RETURNING *;

-- name: GetKubeClosure :one
SELECT * FROM pc.kube_closures WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- The newest unexpired closure of one kind for a cluster and namespace.
-- name: LatestKubeClosure :one
SELECT * FROM pc.kube_closures
WHERE org_id = sqlc.arg(org_id) AND cluster = sqlc.arg(cluster) AND namespace = sqlc.arg(namespace)
  AND kind = sqlc.arg(kind) AND expires_at > now()
ORDER BY evaluated_at DESC
LIMIT 1;

-- A single-use closure nonce for one instance and namespace, valid 15
-- minutes (migration 00365).
-- name: IssueKubeClosureNonce :one
INSERT INTO pc.kube_closure_nonces (org_id, nonce, cluster, namespace, instance_id, issued_at, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(nonce), sqlc.arg(cluster), sqlc.arg(namespace), sqlc.arg(instance_id), now(),
    now() + interval '15 minutes')
RETURNING *;

-- Serialises nonce issuance for one instance, so the outstanding-nonce cap
-- holds under concurrent requests (D1218 L2).
-- name: LockKubeClosureNonces :exec
SELECT pg_advisory_xact_lock(hashtextextended(
    (sqlc.arg(org_id)::uuid)::text || '/' || (sqlc.arg(instance_id)::uuid)::text, 365));

-- The instance's unused, unexpired nonces (D1218 L2: at most 8).
-- name: CountOutstandingKubeClosureNonces :one
SELECT count(*)::int FROM pc.kube_closure_nonces
WHERE org_id = sqlc.arg(org_id) AND instance_id = sqlc.arg(instance_id) AND used_at IS NULL AND expires_at > now();

-- Janitor: nonces expired more than a minute ago, used or not (D1218 L2).
-- name: DeleteExpiredKubeClosureNonces :execrows
DELETE FROM pc.kube_closure_nonces WHERE org_id = sqlc.arg(org_id) AND expires_at < now() - interval '1 minute';

-- Consumes a nonce: the row comes back only when it was unused, is
-- unexpired, and names the same instance and namespace.
-- name: ConsumeKubeClosureNonce :one
UPDATE pc.kube_closure_nonces SET used_at = now()
WHERE org_id = sqlc.arg(org_id) AND nonce = sqlc.arg(nonce) AND used_at IS NULL AND expires_at > now()
  AND instance_id = sqlc.arg(instance_id) AND namespace = sqlc.arg(namespace)
RETURNING *;
