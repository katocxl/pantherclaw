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
