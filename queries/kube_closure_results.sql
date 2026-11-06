-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Kubernetes closures with their probe results (G0 M32 D970c, migration
-- 00367).

-- Records a verified report with its results; a replayed report (the same
-- digest) inserts nothing.
-- name: InsertKubeClosureWithResults :one
INSERT INTO pc.kube_closures (org_id, id, cluster, namespace, instance_id, kind, report_digest, result, evaluated_at,
    expires_at, results)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(cluster), sqlc.arg(namespace), sqlc.arg(instance_id), sqlc.arg(kind),
    sqlc.arg(report_digest), sqlc.arg(result), sqlc.arg(evaluated_at),
    sqlc.arg(evaluated_at)::timestamptz + interval '24 hours', sqlc.arg(results))
ON CONFLICT (org_id, report_digest) DO NOTHING
RETURNING *;

-- The newest unexpired PASSED control closure of a cluster: its results
-- are a sandbox report's positive twins.
-- name: LatestKubeControlClosure :one
SELECT * FROM pc.kube_closures
WHERE org_id = sqlc.arg(org_id) AND cluster = sqlc.arg(cluster) AND kind = 'control' AND result = 'PASSED'
  AND expires_at > now() AND results IS NOT NULL
ORDER BY evaluated_at DESC
LIMIT 1;

-- The pod an instance was last attested for: the pod_name claim of its
-- newest accepted attestation (G0 M32 D970, D973).
-- name: LatestAttestedPodName :one
SELECT coalesce(claims ->> 'pod_name', '')::text AS pod_name
FROM pc.attestations
WHERE org_id = sqlc.arg(org_id) AND instance_id = sqlc.arg(instance_id)
ORDER BY accepted_at DESC
LIMIT 1;

-- The connections a kube closure maps: those whose agent hosts include a
-- host the edge mediated in the report (G0 M32 D970).
-- name: KubeMappedConnections :many
SELECT c.id FROM pc.connections c
WHERE c.org_id = sqlc.arg(org_id) AND c.agent_hosts && sqlc.arg(hosts)::text[] AND c.state <> 'RETIRED'
ORDER BY c.id;

-- The admitted instances of an agent enrolled through a Kubernetes issuer
-- entry, with the cluster and namespace of their binding (G0 M32 D970).
-- name: CoverageKubeInstancesOfAgent :many
SELECT i.id, coalesce(i.binding ->> 'cluster', '')::text AS cluster, coalesce(i.binding ->> 'namespace', '')::text AS namespace
FROM pc.agent_instances i
JOIN pc.trusted_issuers t ON t.org_id = i.org_id AND t.id = i.issuer_revision_id
WHERE i.org_id = sqlc.arg(org_id) AND i.agent_id = sqlc.arg(agent_id) AND i.state = 'ADMITTED'
  AND (i.expires_at IS NULL OR i.expires_at > now()) AND t.kind = 'kubernetes' AND i.enrolled_via = 'attestation'
ORDER BY i.id;
