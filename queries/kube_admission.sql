-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- When the admission webhook last allowed or denied a pod of a protected
-- namespace (G0 M32 D967a, migration 00364).

-- Records one decision; allowed picks the column. A later time never
-- moves back.
-- name: UpsertKubeAdmissionSeen :exec
INSERT INTO pc.kube_admission_seen (org_id, cluster, namespace, last_allowed_at, last_denied_at)
VALUES (sqlc.arg(org_id), sqlc.arg(cluster), sqlc.arg(namespace),
    CASE WHEN sqlc.arg(allowed)::boolean THEN sqlc.arg(seen_at)::timestamptz END,
    CASE WHEN NOT sqlc.arg(allowed)::boolean THEN sqlc.arg(seen_at)::timestamptz END)
ON CONFLICT (org_id, cluster, namespace) DO UPDATE SET
    last_allowed_at = CASE WHEN sqlc.arg(allowed)::boolean
        THEN greatest(pc.kube_admission_seen.last_allowed_at, EXCLUDED.last_allowed_at)
        ELSE pc.kube_admission_seen.last_allowed_at END,
    last_denied_at = CASE WHEN NOT sqlc.arg(allowed)::boolean
        THEN greatest(pc.kube_admission_seen.last_denied_at, EXCLUDED.last_denied_at)
        ELSE pc.kube_admission_seen.last_denied_at END;

-- name: GetKubeAdmissionSeen :one
SELECT * FROM pc.kube_admission_seen
WHERE org_id = sqlc.arg(org_id) AND cluster = sqlc.arg(cluster) AND namespace = sqlc.arg(namespace);
