-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Trusted-issuer entries (HR-140, HR-141, G0 M3). Each entry is a series of
-- immutable revisions; only the state of a revision changes, conditionally
-- (HR-004). One active and at most one proposed revision per entry.

-- name: InsertIssuerRevision :one
INSERT INTO pc.trusted_issuers (org_id, id, entry_id, revision, agent_id, kind, issuer, audience, algorithms, binding,
    auto_admit, widening, state, proposed_by, activated_by, activated_at, run_grant_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(entry_id), sqlc.arg(revision), sqlc.arg(agent_id), sqlc.arg(kind),
    sqlc.arg(issuer), sqlc.arg(audience), sqlc.arg(algorithms), sqlc.arg(binding), sqlc.arg(auto_admit), sqlc.arg(widening),
    sqlc.arg(state), sqlc.arg(proposed_by), sqlc.narg(activated_by),
    CASE WHEN sqlc.arg(state)::text = 'ACTIVE' THEN now() END, sqlc.narg(run_grant_id))
RETURNING *;

-- name: LockIssuerEntry :many
SELECT * FROM pc.trusted_issuers WHERE org_id = sqlc.arg(org_id) AND entry_id = sqlc.arg(entry_id)
ORDER BY revision FOR UPDATE;

-- name: ListIssuerRevisions :many
SELECT * FROM pc.trusted_issuers WHERE org_id = sqlc.arg(org_id) AND entry_id = sqlc.arg(entry_id)
ORDER BY revision DESC;

-- The current revision of each entry: the active one, else the proposal of
-- an entry never activated, else the latest.
-- name: ListCurrentIssuerRevisions :many
SELECT DISTINCT ON (entry_id) * FROM pc.trusted_issuers
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR agent_id = sqlc.narg(agent_id)::uuid)
  AND entry_id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY entry_id, (state = 'ACTIVE') DESC, (state = 'PROPOSED') DESC, revision DESC
LIMIT sqlc.arg(page_limit);

-- name: SetIssuerRevisionState :one
UPDATE pc.trusted_issuers SET state = sqlc.arg(to_state), closed_by = sqlc.arg(closed_by), closed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state)
RETURNING *;

-- name: ActivateIssuerRevision :one
UPDATE pc.trusted_issuers SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PROPOSED'
RETURNING *;

-- Active entries of one preset kind, for attestation (slice 10).
-- name: ListActiveIssuers :many
SELECT * FROM pc.trusted_issuers WHERE org_id = sqlc.arg(org_id) AND kind = sqlc.arg(kind) AND state = 'ACTIVE';

-- The active revision of the entry another revision belongs to. An
-- instance keeps L2 only while its entry has one (HR-141: disabling takes
-- effect at the next token refresh).
-- name: ActiveRevisionFor :one
SELECT a.* FROM pc.trusted_issuers r JOIN pc.trusted_issuers a ON a.org_id = r.org_id AND a.entry_id = r.entry_id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(revision_id) AND a.state = 'ACTIVE';

-- The active kubernetes entries for one cluster, namespace and service
-- account, for the admission webhook (G0 M32 D967; index
-- trusted_issuers_kubernetes_lookup, migration 00360).
-- name: ListKubernetesIssuersFor :many
SELECT * FROM pc.trusted_issuers
WHERE org_id = sqlc.arg(org_id) AND kind = 'kubernetes' AND state = 'ACTIVE'
  AND binding #>> '{kubernetes,cluster}' = sqlc.arg(cluster)::text
  AND binding #>> '{kubernetes,namespace}' = sqlc.arg(namespace)::text
  AND binding #>> '{kubernetes,service_account_name}' = sqlc.arg(service_account_name)::text
ORDER BY entry_id;
