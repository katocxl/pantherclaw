-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Cross-org federation queries (G0 M35 D1020..D1024). Every query runs
-- inside db.InTenantTx and also filters by org_id explicitly.

-- name: ListFederationKeys :many
-- An org's federation keys that are not RETIRED. live is false for a
-- RETIRING key whose 7-day overlap has ended: it signs and verifies
-- nothing, and the next change retires it.
SELECT kid, public_key, public_jwk, wrapped_private_key, kek_id, state, created_at, created_by, rotated_at,
       (coalesce(rotated_at, now()) + make_interval(secs => sqlc.arg(overlap_seconds)::int))::timestamptz AS retires_at,
       (state = 'ACTIVE' OR rotated_at > now() - make_interval(secs => sqlc.arg(overlap_seconds)::int))::bool AS live
FROM pc.federation_keys
WHERE org_id = sqlc.arg(org_id) AND state <> 'RETIRED'
ORDER BY created_at DESC, kid;

-- name: InsertFederationKey :exec
INSERT INTO pc.federation_keys (org_id, id, kid, public_key, public_jwk, wrapped_private_key, kek_id, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kid), sqlc.arg(public_key), sqlc.arg(public_jwk),
        sqlc.arg(wrapped_private_key), sqlc.arg(kek_id), sqlc.arg(created_by));

-- name: TransitionFederationKey :execrows
UPDATE pc.federation_keys SET state = sqlc.arg(to_state)
WHERE org_id = sqlc.arg(org_id) AND kid = sqlc.arg(kid) AND state = sqlc.arg(from_state);

-- name: ListFederationKeysToRewrap :many
-- RETIRED keys are never unwrapped, so they stay as they are.
SELECT kid, wrapped_private_key, kek_id
FROM pc.federation_keys
WHERE org_id = sqlc.arg(org_id) AND state <> 'RETIRED' AND kek_id <> ALL(sqlc.arg(skip_kek_ids)::text[])
ORDER BY created_at, kid
LIMIT sqlc.arg(row_limit);

-- name: RewrapFederationKey :execrows
UPDATE pc.federation_keys
SET wrapped_private_key = sqlc.arg(wrapped_private_key), kek_id = sqlc.arg(kek_id)
WHERE org_id = sqlc.arg(org_id) AND kid = sqlc.arg(kid)
  AND wrapped_private_key = sqlc.arg(old_wrapped_private_key) AND kek_id = sqlc.arg(old_kek_id);

-- name: ListFederationKeyKEKs :many
-- The KEK ids an org's federation keys are wrapped with (the KEK router's
-- check, D170).
SELECT DISTINCT kek_id FROM pc.federation_keys
WHERE org_id = sqlc.arg(org_id) AND state <> 'RETIRED';

-- name: GetFederationSettings :one
SELECT * FROM pc.federation_settings WHERE org_id = sqlc.arg(org_id);

-- name: PutFederationSettings :one
INSERT INTO pc.federation_settings (org_id, federation_url, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(federation_url), sqlc.arg(updated_by))
ON CONFLICT (org_id) DO UPDATE
SET federation_url = EXCLUDED.federation_url, updated_by = EXCLUDED.updated_by, updated_at = now()
RETURNING *;

-- name: GetOrgName :one
SELECT name FROM pc.orgs WHERE id = sqlc.arg(org_id);

-- name: InsertFederationTrust :one
INSERT INTO pc.federation_trusts (org_id, id, peer_org_id, peer_name, peer_doc_url, peer_server_url, peer_federation_url,
                                  pinned_jwks, pinned_keys_digest, peer_document, peer_doc_expires_at, safety_code,
                                  created_by, last_refreshed_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(peer_org_id), sqlc.arg(peer_name), sqlc.arg(peer_doc_url),
        sqlc.arg(peer_server_url), sqlc.narg(peer_federation_url), sqlc.arg(pinned_jwks), sqlc.arg(pinned_keys_digest),
        sqlc.arg(peer_document), sqlc.arg(peer_doc_expires_at), sqlc.arg(safety_code), sqlc.arg(created_by), now())
RETURNING *;

-- name: GetFederationTrust :one
SELECT * FROM pc.federation_trusts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockFederationTrust :one
SELECT * FROM pc.federation_trusts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: GetLiveFederationTrustByPeer :one
SELECT * FROM pc.federation_trusts
WHERE org_id = sqlc.arg(org_id) AND peer_org_id = sqlc.arg(peer_org_id) AND state <> 'REVOKED';

-- name: LockLiveFederationTrustByPeer :one
SELECT * FROM pc.federation_trusts
WHERE org_id = sqlc.arg(org_id) AND peer_org_id = sqlc.arg(peer_org_id) AND state <> 'REVOKED'
FOR UPDATE;

-- name: ListFederationTrusts :many
SELECT * FROM pc.federation_trusts
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(include_revoked)::bool OR state <> 'REVOKED')
ORDER BY created_at DESC, id;

-- name: ListFederationTrustsToRefresh :many
-- The org's live trusts not refreshed since the cutoff (the daily job).
SELECT id FROM pc.federation_trusts
WHERE org_id = sqlc.arg(org_id) AND state <> 'REVOKED'
  AND (last_refreshed_at IS NULL OR last_refreshed_at < sqlc.arg(cutoff))
ORDER BY last_refreshed_at NULLS FIRST, id
LIMIT sqlc.arg(row_limit);

-- name: UpdateFederationTrustPeer :exec
-- A refreshed peer document: the keys pinned (unchanged unless a pinned key
-- signed the rotation), the names and the expiry.
UPDATE pc.federation_trusts
SET peer_name = sqlc.arg(peer_name), peer_server_url = sqlc.arg(peer_server_url),
    peer_federation_url = sqlc.narg(peer_federation_url), pinned_jwks = sqlc.arg(pinned_jwks),
    pinned_keys_digest = sqlc.arg(pinned_keys_digest), peer_document = sqlc.arg(peer_document),
    peer_doc_expires_at = sqlc.arg(peer_doc_expires_at), safety_code = sqlc.arg(safety_code),
    last_refreshed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: TouchFederationTrust :exec
UPDATE pc.federation_trusts SET last_refreshed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ConfirmFederationTrustLocal :exec
UPDATE pc.federation_trusts
SET state = sqlc.arg(state), confirmed_by = sqlc.arg(confirmed_by), confirmed_credential = sqlc.arg(confirmed_credential),
    confirmed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SetFederationTrustPeerConfirmed :exec
UPDATE pc.federation_trusts
SET peer_confirmed_at = coalesce(peer_confirmed_at, now()), state = sqlc.arg(state)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: SetFederationTrustState :exec
UPDATE pc.federation_trusts SET state = sqlc.arg(state)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: RevokeFederationTrust :exec
UPDATE pc.federation_trusts SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'REVOKED';

-- name: InsertFederationListing :one
INSERT INTO pc.federation_listings (org_id, id, name, agent_id, connection_id, skills, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(agent_id), sqlc.arg(connection_id),
        sqlc.arg(skills)::text[], sqlc.arg(created_by))
RETURNING *;

-- name: GetFederationListing :one
SELECT * FROM pc.federation_listings WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: GetActiveFederationListingByName :one
SELECT * FROM pc.federation_listings
WHERE org_id = sqlc.arg(org_id) AND name = sqlc.arg(name) AND state = 'ACTIVE';

-- name: ListFederationListings :many
SELECT * FROM pc.federation_listings
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(include_retired)::bool OR state = 'ACTIVE')
ORDER BY name, created_at DESC;

-- name: RetireFederationListing :one
UPDATE pc.federation_listings SET state = 'RETIRED', retired_by = sqlc.arg(retired_by), retired_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: InsertFederationReceipt :exec
INSERT INTO pc.federation_receipts (org_id, id, direction, trust_id, peer_org_id, action_id, peer_action_id, decision,
                                    receipt_jws, state)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(direction), sqlc.arg(trust_id), sqlc.arg(peer_org_id), sqlc.narg(action_id),
        sqlc.narg(peer_action_id), sqlc.narg(decision), sqlc.narg(receipt_jws), sqlc.arg(state));

-- name: ListFederationReceipts :many
SELECT * FROM pc.federation_receipts
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(trust_id)::uuid IS NULL OR trust_id = sqlc.narg(trust_id)::uuid)
  AND (sqlc.narg(action_id)::uuid IS NULL OR action_id = sqlc.narg(action_id)::uuid)
  AND (sqlc.narg(before_at)::timestamptz IS NULL OR (received_at, id) < (sqlc.narg(before_at)::timestamptz, sqlc.narg(before_id)::uuid))
ORDER BY received_at DESC, id DESC
LIMIT sqlc.arg(row_limit);

-- name: InsertFederationReplay :execrows
-- A token, confirmation or revocation id seen from a peer; 0 rows when it
-- was seen before (FEDERATION_REPLAY).
INSERT INTO pc.federation_replay (org_id, peer_org_id, kind, jti, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(peer_org_id), sqlc.arg(kind), sqlc.arg(jti), sqlc.arg(expires_at))
ON CONFLICT DO NOTHING;

-- name: DeleteExpiredFederationReplay :execrows
DELETE FROM pc.federation_replay
WHERE org_id = sqlc.arg(org_id) AND expires_at < now();

-- name: FindCrossOrgGrant :one
-- The newest active cross-org grant of the peer agent (or its agent, for
-- any instance) to the listing's agent.
SELECT g.id FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.state = 'ACTIVE' AND g.peer_org_id = sqlc.arg(peer_org_id)
  AND g.peer_agent = ANY(sqlc.arg(peer_agents)::text[]) AND g.agent_id = sqlc.arg(agent_id)
  AND r.not_before <= now() AND r.expires_at > now()
ORDER BY g.created_at DESC, g.id
LIMIT 1;

-- name: ListCrossOrgGrantsOfPeer :many
SELECT id FROM pc.grants
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND peer_org_id = sqlc.arg(peer_org_id);

-- name: GetActiveFederationRun :one
SELECT id, grant_id, expires_at FROM pc.runs
WHERE org_id = sqlc.arg(org_id) AND principal_source = 'federation' AND state = 'ACTIVE'
  AND federation_trust_id = sqlc.arg(federation_trust_id) AND peer_agent = sqlc.arg(peer_agent)
  AND federation_day = sqlc.arg(federation_day)::date
  AND expires_at > now()
FOR UPDATE;

-- name: InsertFederationRun :exec
INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, principal_source, grant_id, task_ref, expires_at,
                     federation_trust_id, peer_org_id, peer_agent, federation_day)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(instance_id), sqlc.arg(environment_id), 'federation', sqlc.arg(grant_id),
        sqlc.arg(task_ref), sqlc.arg(expires_at), sqlc.arg(federation_trust_id), sqlc.arg(peer_org_id),
        sqlc.arg(peer_agent), sqlc.arg(federation_day)::date);

-- name: ActivateFederatedA2APin :execrows
-- A federated peer's pin, activated by the federation check (D1023).
UPDATE pc.a2a_pins SET state = 'ACTIVE', confirmed_operator = 'federation'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PROPOSED' AND federation_trust_id IS NOT NULL;

-- name: InsertFederatedInstance :exec
-- The federated agent's one instance (D1024c): ADMITTED, no key; its jkt
-- is a synthetic digest no key has, and Identify refuses it for PAP/1.
INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via, decided_by, decided_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(jkt), '\x7b7d'::bytea, 'ADMITTED', 'federation',
        sqlc.arg(decided_by), now());

-- name: InsertFederationAgent :exec
INSERT INTO pc.federation_agents (org_id, trust_id, peer_agent, agent_id, instance_id, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(trust_id), sqlc.arg(peer_agent), sqlc.arg(agent_id), sqlc.arg(instance_id),
        sqlc.arg(created_by));

-- name: GetFederationAgent :one
SELECT fa.*, a.state AS agent_state, a.environment_id AS environment_id
FROM pc.federation_agents fa
JOIN pc.agents a ON a.org_id = fa.org_id AND a.id = fa.agent_id
WHERE fa.org_id = sqlc.arg(org_id) AND fa.trust_id = sqlc.arg(trust_id) AND fa.peer_agent = sqlc.arg(peer_agent);

-- name: ListFederationAgentsOfTrust :many
SELECT * FROM pc.federation_agents
WHERE org_id = sqlc.arg(org_id) AND trust_id = sqlc.arg(trust_id)
ORDER BY created_at, peer_agent;

-- name: InsertFederationCall :exec
INSERT INTO pc.federation_calls (org_id, id, trust_id, peer_agent, run_id, agent_id, instance_id, listing, htu,
                                 body_sha256, receipt_id, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(trust_id), sqlc.arg(peer_agent), sqlc.arg(run_id), sqlc.arg(agent_id),
        sqlc.arg(instance_id), sqlc.arg(listing), sqlc.arg(htu), sqlc.arg(body_sha256), sqlc.arg(receipt_id),
        sqlc.arg(expires_at));

-- name: UseFederationCall :one
-- Authorize's single use of an admitted call (D1024c).
UPDATE pc.federation_calls SET used_at = now(), action_id = sqlc.arg(action_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: GetFederationCallOfAction :one
SELECT * FROM pc.federation_calls
WHERE org_id = sqlc.arg(org_id) AND action_id = sqlc.arg(action_id);

-- name: DeleteExpiredFederationCalls :execrows
DELETE FROM pc.federation_calls
WHERE org_id = sqlc.arg(org_id) AND expires_at < now() - interval '1 day';
