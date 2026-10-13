-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- PAP/1 workload identity (M3, G0 M3): enrollment tokens, instances and
-- their admission, server nonces and the proof replay store. Security
-- deadlines use the database clock (now(), ARCHITECTURE §4); changes are
-- conditional on the expected state (HR-004).

-- name: InsertEnrollmentToken :one
INSERT INTO pc.enrollment_tokens (org_id, id, agent_id, environment_id, token_hash, created_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(environment_id), sqlc.arg(token_hash),
    sqlc.arg(created_by), now() + make_interval(mins => sqlc.arg(ttl_minutes)::int))
RETURNING *;

-- Consumes an active, unexpired token exactly once (PAP-1 §3.2).
-- name: ConsumeEnrollmentToken :one
UPDATE pc.enrollment_tokens SET state = 'USED', used_at = now()
WHERE org_id = sqlc.arg(org_id) AND token_hash = sqlc.arg(token_hash) AND state = 'ACTIVE' AND expires_at > now()
RETURNING *;

-- name: GetEnrollmentTokenByHash :one
SELECT * FROM pc.enrollment_tokens WHERE org_id = sqlc.arg(org_id) AND token_hash = sqlc.arg(token_hash);

-- name: InsertInstance :one
INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via, enrollment_token_id,
    release_state, release_digest, last_network, last_seen_at, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(jkt), sqlc.arg(public_jwk), 'PENDING_ADMISSION',
    sqlc.arg(enrolled_via), sqlc.narg(enrollment_token_id), sqlc.narg(release_state), sqlc.narg(release_digest),
    sqlc.narg(last_network), now(), now() + interval '7 days')
RETURNING *;

-- name: GetInstance :one
SELECT * FROM pc.agent_instances WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockInstance :one
SELECT * FROM pc.agent_instances WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: InstanceExistsForKey :one
SELECT EXISTS (SELECT 1 FROM pc.agent_instances WHERE org_id = sqlc.arg(org_id) AND jkt = sqlc.arg(jkt))::boolean;

-- name: ListInstances :many
SELECT * FROM pc.agent_instances
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id)
  AND id > coalesce(sqlc.arg(after)::uuid, '00000000-0000-0000-0000-000000000000')
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- Admission (HR-094): only a pending instance whose admission deadline has
-- not passed.
-- name: AdmitInstance :one
UPDATE pc.agent_instances
SET state = 'ADMITTED', decided_by = sqlc.arg(decided_by), decided_at = now(), expires_at = NULL, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING_ADMISSION' AND expires_at > now()
RETURNING *;

-- name: CloseInstance :one
UPDATE pc.agent_instances
SET state = sqlc.arg(to_state), decided_by = sqlc.arg(decided_by), decided_at = now(), revoke_reason = sqlc.narg(reason),
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state)
RETURNING *;

-- name: TouchInstance :one
UPDATE pc.agent_instances
SET last_seen_at = now(), last_network = sqlc.narg(last_network), release_state = sqlc.narg(release_state),
    release_digest = sqlc.narg(release_digest), needs_review = needs_review OR sqlc.arg(drift)::boolean, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ADMITTED'
RETURNING *;

-- name: InsertWaitlistEntry :one
INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, evidence, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'ADMISSION', sqlc.arg(subject_type), sqlc.arg(subject_id), sqlc.arg(agent_id)::uuid,
    sqlc.arg(evidence), now() + interval '7 days')
RETURNING *;

-- name: CloseSubjectEntry :execrows
UPDATE pc.waitlist_entries
SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_at = now(), decision_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND subject_type = sqlc.arg(subject_type) AND subject_id = sqlc.arg(subject_id)
  AND state = 'OPEN';

-- Nonces (HR-091): one per org per minute, accepted until 6 minutes after
-- the start of their minute.
-- name: InsertNonce :exec
INSERT INTO pc.dpop_nonces (org_id, minute, nonce) VALUES (sqlc.arg(org_id), sqlc.arg(minute), sqlc.arg(nonce))
ON CONFLICT (org_id, minute) DO NOTHING;

-- name: GetNonceForMinute :one
SELECT nonce FROM pc.dpop_nonces WHERE org_id = sqlc.arg(org_id) AND minute = sqlc.arg(minute);

-- name: CurrentMinute :one
SELECT floor(extract(epoch FROM now()) / 60)::bigint;

-- name: LiveNonceMinute :one
SELECT minute FROM pc.dpop_nonces
WHERE org_id = sqlc.arg(org_id) AND nonce = sqlc.arg(nonce)
  AND to_timestamp((minute + 6) * 60) > now();

-- Records a proof's (jkt, jti) in its nonce's slot; no row means a replay
-- (HR-090). Only called after the proof verified and its nonce is live.
-- name: InsertProofJTI :execrows
INSERT INTO pc.dpop_jti (org_id, slot, jkt, jti, nonce_minute)
VALUES (sqlc.arg(org_id), sqlc.arg(slot), sqlc.arg(jkt), sqlc.arg(jti), sqlc.arg(nonce_minute))
ON CONFLICT DO NOTHING;

-- Janitor: replay rows whose nonce expired more than 60 seconds ago, and
-- old nonces.
-- name: DeleteExpiredProofs :execrows
DELETE FROM pc.dpop_jti
WHERE org_id = sqlc.arg(org_id) AND slot = ANY (sqlc.arg(slots)::smallint[])
  AND nonce_minute < sqlc.arg(before_minute);

-- name: DeleteExpiredNonces :execrows
DELETE FROM pc.dpop_nonces WHERE org_id = sqlc.arg(org_id) AND minute < sqlc.arg(before_minute);

-- Attestations (HR-143): the unique (issuer, token_key) makes a token
-- single use; no row means a replay.
-- name: InsertAttestation :execrows
INSERT INTO pc.attestations (org_id, id, instance_id, issuer_revision_id, issuer, token_key, claims, release_digest,
    issued_at, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(instance_id), sqlc.arg(issuer_revision_id), sqlc.arg(issuer),
    sqlc.arg(token_key), sqlc.arg(claims), sqlc.narg(release_digest), sqlc.arg(issued_at), sqlc.arg(expires_at))
ON CONFLICT (org_id, issuer, token_key) DO NOTHING;

-- An instance enrolled with an attestation: admitted at once when its
-- entry auto-admits, otherwise waiting for the owner.
-- name: InsertAttestedInstance :one
INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via, enrollment_token_id,
    issuer_revision_id, binding, att_level, attested_until, release_state, release_digest, last_network, last_seen_at,
    decided_by, decided_at, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(jkt), sqlc.arg(public_jwk), sqlc.arg(state),
    sqlc.arg(enrolled_via), sqlc.narg(enrollment_token_id), sqlc.arg(issuer_revision_id), sqlc.arg(binding), 2,
    sqlc.arg(attested_until), sqlc.narg(release_state), sqlc.narg(release_digest), sqlc.narg(last_network), now(),
    sqlc.narg(decided_by), CASE WHEN sqlc.arg(state)::text = 'ADMITTED' THEN now() END,
    CASE WHEN sqlc.arg(state)::text = 'ADMITTED' THEN NULL ELSE now() + interval '7 days' END)
RETURNING *;

-- Renews L2 until a fresh attestation expires (HR-143).
-- name: AttestInstance :one
UPDATE pc.agent_instances SET attested_until = sqlc.arg(attested_until), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ADMITTED' AND att_level = 2
RETURNING *;

-- Discovery (HR-148): unknown keys a gateway reports. One advisory lock per
-- org serializes the limit checks.
-- name: LockDiscoveries :exec
SELECT pg_advisory_xact_lock(hashtextextended('pc.discoveries:' || sqlc.arg(org_id)::text, 0));

-- Later sightings of a known key are only counted.
-- name: TouchDiscovery :execrows
UPDATE pc.discoveries SET seen_count = seen_count + 1, last_seen_at = now()
WHERE org_id = sqlc.arg(org_id) AND key_jkt = sqlc.arg(key_jkt);

-- name: DiscoveryLoad :one
SELECT
    -- The gateway's own: scans' findings have caps of their own (HR-148, HR-209).
    (SELECT count(*) FROM pc.discoveries d WHERE d.org_id = sqlc.arg(org_id) AND d.state = 'OPEN' AND d.source = 'gateway')::int AS open_discoveries,
    (SELECT count(*) FROM pc.discoveries d
      WHERE d.org_id = sqlc.arg(org_id) AND d.source = 'gateway' AND d.first_seen_at > now() - interval '1 minute'
        AND d.observed->>'gateway' = sqlc.arg(gateway)::text)::int AS recent_from_gateway;

-- name: InsertGatewayDiscovery :one
INSERT INTO pc.discoveries (org_id, id, agent_id, source, key_jkt, public_jwk, observed)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), 'gateway', sqlc.arg(key_jkt), sqlc.arg(public_jwk),
    sqlc.arg(observed))
RETURNING *;

-- name: InsertAgentAdmissionEntry :one
INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, evidence, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'ADMISSION', 'agent', sqlc.arg(agent_id), sqlc.arg(agent_id), sqlc.arg(evidence),
    now() + interval '7 days')
RETURNING *;

-- Janitor: pending instances whose admission deadline passed.
-- name: ExpirePendingInstances :many
UPDATE pc.agent_instances SET state = 'EXPIRED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND state = 'PENDING_ADMISSION' AND expires_at <= now()
RETURNING id, agent_id;

-- A verified request (Authorize): last seen moves at most once a minute and
-- the network only when it changed, so a busy instance does not serialize
-- on its row. No row means nothing changed, or a concurrent request
-- already recorded the change (and raised any network alert).
-- name: SeeInstance :execrows
UPDATE pc.agent_instances SET last_seen_at = now(), last_network = sqlc.narg(last_network), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ADMITTED'
  AND (last_seen_at IS NULL OR last_seen_at < now() - interval '1 minute'
       OR last_network IS DISTINCT FROM sqlc.narg(last_network));
