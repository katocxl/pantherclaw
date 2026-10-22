-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Gateways, enrollment tokens, certificates and broker keys (G0 M6,
-- HR-180..182). State changes are conditional updates (HR-004).

-- name: InsertGateway :one
INSERT INTO pc.gateways (org_id, id, name, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(created_by))
RETURNING *;

-- name: GetGateway :one
SELECT * FROM pc.gateways WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockGateway :one
SELECT * FROM pc.gateways WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListGateways :many
SELECT * FROM pc.gateways
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(include_revoked)::boolean OR state = 'ACTIVE')
  AND id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: RevokeGateway :one
UPDATE pc.gateways
SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by)::text, revoked_at = now(), revoke_reason = sqlc.arg(reason)::text,
    config_version = config_version + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE'
RETURNING *;

-- name: BumpGatewayConfig :one
UPDATE pc.gateways SET config_version = config_version + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
RETURNING config_version;

-- name: InsertGatewayEnrollmentToken :one
INSERT INTO pc.gateway_enrollment_tokens (org_id, id, gateway_id, token_hash, created_by, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(gateway_id), sqlc.arg(token_hash), sqlc.arg(created_by),
        now() + make_interval(mins => sqlc.arg(ttl_minutes)::integer))
RETURNING id, expires_at;

-- name: LockGatewayEnrollmentToken :one
SELECT t.*, (t.expires_at > now())::boolean AS live
FROM pc.gateway_enrollment_tokens t
WHERE t.org_id = sqlc.arg(org_id) AND t.token_hash = sqlc.arg(token_hash)
FOR UPDATE;

-- name: UseGatewayEnrollmentToken :execrows
UPDATE pc.gateway_enrollment_tokens SET used_at = now(), used_cert_id = sqlc.arg(cert_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND used_at IS NULL AND expires_at > now();

-- name: InsertGatewayCert :exec
INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, previous_id, not_before, not_after)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(gateway_id), sqlc.arg(serial), sqlc.arg(key_thumbprint),
        sqlc.arg(issued_via), sqlc.narg(previous_id), sqlc.arg(not_before), sqlc.arg(not_after));

-- GatewayCertAuth is what the gateway listener checks on every call
-- (HR-181): the certificate row, its gateway's state, its org's state (a
-- DELETED org fails closed, HR-392) and the database time.
-- name: GatewayCertAuth :one
SELECT c.id, c.gateway_id, c.state, c.not_before, c.not_after, c.superseded_at, g.state AS gateway_state, o.state AS org_state,
       now()::timestamptz AS db_now
FROM pc.gateway_certs c
JOIN pc.gateways g ON g.org_id = c.org_id AND g.id = c.gateway_id
JOIN pc.orgs o ON o.id = c.org_id
WHERE c.org_id = sqlc.arg(org_id) AND c.id = sqlc.arg(id);

-- name: LockGatewayCert :one
SELECT * FROM pc.gateway_certs WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: SupersedeGatewayCert :execrows
UPDATE pc.gateway_certs SET state = 'SUPERSEDED', superseded_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- Revoking also covers a SUPERSEDED certificate, which authenticates for a
-- grace period after a renewal; superseded_at belongs to that state only.
-- name: RevokeGatewayCert :execrows
UPDATE pc.gateway_certs SET state = 'REVOKED', revoked_at = now(), revoke_reason = sqlc.arg(reason)::text, superseded_at = NULL
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND id = sqlc.arg(id) AND state <> 'REVOKED';

-- name: RevokeGatewayCerts :execrows
UPDATE pc.gateway_certs SET state = 'REVOKED', revoked_at = now(), revoke_reason = sqlc.arg(reason)::text, superseded_at = NULL
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND state <> 'REVOKED';

-- name: ListGatewayCerts :many
SELECT * FROM pc.gateway_certs
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id)
ORDER BY issued_at DESC, id DESC
LIMIT 20;

-- name: GetActiveBrokerKey :one
SELECT * FROM pc.broker_keys WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND state = 'ACTIVE';

-- name: GetBrokerKey :one
SELECT * FROM pc.broker_keys WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: RetireBrokerKeys :execrows
UPDATE pc.broker_keys SET state = 'RETIRED', retired_at = now()
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND state = 'ACTIVE';

-- name: InsertBrokerKey :one
INSERT INTO pc.broker_keys (org_id, id, gateway_id, version, public_key, fingerprint, cert_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(gateway_id),
        (SELECT coalesce(max(version), 0) + 1 FROM pc.broker_keys b WHERE b.org_id = sqlc.arg(org_id) AND b.gateway_id = sqlc.arg(gateway_id)),
        sqlc.arg(public_key), sqlc.arg(fingerprint), sqlc.arg(cert_id))
RETURNING *;

-- name: ListBrokerKeys :many
SELECT * FROM pc.broker_keys
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id)
ORDER BY version DESC
LIMIT 20;
