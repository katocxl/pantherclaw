-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- IdP-native agent access (G0 M26 D400-D402, D408). State changes are
-- conditional updates (HR-004). Codes and refresh tokens are looked up by
-- hash only.

-- name: InsertAssertionIssuer :one
INSERT INTO pc.org_assertion_issuers (org_id, id, name, issuer, audience, tenant, algorithms, created_by, updated_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(issuer), sqlc.arg(audience), sqlc.narg(tenant),
        sqlc.arg(algorithms), sqlc.arg(created_by), sqlc.arg(created_by))
RETURNING *;

-- name: GetAssertionIssuer :one
SELECT * FROM pc.org_assertion_issuers WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockAssertionIssuer :one
SELECT * FROM pc.org_assertion_issuers WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListAssertionIssuers :many
SELECT * FROM pc.org_assertion_issuers WHERE org_id = sqlc.arg(org_id) ORDER BY name LIMIT 100;

-- The ACTIVE entries of an issuer URL, one per tenant.
-- name: ActiveAssertionIssuers :many
SELECT * FROM pc.org_assertion_issuers
WHERE org_id = sqlc.arg(org_id) AND issuer = sqlc.arg(issuer) AND state = 'ACTIVE'
ORDER BY id
LIMIT 100;

-- Whether any entry of an issuer URL pins a tenant, in any state: such an
-- entry, even PENDING or DISABLED, rules out the untenanted fallback.
-- name: AssertionIssuerPinsTenant :one
SELECT EXISTS (SELECT 1 FROM pc.org_assertion_issuers
    WHERE org_id = sqlc.arg(org_id) AND issuer = sqlc.arg(issuer) AND tenant IS NOT NULL)::boolean;

-- name: ActivateAssertionIssuer :execrows
UPDATE pc.org_assertion_issuers
SET state = 'ACTIVE', activated_at = coalesce(activated_at, now()), updated_by = sqlc.arg(updated_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- Turning an issuer off also ends a filing that never applied.
-- name: DisableAssertionIssuer :one
UPDATE pc.org_assertion_issuers
SET state = 'DISABLED', disabled_by = sqlc.arg(disabled_by), disabled_at = now(), updated_by = sqlc.arg(disabled_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'DISABLED'
RETURNING *;

-- An issuer whose activation was declined or expired stops waiting.
-- name: LapseAssertionIssuer :execrows
UPDATE pc.org_assertion_issuers
SET state = 'DISABLED', disabled_by = sqlc.arg(disabled_by), disabled_at = now(), updated_by = sqlc.arg(disabled_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND activated_at IS NULL;

-- name: InsertAssertionClient :one
INSERT INTO pc.org_assertion_clients (org_id, id, issuer_id, client_id, agent_id, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(issuer_id), sqlc.arg(client_id), sqlc.arg(agent_id), sqlc.arg(created_by))
RETURNING *;

-- name: GetAssertionClient :one
SELECT * FROM pc.org_assertion_clients WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockAssertionClient :one
SELECT * FROM pc.org_assertion_clients WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListAssertionClients :many
SELECT * FROM pc.org_assertion_clients
WHERE org_id = sqlc.arg(org_id) AND issuer_id = sqlc.arg(issuer_id)
ORDER BY client_id, id
LIMIT 100;

-- The binding an assertion's client_id names, with its live issuer.
-- name: ActiveAssertionClient :one
SELECT c.* FROM pc.org_assertion_clients c
JOIN pc.org_assertion_issuers i ON i.org_id = c.org_id AND i.id = c.issuer_id AND i.state = 'ACTIVE'
WHERE c.org_id = sqlc.arg(org_id) AND c.issuer_id = sqlc.arg(issuer_id) AND c.client_id = sqlc.arg(client_id) AND c.state = 'ACTIVE';

-- name: AssertionClientLive :one
SELECT EXISTS (
    SELECT 1 FROM pc.org_assertion_clients c
    JOIN pc.org_assertion_issuers i ON i.org_id = c.org_id AND i.id = c.issuer_id AND i.state = 'ACTIVE'
    WHERE c.org_id = sqlc.arg(org_id) AND c.id = sqlc.arg(id) AND c.state = 'ACTIVE')::boolean;

-- name: ActivateAssertionClient :execrows
UPDATE pc.org_assertion_clients SET state = 'ACTIVE', activated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: RemoveAssertionClient :one
UPDATE pc.org_assertion_clients SET state = 'REMOVED', removed_by = sqlc.arg(removed_by), removed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'REMOVED'
RETURNING *;

-- name: LapseAssertionClient :execrows
UPDATE pc.org_assertion_clients SET state = 'REMOVED', removed_by = sqlc.arg(removed_by), removed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: GetOrgMcpAccess :one
SELECT * FROM pc.org_mcp_access WHERE org_id = sqlc.arg(org_id);

-- name: EnableOrgMcpAccess :exec
INSERT INTO pc.org_mcp_access (org_id, enabled, gateway_url, updated_by)
VALUES (sqlc.arg(org_id), true, sqlc.arg(gateway_url), sqlc.arg(updated_by))
ON CONFLICT (org_id) DO UPDATE SET enabled = true, gateway_url = excluded.gateway_url, updated_by = excluded.updated_by, updated_at = now();

-- Every gateway of the org gets a new configuration: its OAuth route
-- follows the org's MCP authorization (D402).
-- name: BumpOrgGatewaysConfig :exec
UPDATE pc.gateways SET config_version = config_version + 1 WHERE org_id = sqlc.arg(org_id);

-- name: DisableOrgMcpAccess :one
UPDATE pc.org_mcp_access SET enabled = false, updated_by = sqlc.arg(updated_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND enabled
RETURNING *;

-- name: InsertMcpClient :one
INSERT INTO pc.mcp_clients (org_id, id, client_url, agent_id, instance_id, client_name, redirect_uris, document_digest, created_by,
    dpop_bound)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(client_url), sqlc.arg(agent_id), sqlc.arg(instance_id), sqlc.arg(client_name),
    sqlc.arg(redirect_uris), sqlc.arg(document_digest), sqlc.arg(created_by), sqlc.arg(dpop_bound))
RETURNING *;

-- A confirmed change takes a new document, only over the one it was asked
-- against.
-- name: UpdateMcpClientDocument :execrows
UPDATE pc.mcp_clients SET client_name = sqlc.arg(client_name), redirect_uris = sqlc.arg(redirect_uris),
    document_digest = sqlc.arg(document_digest), dpop_bound = sqlc.arg(dpop_bound)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE' AND document_digest = sqlc.arg(previous_digest);

-- name: GetMcpClient :one
SELECT * FROM pc.mcp_clients WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockMcpClient :one
SELECT * FROM pc.mcp_clients WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListMcpClients :many
SELECT * FROM pc.mcp_clients WHERE org_id = sqlc.arg(org_id) ORDER BY client_url, id LIMIT 100;

-- name: ActiveMcpClientByURL :one
SELECT * FROM pc.mcp_clients WHERE org_id = sqlc.arg(org_id) AND client_url = sqlc.arg(client_url) AND state = 'ACTIVE';

-- name: McpClientLive :one
SELECT EXISTS (
    SELECT 1 FROM pc.mcp_clients WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE')::boolean;

-- name: ActivateMcpClient :execrows
UPDATE pc.mcp_clients SET state = 'ACTIVE', activated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: RemoveMcpClient :one
UPDATE pc.mcp_clients SET state = 'REMOVED', removed_by = sqlc.arg(removed_by), removed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'REMOVED'
RETURNING *;

-- name: LapseMcpClient :one
UPDATE pc.mcp_clients SET state = 'REMOVED', removed_by = sqlc.arg(removed_by), removed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING'
RETURNING *;

-- A client's instance waits with no expiry: only the protected change
-- admits it, and the waitlist's AdmitInstance never does (D408.1).
-- name: InsertMcpClientInstance :one
INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(jkt), sqlc.arg(public_jwk), 'PENDING_ADMISSION', 'mcp_client')
RETURNING *;

-- name: AdmitMcpClientInstance :execrows
UPDATE pc.agent_instances
SET state = 'ADMITTED', decided_by = sqlc.arg(decided_by), decided_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING_ADMISSION' AND enrolled_via = 'mcp_client';

-- name: RevokeMcpClientInstance :execrows
UPDATE pc.agent_instances
SET state = 'REVOKED', decided_by = sqlc.arg(decided_by), decided_at = now(), revoke_reason = sqlc.arg(reason), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING_ADMISSION', 'ADMITTED') AND enrolled_via = 'mcp_client';

-- An admitted instance of an agent by its key, for client authentication.
-- A client's own instance holds no key and is never one (D408.1).
-- name: AdmittedInstanceByKey :one
SELECT * FROM pc.agent_instances
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND jkt = sqlc.arg(jkt)
  AND state = 'ADMITTED' AND enrolled_via <> 'mcp_client';

-- The active, unexpired root grants a person gave this agent in its
-- environment. A delegated grant reaches a run only through delegation.
-- name: UsableRootGrants :many
SELECT g.id, g.instance_id, r.bounds, r.min_attestation, r.expires_at
FROM pc.grants g
JOIN pc.grant_revisions r ON r.org_id = g.org_id AND r.grant_id = g.id AND r.revision = g.current_revision
WHERE g.org_id = sqlc.arg(org_id) AND g.agent_id = sqlc.arg(agent_id) AND g.environment_id = sqlc.arg(environment_id)
  AND g.principal_user_id = sqlc.arg(user_id) AND g.parent_id IS NULL AND g.state = 'ACTIVE'
  AND r.not_before <= now() AND r.expires_at > now()
  AND (g.instance_id IS NULL OR g.instance_id = sqlc.arg(instance_id))
ORDER BY g.id
LIMIT 20;

-- name: InsertMcpAuthorizationCode :exec
INSERT INTO pc.mcp_authorization_codes (org_id, code_hash, client_id, user_id, redirect_uri, code_challenge, resource,
    scope_operations, expires_at, dpop_jkt)
VALUES (sqlc.arg(org_id), sqlc.arg(code_hash), sqlc.arg(client_id), sqlc.arg(user_id), sqlc.arg(redirect_uri),
    sqlc.arg(code_challenge), sqlc.arg(resource), sqlc.arg(scope_operations), now() + interval '60 seconds', sqlc.narg(dpop_jkt));

-- A code is spent by the first request that names it, right or wrong.
-- name: SpendMcpAuthorizationCode :one
UPDATE pc.mcp_authorization_codes SET used_at = now()
WHERE org_id = sqlc.arg(org_id) AND code_hash = sqlc.arg(code_hash) AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: SetMcpAuthorizationCodeRun :exec
UPDATE pc.mcp_authorization_codes SET run_id = sqlc.arg(run_id)
WHERE org_id = sqlc.arg(org_id) AND code_hash = sqlc.arg(code_hash) AND used_at IS NOT NULL;

-- A spent code presented again: marks it reused and returns the run it
-- started, if a redemption already recorded one. The update waits for a
-- redemption in flight.
-- name: MarkMcpAuthorizationCodeReused :one
UPDATE pc.mcp_authorization_codes SET reused_at = coalesce(reused_at, now())
WHERE org_id = sqlc.arg(org_id) AND code_hash = sqlc.arg(code_hash) AND used_at IS NOT NULL
RETURNING run_id, client_id;

-- A redemption about to issue tokens: whether a second use came meanwhile.
-- name: McpAuthorizationCodeReused :one
SELECT (reused_at IS NOT NULL)::boolean AS reused FROM pc.mcp_authorization_codes
WHERE org_id = sqlc.arg(org_id) AND code_hash = sqlc.arg(code_hash)
FOR UPDATE;

-- name: InsertMcpRefreshToken :exec
INSERT INTO pc.mcp_refresh_tokens (org_id, id, family_id, token_hash, client_id, run_id, resource, expires_at, dpop_jkt)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(family_id), sqlc.arg(token_hash), sqlc.arg(client_id), sqlc.arg(run_id),
    sqlc.arg(resource), sqlc.arg(expires_at), sqlc.narg(dpop_jkt));

-- name: LockMcpRefreshToken :one
SELECT * FROM pc.mcp_refresh_tokens
WHERE org_id = sqlc.arg(org_id) AND token_hash = sqlc.arg(token_hash) FOR UPDATE;

-- name: RotateMcpRefreshToken :execrows
UPDATE pc.mcp_refresh_tokens SET state = 'ROTATED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: KillMcpRefreshFamily :execrows
UPDATE pc.mcp_refresh_tokens SET state = 'KILLED'
WHERE org_id = sqlc.arg(org_id) AND family_id = sqlc.arg(family_id) AND state <> 'KILLED';

-- name: DeleteExpiredMcpAuthorizationCodes :execrows
DELETE FROM pc.mcp_authorization_codes WHERE org_id = sqlc.arg(org_id) AND expires_at < now() - interval '1 hour';

-- name: DeleteExpiredMcpRefreshTokens :execrows
DELETE FROM pc.mcp_refresh_tokens WHERE org_id = sqlc.arg(org_id) AND expires_at < now() - interval '1 day';
