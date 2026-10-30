-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Hosted gateways (G0 M19 D203). The hosting_* tables are read and written
-- only in a global transaction of the purpose "hosting"; pc.hosted_gateways
-- in the org's own tenant transaction.

-- name: InsertHostingHost :one
INSERT INTO pc.hosting_hosts (id, name, domain, capacity, milli_cpus, memory_mib)
VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(domain), sqlc.arg(capacity), sqlc.arg(milli_cpus), sqlc.arg(memory_mib))
RETURNING *;

-- name: GetHostingHost :one
SELECT * FROM pc.hosting_hosts WHERE id = sqlc.arg(id);

-- name: GetHostingHostByName :one
SELECT * FROM pc.hosting_hosts WHERE name = sqlc.arg(name);

-- name: ListActiveHostingHosts :many
SELECT * FROM pc.hosting_hosts WHERE state = 'ACTIVE' ORDER BY id;

-- name: LockActiveHostingHost :one
-- Held while one hosted gateway is placed on the host, so the capacity check
-- and the placement are one step (G0 M19 D219).
SELECT * FROM pc.hosting_hosts WHERE id = sqlc.arg(id) AND state = 'ACTIVE' FOR UPDATE;

-- name: ClaimHostingSlug :execrows
-- Holds a slug for one hosted gateway across all hosts (D222). A second try
-- for the same record keeps the claim; another record's claim wins: no row.
INSERT INTO pc.hosting_slugs (slug, org_id, hosted_id) VALUES (sqlc.arg(slug), sqlc.arg(org_id), sqlc.arg(hosted_id))
ON CONFLICT (slug) DO UPDATE SET hosted_id = EXCLUDED.hosted_id
WHERE pc.hosting_slugs.hosted_id = EXCLUDED.hosted_id;

-- name: HostingSlugHeld :one
SELECT EXISTS (SELECT 1 FROM pc.hosting_slugs WHERE slug = sqlc.arg(slug))::boolean;

-- name: ReleaseHostingSlug :exec
DELETE FROM pc.hosting_slugs WHERE slug = sqlc.arg(slug) AND hosted_id = sqlc.arg(hosted_id);

-- name: ReleaseOrgHostingSlugs :exec
-- The org's deletion frees its slugs (HR-390).
DELETE FROM pc.hosting_slugs WHERE org_id = sqlc.arg(org_id);

-- name: TouchHostingHost :exec
UPDATE pc.hosting_hosts SET last_seen = now(), agent_version = sqlc.arg(agent_version) WHERE id = sqlc.arg(id);

-- name: SetHostingHostState :execrows
UPDATE pc.hosting_hosts SET state = sqlc.arg(state) WHERE id = sqlc.arg(id);

-- name: InsertHostingHostCert :exec
INSERT INTO pc.hosting_host_certs (id, host_id, serial, key_thumbprint, issued_via, previous_id, not_before, not_after)
VALUES (sqlc.arg(id), sqlc.arg(host_id), sqlc.arg(serial), sqlc.arg(key_thumbprint), sqlc.arg(issued_via),
        sqlc.narg(previous_id), sqlc.arg(not_before), sqlc.arg(not_after));

-- name: HostingHostCertAuth :one
-- A host certificate's row with its host's state, on the database's clock
-- (HR-181 for hosts).
SELECT c.host_id, c.state, c.not_before, c.not_after, c.superseded_at, h.state AS host_state, now()::timestamptz AS db_now
FROM pc.hosting_host_certs c
JOIN pc.hosting_hosts h ON h.id = c.host_id
WHERE c.id = sqlc.arg(id);

-- name: LockHostingHostCert :one
SELECT * FROM pc.hosting_host_certs WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: SupersedeHostingHostCert :execrows
UPDATE pc.hosting_host_certs SET state = 'SUPERSEDED', superseded_at = now()
WHERE id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: RevokeHostingHostCerts :execrows
UPDATE pc.hosting_host_certs SET state = 'REVOKED', revoked_at = now()
WHERE host_id = sqlc.arg(host_id) AND state <> 'REVOKED';

-- name: InsertHostedGateway :one
INSERT INTO pc.hosted_gateways (org_id, id, slug, milli_cpus, memory_mib, pids, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(slug), sqlc.arg(milli_cpus), sqlc.arg(memory_mib), sqlc.arg(pids), sqlc.arg(created_by))
RETURNING *;

-- name: GetHostedGateway :one
SELECT * FROM pc.hosted_gateways WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockHostedGateway :one
SELECT * FROM pc.hosted_gateways WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: LiveHostedGateway :one
-- The org's live hosted gateway (HR-499: at most one).
SELECT * FROM pc.hosted_gateways
WHERE org_id = sqlc.arg(org_id) AND state NOT IN ('DEPROVISIONED', 'FAILED');

-- name: ListHostedGateways :many
SELECT * FROM pc.hosted_gateways
WHERE org_id = sqlc.arg(org_id)
  AND id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY id
LIMIT sqlc.arg(max_rows);

-- name: ListDueHostedGateways :many
-- The org's hosted gateways the provisioner acts on (lister hosting_due).
SELECT * FROM pc.hosted_gateways
WHERE org_id = sqlc.arg(org_id)
  AND (state = 'REQUESTED'
       OR (state = 'PROVISIONED' AND token_pulled_at IS NULL AND updated_at < now() - interval '10 minutes'))
ORDER BY id
FOR UPDATE SKIP LOCKED;

-- name: IsHostedGateway :one
-- Whether PantherClaw hosts the gateway: a hosted gateway record names it,
-- whatever its state, so a deprovisioned one never takes connectors
-- (HR-084).
SELECT EXISTS (SELECT 1 FROM pc.hosted_gateways WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id)::uuid)::boolean;

-- name: ProvisionHostedGateway :execrows
UPDATE pc.hosted_gateways
SET state = 'PROVISIONED', gateway_id = sqlc.arg(gateway_id), host_id = sqlc.arg(host_id),
    token_sealed = sqlc.arg(token_sealed), enrollment_id = sqlc.arg(enrollment_id), token_pulled_at = NULL, failure = NULL,
    updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'REQUESTED';

-- name: ReissueHostedToken :execrows
UPDATE pc.hosted_gateways SET token_sealed = sqlc.arg(token_sealed), enrollment_id = sqlc.arg(enrollment_id), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PROVISIONED' AND token_pulled_at IS NULL;

-- name: TakeHostedToken :execrows
-- The token is handed out once: the row, locked and read by the caller in
-- the same transaction, moves to ENROLLED and forgets it (HR-502).
UPDATE pc.hosted_gateways
SET state = 'ENROLLED', token_sealed = NULL, token_pulled_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND host_id = sqlc.arg(host_id)
  AND state = 'PROVISIONED' AND token_sealed IS NOT NULL;

-- name: ReportHostedGateway :execrows
-- The host agent's report of a process it runs.
UPDATE pc.hosted_gateways
SET state = CASE WHEN sqlc.arg(healthy)::boolean THEN 'RUNNING' ELSE state END,
    version = sqlc.arg(version), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND host_id = sqlc.arg(host_id)
  AND state IN ('ENROLLED', 'RUNNING');

-- name: StaleHostedEnrollment :one
-- Whether the gateway is hosted and the token is not the one its provisioner
-- minted last: a replaced token enrolls nothing (D222).
SELECT EXISTS (
    SELECT 1 FROM pc.hosted_gateways
    WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id)::uuid
      AND enrollment_id IS DISTINCT FROM sqlc.arg(enrollment_id)::uuid
)::boolean;

-- name: BindHostedEnrollment :exec
-- Records the certificate the provisioner's token enrolled; a token of any
-- other gateway changes nothing.
UPDATE pc.hosted_gateways SET enrolled_cert_id = sqlc.arg(cert_id), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id) AND enrollment_id = sqlc.arg(enrollment_id);

-- name: CertDescendsFrom :one
-- Whether the certificate is the enrolled one or a renewal of it.
WITH RECURSIVE chain AS (
    SELECT c.id, c.previous_id FROM pc.gateway_certs c WHERE c.org_id = sqlc.arg(org_id) AND c.id = sqlc.arg(cert_id)
    UNION ALL
    SELECT c.id, c.previous_id FROM pc.gateway_certs c
    JOIN chain ON c.org_id = sqlc.arg(org_id) AND c.id = chain.previous_id
)
SELECT EXISTS (SELECT 1 FROM chain WHERE chain.id = sqlc.arg(enrolled_cert_id)::uuid);

-- name: SetHostedTarget :execrows
UPDATE pc.hosted_gateways SET target_version = sqlc.narg(target_version), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PROVISIONED', 'ENROLLED', 'RUNNING')
  AND target_version IS DISTINCT FROM sqlc.narg(target_version);

-- name: StartDeprovisionHostedGateway :one
-- Marks the org's hosted gateway for stopping; the caller has revoked its
-- gateway in the same transaction first (HR-503).
UPDATE pc.hosted_gateways
SET state = CASE WHEN host_id IS NULL THEN 'DEPROVISIONED' ELSE 'DEPROVISIONING' END,
    deprovisioned_at = CASE WHEN host_id IS NULL THEN now() END,
    token_sealed = NULL, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state NOT IN ('DEPROVISIONING', 'DEPROVISIONED', 'FAILED')
RETURNING *;

-- name: DeprovisionOrgHostedGateways :exec
-- The org's deletion stops its hosted gateways while the host still sees
-- them; the tombstone ends their credentials (HR-392).
UPDATE pc.hosted_gateways
SET state = CASE WHEN host_id IS NULL THEN 'DEPROVISIONED' ELSE 'DEPROVISIONING' END,
    deprovisioned_at = CASE WHEN host_id IS NULL THEN now() END,
    token_sealed = NULL, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND state NOT IN ('DEPROVISIONING', 'DEPROVISIONED', 'FAILED');

-- name: FinishDeprovisionHostedGateway :execrows
UPDATE pc.hosted_gateways SET state = 'DEPROVISIONED', deprovisioned_at = now(), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND host_id = sqlc.arg(host_id) AND state = 'DEPROVISIONING';

-- name: FailHostedGateway :execrows
UPDATE pc.hosted_gateways SET state = 'FAILED', failure = sqlc.arg(failure), token_sealed = NULL, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'REQUESTED';

-- name: HostedGatewayOfGateway :one
-- The live hosted gateway record of one of the org's gateways: its slug
-- names the gateway's server certificate (G0 M19 D210).
SELECT * FROM pc.hosted_gateways
WHERE org_id = sqlc.arg(org_id) AND gateway_id = sqlc.arg(gateway_id)::uuid
  AND state IN ('ENROLLED', 'RUNNING');
