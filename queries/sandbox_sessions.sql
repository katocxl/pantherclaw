-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Sandbox sessions and probe reports (G0 M9 track B; migrations 00090 and
-- 00091). Everything runs as pc_app in a tenant transaction. Reports are
-- only inserted (HR-055); a nonce is used once (HR-215).

-- name: InsertSandboxSession :one
INSERT INTO pc.sandbox_sessions (org_id, id, agent_id, launcher, enrollment_token_id, agent_image, edge_image, probe_image,
    config_digest, probe_jkt, probe_public_key, host_jkt, host_public_key, engine_version, api_version, runtime, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(agent_id), sqlc.arg(launcher), sqlc.arg(enrollment_token_id),
    sqlc.arg(agent_image), sqlc.arg(edge_image), sqlc.arg(probe_image), sqlc.arg(config_digest), sqlc.arg(probe_jkt),
    sqlc.arg(probe_public_key), sqlc.arg(host_jkt), sqlc.arg(host_public_key), sqlc.arg(engine_version), sqlc.arg(api_version),
    sqlc.arg(runtime),
    now() + make_interval(secs => sqlc.arg(ttl_seconds)::integer))
RETURNING *;

-- A connection the session maps, with its bindings as the session opens
-- (CoverageBinding).
-- name: InsertSandboxSessionConnection :exec
INSERT INTO pc.sandbox_session_connections (org_id, session_id, connection_id, connection_revision, gateway_id,
    package_version_id, credential_version)
VALUES (sqlc.arg(org_id), sqlc.arg(session_id), sqlc.arg(connection_id), sqlc.arg(connection_revision), sqlc.arg(gateway_id),
    sqlc.arg(package_version_id), sqlc.narg(credential_version));

-- name: GetSandboxSession :one
SELECT * FROM pc.sandbox_sessions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- The session row is locked while a report is verified and recorded, so
-- that two reports of one session never interleave.
-- name: LockSandboxSession :one
SELECT * FROM pc.sandbox_sessions WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: ListSandboxSessionsPage :many
SELECT * FROM pc.sandbox_sessions
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(after)::uuid IS NULL OR id < sqlc.narg(after)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- The connections a session maps, with what the edge needs of each.
-- name: SandboxSessionConnections :many
SELECT c.id, c.name, c.gateway_id, c.agent_hosts, c.state
FROM pc.sandbox_session_connections s
JOIN pc.connections c ON c.org_id = s.org_id AND c.id = s.connection_id
WHERE s.org_id = sqlc.arg(org_id) AND s.session_id = sqlc.arg(session_id)
ORDER BY c.name;

-- The instance enrolled with a session's enrollment token, if any.
-- name: SandboxSessionInstance :one
SELECT id, state, sandbox_session_id FROM pc.agent_instances
WHERE org_id = sqlc.arg(org_id) AND enrollment_token_id = sqlc.arg(enrollment_token_id);

-- name: BindSandboxSessionInstance :execrows
UPDATE pc.sandbox_sessions SET instance_id = sqlc.arg(instance_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN' AND (instance_id IS NULL OR instance_id = sqlc.arg(instance_id));

-- name: MarkSandboxInstance :execrows
UPDATE pc.agent_instances SET sandbox_session_id = sqlc.arg(session_id), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND enrollment_token_id = sqlc.arg(enrollment_token_id)
  AND (sandbox_session_id IS NULL OR sandbox_session_id = sqlc.arg(session_id));

-- name: BindSandboxSessionRun :execrows
UPDATE pc.sandbox_sessions SET run_id = sqlc.arg(run_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN' AND (run_id IS NULL OR run_id = sqlc.arg(run_id));

-- name: EndSandboxSession :one
UPDATE pc.sandbox_sessions SET state = sqlc.arg(state), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN'
RETURNING *;

-- name: InsertProbeNonce :one
INSERT INTO pc.probe_nonces (org_id, id, session_id, kind, nonce_sha256, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(session_id), sqlc.arg(kind), sqlc.arg(nonce_sha256),
    now() + interval '15 minutes')
RETURNING *;

-- A report's nonce is used once, within 15 minutes, for its session and
-- kind; anything else matches no row.
-- name: UseProbeNonce :one
UPDATE pc.probe_nonces SET used_at = now()
WHERE org_id = sqlc.arg(org_id) AND nonce_sha256 = sqlc.arg(nonce_sha256) AND session_id = sqlc.arg(session_id)
  AND kind = sqlc.arg(kind) AND used_at IS NULL AND expires_at > now()
RETURNING *;

-- name: InsertProbeRun :one
INSERT INTO pc.probe_runs (org_id, id, session_id, nonce_id, kind, report, report_sha256)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(session_id), sqlc.arg(nonce_id), sqlc.arg(kind), sqlc.arg(report),
    sqlc.arg(report_sha256))
RETURNING *;

-- The latest report of each kind since a time: one probe run is the
-- session's last SANDBOX, CONTROL and CANARY reports.
-- name: LatestProbeRuns :many
SELECT DISTINCT ON (kind) * FROM pc.probe_runs
WHERE org_id = sqlc.arg(org_id) AND session_id = sqlc.arg(session_id) AND received_at >= sqlc.arg(since)
ORDER BY kind, id DESC;

-- The agent's last closure for a connection: the images and configuration
-- its evidence was taken with.
-- name: LastSandboxClosure :one
SELECT image_digests, config_sha256 FROM pc.coverage_closures
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND connection_id = sqlc.arg(connection_id)
ORDER BY id DESC
LIMIT 1;

-- Whether the session an enrollment token belongs to is open: a sandbox
-- instance acts only inside its session (design decision 9). No row: the
-- token is not a sandbox session's.
-- name: SandboxSessionOpenForToken :one
SELECT (state = 'OPEN' AND expires_at > now())::boolean AS open FROM pc.sandbox_sessions
WHERE org_id = sqlc.arg(org_id) AND enrollment_token_id = sqlc.arg(enrollment_token_id);

-- The connections a session maps, with their bindings as it opened (the
-- closure contract's Bound).
-- name: SandboxSessionBindings :many
SELECT connection_id, connection_revision, gateway_id, package_version_id, credential_version
FROM pc.sandbox_session_connections
WHERE org_id = sqlc.arg(org_id) AND session_id = sqlc.arg(session_id)
ORDER BY connection_id;
