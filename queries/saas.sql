-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- SaaS agent discovery (N6, G0 M26 D407; HR-635..639).

-- InsertExternalAgent records an agent that lives in a SaaS tenant: DISCOVERED
-- and marked external, which keeps it from ever being claimed (HR-639).
-- name: InsertExternalAgent :one
INSERT INTO pc.agents (org_id, id, name, state, created_by, external)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), 'DISCOVERED', sqlc.arg(created_by), true)
RETURNING *;

-- SetExternalOwner names an external agent's owners and nothing else: its
-- state, team, environment and authority do not change (HR-639).
-- name: SetExternalOwner :one
UPDATE pc.agents
SET owner_user_id = sqlc.arg(owner_user_id), backup_owner_user_id = sqlc.narg(backup_owner_user_id), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND external AND state = 'DISCOVERED'
RETURNING *;

-- name: InsertSaasRun :exec
INSERT INTO pc.saas_scan_runs (org_id, id, source, origin, tenant, connection_id, verification_id, started_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(source), sqlc.arg(origin), sqlc.arg(tenant), sqlc.narg(connection_id),
        sqlc.narg(verification_id), sqlc.arg(started_by));

-- name: FinishSaasRun :exec
UPDATE pc.saas_scan_runs
SET state = sqlc.arg(state), counts = sqlc.arg(counts), scanned = sqlc.arg(scanned)::text[], not_scanned = sqlc.arg(not_scanned),
    finished_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'RUNNING');

-- GetSaasRun is a run with its lease's state: a PENDING run whose lease is
-- held is RUNNING, and one whose lease ended unreported FAILED.
-- name: GetSaasRun :one
SELECT r.id, r.source, r.origin, r.tenant, r.connection_id, r.counts, r.scanned, r.not_scanned, r.started_by, r.created_at, r.finished_at,
       (CASE WHEN r.state <> 'PENDING' THEN r.state
             WHEN v.state = 'LEASED' THEN 'RUNNING'
             WHEN v.state IN ('EXPIRED', 'CANCELLED', 'DONE') THEN 'FAILED'
             ELSE 'PENDING' END)::text AS state
FROM pc.saas_scan_runs r
LEFT JOIN pc.verifications v ON v.org_id = r.org_id AND v.id = r.verification_id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id);

-- ListSaasRuns are the org's runs, newest first.
-- name: ListSaasRuns :many
SELECT r.id, r.source, r.origin, r.tenant, r.connection_id, r.counts, r.scanned, r.not_scanned, r.started_by, r.created_at, r.finished_at,
       (CASE WHEN r.state <> 'PENDING' THEN r.state
             WHEN v.state = 'LEASED' THEN 'RUNNING'
             WHEN v.state IN ('EXPIRED', 'CANCELLED', 'DONE') THEN 'FAILED'
             ELSE 'PENDING' END)::text AS state
FROM pc.saas_scan_runs r
LEFT JOIN pc.verifications v ON v.org_id = r.org_id AND v.id = r.verification_id
WHERE r.org_id = sqlc.arg(org_id) AND (sqlc.arg(source)::text = '' OR r.source = sqlc.arg(source)::text)
  AND r.id < coalesce(sqlc.narg(before_id)::uuid, 'ffffffff-ffff-ffff-ffff-ffffffffffff')
ORDER BY r.id DESC
LIMIT sqlc.arg(max_rows);

-- OpenSaasScan reports whether a scan of the connection is pending or held.
-- name: OpenSaasScan :one
SELECT EXISTS (SELECT 1 FROM pc.verifications
               WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND purpose = 'saas_scan'
                 AND state IN ('PENDING', 'LEASED'))::boolean;

-- name: ScheduleSaasScan :exec
INSERT INTO pc.verifications (org_id, id, purpose, connection_id, operation, request, next_at, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'saas_scan', sqlc.arg(connection_id), sqlc.arg(operation), sqlc.arg(request), now(),
        now() + interval '30 minutes');

-- FailExpiredSaasScans ends the runs whose lease ended unreported (expired,
-- cancelled, or done without the run's report): a scan never stays PENDING,
-- and reads FAILED as GetSaasRun derives it.
-- name: FailExpiredSaasScans :execrows
UPDATE pc.saas_scan_runs r
SET state = 'FAILED', finished_at = now()
FROM pc.verifications v
WHERE r.org_id = sqlc.arg(org_id) AND v.org_id = r.org_id AND v.id = r.verification_id AND v.purpose = 'saas_scan'
  AND v.state IN ('EXPIRED', 'CANCELLED', 'DONE') AND r.state IN ('PENDING', 'RUNNING');

-- LeasedSaasScan is a SaaS scan task under a live lease of this gateway, with
-- its run.
-- name: LeasedSaasScan :one
SELECT v.id, r.connection_id, r.id AS run_id, r.source, r.tenant
FROM pc.verifications v
JOIN pc.saas_scan_runs r ON r.org_id = v.org_id AND r.verification_id = v.id
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id) AND v.purpose = 'saas_scan' AND v.state = 'LEASED'
  AND v.leased_by = sqlc.arg(gateway_id) AND v.lease_hash = sqlc.arg(lease_hash) AND v.lease_expires_at >= now()
FOR UPDATE OF v;

-- GatewaySaasRun is a run whose saas_scan lease this gateway holds now, under
-- the lease it presents: only then may it submit the run's findings.
-- name: GatewaySaasRun :one
SELECT r.id, r.source, r.tenant FROM pc.saas_scan_runs r
JOIN pc.verifications v ON v.org_id = r.org_id AND v.id = r.verification_id
WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id) AND v.purpose = 'saas_scan' AND v.state = 'LEASED'
  AND v.leased_by = sqlc.arg(gateway_id)::uuid AND v.lease_hash = sqlc.arg(lease_hash) AND v.lease_expires_at >= now();

-- MissSaasDiscoveries counts a miss on each discovery of a tenant that a
-- complete run did not see, and returns them. A dismissed one counts nothing.
-- name: MissSaasDiscoveries :many
UPDATE pc.discoveries
SET missed_scans = missed_scans + 1
WHERE org_id = sqlc.arg(org_id) AND source = sqlc.arg(source) AND observed ->> 'tenant' = sqlc.arg(tenant)::text
  AND last_scan_run IS DISTINCT FROM sqlc.arg(run)::uuid AND state <> 'DISMISSED'
RETURNING id, agent_id, state, observed, missed_scans, vanish_notified_at;

-- ListSaasAgents are the external agents with their discoveries.
-- name: ListSaasAgents :many
SELECT a.id, a.name, a.state, a.owner_user_id, a.backup_owner_user_id, d.id AS discovery_id, d.source, d.state AS discovery_state,
       d.observed, d.seen_count, d.missed_scans, d.first_seen_at, d.last_seen_at
FROM pc.discoveries d
JOIN pc.agents a ON a.org_id = d.org_id AND a.id = d.agent_id
WHERE d.org_id = sqlc.arg(org_id) AND a.external AND d.source IN ('copilot_studio', 'chatgpt_enterprise')
  AND (sqlc.arg(source)::text = '' OR d.source = sqlc.arg(source)::text)
  AND d.id > coalesce(sqlc.narg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY d.id
LIMIT sqlc.arg(max_rows);

-- GetSaasAgent is one external agent with its discovery.
-- name: GetSaasAgent :one
SELECT a.id, a.name, a.state, a.owner_user_id, a.backup_owner_user_id, d.id AS discovery_id, d.source, d.state AS discovery_state,
       d.observed, d.seen_count, d.missed_scans, d.first_seen_at, d.last_seen_at
FROM pc.discoveries d
JOIN pc.agents a ON a.org_id = d.org_id AND a.id = d.agent_id
WHERE d.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(id) AND a.external AND d.source IN ('copilot_studio', 'chatgpt_enterprise')
ORDER BY d.id DESC
LIMIT 1;

-- PostureQueueSaasUnowned are the external agents nobody owns yet, for the
-- ranked queue: ids and the source only, never anything they observed.
-- name: PostureQueueSaasUnowned :many
SELECT d.id, d.agent_id, d.source, d.first_seen_at
FROM pc.discoveries d
JOIN pc.agents a ON a.org_id = d.org_id AND a.id = d.agent_id
WHERE d.org_id = sqlc.arg(org_id) AND a.external AND a.owner_user_id IS NULL AND a.state = 'DISCOVERED' AND d.state = 'OPEN'
  AND d.source IN ('copilot_studio', 'chatgpt_enterprise')
  AND (sqlc.arg(all_agents)::boolean OR d.agent_id = ANY (sqlc.arg(agent_ids)::uuid[]))
ORDER BY d.first_seen_at, d.id
LIMIT sqlc.arg(max_rows);

-- PostureQueueSaasGaps are the latest finished run of each source and tenant
-- that left something unread, for the ranked queue: a gap, never a clean bill.
-- name: PostureQueueSaasGaps :many
SELECT x.id, x.source, x.tenant, x.finished_at FROM (
    SELECT DISTINCT ON (r.source, r.tenant) r.id, r.source, r.tenant, r.finished_at, r.state, r.not_scanned
    FROM pc.saas_scan_runs r
    WHERE r.org_id = sqlc.arg(org_id) AND r.finished_at IS NOT NULL
    ORDER BY r.source, r.tenant, r.finished_at DESC, r.id DESC
) x
WHERE x.state = 'FAILED' OR x.not_scanned <> '{}'::jsonb
ORDER BY x.finished_at DESC
LIMIT sqlc.arg(max_rows);

-- Daily scan schedules (G0 M34 D997, migration 00382). Setting one again
-- keeps it and names the person who set it last.
-- name: UpsertSaasScanSchedule :one
INSERT INTO pc.saas_scan_schedules (org_id, source, connection_id, tenant, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(source), sqlc.arg(connection_id), sqlc.arg(tenant), sqlc.arg(created_by))
ON CONFLICT (org_id, source, connection_id, tenant) DO UPDATE SET created_by = excluded.created_by
RETURNING *;

-- name: DeleteSaasScanSchedule :one
DELETE FROM pc.saas_scan_schedules
WHERE org_id = sqlc.arg(org_id) AND source = sqlc.arg(source) AND connection_id = sqlc.arg(connection_id)
  AND tenant = sqlc.arg(tenant)
RETURNING *;

-- The org's schedules, for the daily job and the CLI.
-- name: ListSaasScanSchedules :many
SELECT * FROM pc.saas_scan_schedules
WHERE org_id = sqlc.arg(org_id)
ORDER BY source, connection_id, tenant;

-- Locks one schedule, so two daily jobs start one scan.
-- name: LockSaasScanSchedule :one
SELECT * FROM pc.saas_scan_schedules
WHERE org_id = sqlc.arg(org_id) AND source = sqlc.arg(source) AND connection_id = sqlc.arg(connection_id)
  AND tenant = sqlc.arg(tenant)
FOR UPDATE;

-- name: MarkSaasScanScheduleStarted :exec
UPDATE pc.saas_scan_schedules SET last_started_at = now()
WHERE org_id = sqlc.arg(org_id) AND source = sqlc.arg(source) AND connection_id = sqlc.arg(connection_id)
  AND tenant = sqlc.arg(tenant);
