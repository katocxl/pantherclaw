-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Compliance coverage (G0 M25 D312; F893, HR-601..603). Each source counts
-- a period's records as real or simulated, and lists a few of them. Nothing
-- here reads what a person or runner claimed. Periods are [start, end).

-- A transaction with a decision, under enforcement. A monitored decision
-- stopped nothing, so it is no evidence of a control.
-- name: ComplianceReceiptCounts :one
SELECT count(*) FILTER (WHERE NOT t.simulated)::bigint AS real_count,
       count(*) FILTER (WHERE t.simulated)::bigint AS simulated_count
FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.mode = 'enforce' AND t.decision IS NOT NULL
  AND t.created_at >= sqlc.arg(period_start) AND t.created_at < sqlc.arg(period_end);

-- name: ComplianceReceiptRefs :many
SELECT t.id FROM pc.transactions t
WHERE t.org_id = sqlc.arg(org_id) AND t.mode = 'enforce' AND t.decision IS NOT NULL AND t.simulated = sqlc.arg(simulated)
  AND t.created_at >= sqlc.arg(period_start) AND t.created_at < sqlc.arg(period_end)
ORDER BY t.id DESC
LIMIT sqlc.arg(page_limit);

-- An action's approval a person decided in the period. A request that timed
-- out or was withdrawn shows no oversight.
-- name: ComplianceApprovalCounts :one
SELECT count(*) FILTER (WHERE NOT t.simulated)::bigint AS real_count,
       count(*) FILTER (WHERE t.simulated)::bigint AS simulated_count
FROM pc.approval_requests a
JOIN pc.transactions t ON t.org_id = a.org_id AND t.id = a.transaction_id
WHERE a.org_id = sqlc.arg(org_id) AND a.subject_kind = 'ACTION' AND a.approved_at IS NOT NULL
  AND a.approved_at >= sqlc.arg(period_start) AND a.approved_at < sqlc.arg(period_end);

-- name: ComplianceApprovalRefs :many
SELECT a.transaction_id::uuid AS transaction_id FROM pc.approval_requests a
JOIN pc.transactions t ON t.org_id = a.org_id AND t.id = a.transaction_id
WHERE a.org_id = sqlc.arg(org_id) AND a.subject_kind = 'ACTION' AND a.approved_at IS NOT NULL AND t.simulated = sqlc.arg(simulated)
  AND a.approved_at >= sqlc.arg(period_start) AND a.approved_at < sqlc.arg(period_end)
ORDER BY a.id DESC
LIMIT sqlc.arg(page_limit);

-- A grant in force during the period. A range agent's is simulated.
-- name: ComplianceGrantCounts :one
SELECT count(*) FILTER (WHERE NOT ag.range_agent)::bigint AS real_count,
       count(*) FILTER (WHERE ag.range_agent)::bigint AS simulated_count
FROM pc.grants g
JOIN pc.agents ag ON ag.org_id = g.org_id AND ag.id = g.agent_id
WHERE g.org_id = sqlc.arg(org_id) AND g.created_at < sqlc.arg(period_end)
  AND (g.revoked_at IS NULL OR g.revoked_at >= sqlc.arg(period_start));

-- name: ComplianceGrantRefs :many
SELECT g.id FROM pc.grants g
JOIN pc.agents ag ON ag.org_id = g.org_id AND ag.id = g.agent_id
WHERE g.org_id = sqlc.arg(org_id) AND ag.range_agent = sqlc.arg(simulated) AND g.created_at < sqlc.arg(period_end)
  AND (g.revoked_at IS NULL OR g.revoked_at >= sqlc.arg(period_start))
ORDER BY g.id DESC
LIMIT sqlc.arg(page_limit);

-- An ENFORCED coverage snapshot in force during the period. Anything less
-- does not say a route is covered, and HR-222 keeps simulated connections out
-- of snapshots, so all of these are real.
-- name: ComplianceCoverageCount :one
SELECT count(*)::bigint FROM pc.coverage_snapshots s
WHERE s.org_id = sqlc.arg(org_id) AND s.state = 'ENFORCED' AND s.computed_at < sqlc.arg(period_end)
  AND s.expires_at > sqlc.arg(period_start);

-- name: ComplianceCoverageRefs :many
SELECT s.id FROM pc.coverage_snapshots s
WHERE s.org_id = sqlc.arg(org_id) AND s.state = 'ENFORCED' AND s.computed_at < sqlc.arg(period_end)
  AND s.expires_at > sqlc.arg(period_start)
ORDER BY s.id DESC
LIMIT sqlc.arg(page_limit);

-- Finished ranges of library scenarios: a customer-authored one is the
-- customer's word (HR-466).
-- name: ComplianceRanges :many
SELECT r.id FROM pc.redteam_runs r
WHERE r.org_id = sqlc.arg(org_id) AND r.state = 'FINISHED' AND r.origin = 'library'
  AND r.finished_at >= sqlc.arg(period_start) AND r.finished_at < sqlc.arg(period_end)
ORDER BY r.id DESC
LIMIT sqlc.arg(page_limit);

-- What people stated about the org's own agents; a range agent is not one.
-- name: ComplianceStatedCounts :one
SELECT count(*) FILTER (WHERE a.ai_act_role <> 'UNSET')::bigint AS role_stated,
       count(*) FILTER (WHERE a.ai_act_role = 'UNSET')::bigint AS role_unset,
       count(*) FILTER (WHERE a.ai_act_risk <> 'UNSET')::bigint AS risk_stated,
       count(*) FILTER (WHERE a.ai_act_risk = 'UNSET')::bigint AS risk_unset
FROM pc.agents a
WHERE a.org_id = sqlc.arg(org_id) AND NOT a.range_agent AND a.state <> 'RETIRED';

-- name: InsertComplianceReport :exec
INSERT INTO pc.compliance_reports (org_id, id, pack_id, framework, period_start, period_end, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(pack_id), sqlc.arg(framework), sqlc.arg(period_start),
    sqlc.arg(period_end), sqlc.arg(created_by));

-- name: GetComplianceReportOfPack :one
SELECT * FROM pc.compliance_reports WHERE org_id = sqlc.arg(org_id) AND pack_id = sqlc.arg(pack_id);

-- A report's digest is set once, by the job that built it.
-- name: SetComplianceReportDigest :execrows
UPDATE pc.compliance_reports SET report_sha256 = sqlc.arg(report_sha256)
WHERE org_id = sqlc.arg(org_id) AND pack_id = sqlc.arg(pack_id) AND report_sha256 IS NULL;

-- name: ListComplianceReports :many
SELECT * FROM pc.compliance_reports
WHERE org_id = sqlc.arg(org_id)
  AND (coalesce(sqlc.arg(before)::uuid, '00000000-0000-0000-0000-000000000000') = '00000000-0000-0000-0000-000000000000' OR id < sqlc.arg(before))
ORDER BY id DESC
LIMIT sqlc.arg(page_limit);
