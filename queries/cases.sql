-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Cases (G0 M10 D19, HR-245, HR-246). Entries are only ever inserted; the
-- triggers of migration 00122 derive their columns, chain them and move the
-- case.

-- The insert trigger sets the genesis head.
-- name: InsertCase :one
INSERT INTO pc.cases (org_id, id, title, source, opened_by_type, opened_by_id, alert_id, incident_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(title), sqlc.arg(source), sqlc.arg(opened_by_type),
    sqlc.arg(opened_by_id), sqlc.narg(alert_id), sqlc.narg(incident_id))
RETURNING *;

-- name: GetCase :one
SELECT * FROM pc.cases WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- The case row lock serialises appends; the head it returns numbers the
-- next entry.
-- name: LockCase :one
SELECT * FROM pc.cases WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- The insert trigger derives every other column from the body.
-- name: InsertCaseEntry :one
INSERT INTO pc.case_entries (org_id, case_id, id, body, ledger_entry_id)
VALUES (sqlc.arg(org_id), sqlc.arg(case_id), sqlc.arg(id), sqlc.arg(body), sqlc.arg(ledger_entry_id))
RETURNING *;

-- name: ListCaseEntries :many
SELECT * FROM pc.case_entries
WHERE org_id = sqlc.arg(org_id) AND case_id = sqlc.arg(case_id) AND seq > sqlc.arg(after_seq)
ORDER BY seq
LIMIT sqlc.arg(max_rows);

-- name: GetCaseEntry :one
SELECT * FROM pc.case_entries WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- Ids of the case's entries that a later entry superseded.
-- name: SupersededCaseEntries :many
SELECT s.supersedes::uuid AS id FROM pc.case_entries s
WHERE s.org_id = sqlc.arg(org_id) AND s.case_id = sqlc.arg(case_id) AND s.supersedes IS NOT NULL
ORDER BY s.seq;

-- name: CaseOpenQuestions :one
SELECT pc.case_open_questions(sqlc.arg(org_id), sqlc.arg(case_id))::bigint AS open;

-- Cases newest-updated first; keyset paging on (updated_at, id).
-- A scoped viewer's cases are filtered here, before the limit (D60).
-- name: ListCases :many
SELECT * FROM pc.cases
WHERE org_id = sqlc.arg(org_id)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(owner_id)::uuid IS NULL OR owner_id = sqlc.narg(owner_id) OR follow_up_owner_id = sqlc.narg(owner_id))
  AND (sqlc.narg(alert_id)::uuid IS NULL OR alert_id = sqlc.narg(alert_id))
  AND (sqlc.narg(incident_id)::uuid IS NULL OR incident_id = sqlc.narg(incident_id))
  AND (sqlc.narg(before_updated)::timestamptz IS NULL
       OR (updated_at, id) < (sqlc.narg(before_updated)::timestamptz, sqlc.narg(before_id)::uuid))
  AND (NOT sqlc.arg(scoped)::boolean OR pc.case_within(org_id, id, sqlc.arg(visible_agents)::uuid[]))
ORDER BY updated_at DESC, id DESC
LIMIT sqlc.arg(page_limit);

-- Standing LINK entries of a kind (for lenses and permission checks).
-- name: CaseLinks :many
SELECT l.* FROM pc.case_entries l
WHERE l.org_id = sqlc.arg(org_id) AND l.case_id = sqlc.arg(case_id) AND l.kind = 'LINK'
  AND NOT pc.case_entry_superseded(l.org_id, l.id)
ORDER BY l.seq;

-- Cases that link a subject (the cases of an alert, a run or an agent).
-- name: CasesLinking :many
SELECT DISTINCT c.* FROM pc.cases c
JOIN pc.case_entries l ON l.org_id = c.org_id AND l.case_id = c.id
WHERE c.org_id = sqlc.arg(org_id) AND l.kind = 'LINK' AND l.ref_kind = sqlc.arg(ref_kind) AND l.ref_id = sqlc.arg(ref_id)
  AND NOT pc.case_entry_superseded(l.org_id, l.id)
  AND (NOT sqlc.arg(scoped)::boolean OR pc.case_within(c.org_id, c.id, sqlc.arg(visible_agents)::uuid[]))
ORDER BY c.id
LIMIT sqlc.arg(max_rows);

-- The agents a case is about: linked agents and the agents of linked runs
-- and transactions (the case's read scope, HR-247).
-- name: CaseAgents :many
SELECT a::uuid AS agent_id FROM pc.case_agents(sqlc.arg(org_id), sqlc.arg(case_id)) a ORDER BY 1;

-- The agents of subjects named before a case exists (agent, run and
-- transaction ids).
-- name: AgentsOfSubjects :many
SELECT g.id AS agent_id FROM pc.agents g WHERE g.org_id = sqlc.arg(org_id) AND g.id = ANY (sqlc.arg(agent_ids)::uuid[])
UNION
SELECT r.agent_id FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = ANY (sqlc.arg(run_ids)::uuid[])
UNION
SELECT r.agent_id FROM pc.transactions t JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = ANY (sqlc.arg(transaction_ids)::uuid[]);

-- The actions of a case's runs, transactions and agents in a window, for
-- the sequence and effects lenses (F237). A scoped viewer sees only the
-- visible agents' rows, filtered before the limit (D60).
-- name: CaseLensTransactions :many
SELECT t.id, t.run_id, r.agent_id, t.operation, t.decision, t.reason_code, t.mode, t.connection_id,
       t.effect_state, t.effect_level_achieved, t.created_at, p.state AS permit_state, a.outcome
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
LEFT JOIN pc.permits p ON p.org_id = t.org_id AND p.transaction_id = t.id AND NOT p.replaced
LEFT JOIN pc.execution_attempts a ON a.org_id = p.org_id AND a.permit_id = p.id
WHERE t.org_id = sqlc.arg(org_id)
  AND (t.id = ANY (sqlc.arg(transaction_ids)::uuid[]) OR t.run_id = ANY (sqlc.arg(run_ids)::uuid[])
       OR r.agent_id = ANY (sqlc.arg(agent_ids)::uuid[]))
  AND t.created_at >= sqlc.arg(start_time) AND t.created_at < sqlc.arg(end_time)
  AND (NOT sqlc.arg(effects_only)::boolean OR t.effect_state IS NOT NULL OR a.outcome IS NOT NULL)
  AND (NOT sqlc.arg(scoped)::boolean OR r.agent_id = ANY (sqlc.arg(visible_agents)::uuid[]))
ORDER BY t.created_at, t.id
LIMIT sqlc.arg(max_rows);

-- The case's open questions that name no owner (D66): standing QUESTION
-- entries without an owner and without a standing resolving ANSWER.
-- name: UnownedOpenQuestions :many
SELECT q.id FROM pc.case_entries q
WHERE q.org_id = sqlc.arg(org_id) AND q.case_id = sqlc.arg(case_id) AND q.kind = 'QUESTION' AND q.owner_id IS NULL
  AND NOT pc.case_entry_superseded(q.org_id, q.id)
  AND NOT EXISTS (
      SELECT 1 FROM pc.case_entries a
      WHERE a.org_id = q.org_id AND a.case_id = q.case_id AND a.kind = 'ANSWER' AND a.question_id = q.id
        AND NOT a.unresolved AND NOT pc.case_entry_superseded(a.org_id, a.id))
ORDER BY q.seq;
