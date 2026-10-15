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
-- name: ListCases :many
SELECT * FROM pc.cases
WHERE org_id = sqlc.arg(org_id)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR state = ANY (sqlc.arg(states)::text[]))
  AND (sqlc.narg(owner_id)::uuid IS NULL OR owner_id = sqlc.narg(owner_id) OR follow_up_owner_id = sqlc.narg(owner_id))
  AND (sqlc.narg(alert_id)::uuid IS NULL OR alert_id = sqlc.narg(alert_id))
  AND (sqlc.narg(incident_id)::uuid IS NULL OR incident_id = sqlc.narg(incident_id))
  AND (sqlc.narg(before_updated)::timestamptz IS NULL
       OR (updated_at, id) < (sqlc.narg(before_updated)::timestamptz, sqlc.narg(before_id)::uuid))
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
ORDER BY c.id
LIMIT sqlc.arg(max_rows);
