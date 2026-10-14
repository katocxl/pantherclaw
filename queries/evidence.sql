-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- EvidenceService queries (G0 M7 design decision 13, HR-196). Every query
-- runs inside db.InTenantTx and also filters by org_id explicitly.

-- name: ListCheckpointsPage :many
SELECT tree_size, root_hash, note, kid, pq_kid, created_at
FROM pc.checkpoints
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(before_size)::bigint = 0 OR tree_size < sqlc.arg(before_size)::bigint)
ORDER BY tree_size DESC
LIMIT sqlc.arg(page_limit);

-- name: GetCheckpointBySize :one
SELECT tree_size, root_hash, note, kid, pq_kid, created_at
FROM pc.checkpoints
WHERE org_id = sqlc.arg(org_id) AND tree_size = sqlc.arg(tree_size);

-- name: TransactionAgent :one
SELECT r.agent_id
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(transaction_id);

-- name: TransactionReceipts :many
-- Decision, execution and effect receipts, in the order they were written.
SELECT coalesce(receipt_jws, '')::text AS receipt_jws, ledger_entry_id, body_removed_at, created_at
FROM (
    SELECT d.receipt_jws, d.ledger_entry_id, d.body_removed_at, d.created_at
    FROM pc.decision_receipts d WHERE d.org_id = sqlc.arg(org_id) AND d.transaction_id = sqlc.arg(transaction_id)
    UNION ALL
    SELECT x.receipt_jws, x.ledger_entry_id, x.body_removed_at, x.created_at
    FROM pc.execution_receipts x WHERE x.org_id = sqlc.arg(org_id) AND x.transaction_id = sqlc.arg(transaction_id)
    UNION ALL
    SELECT f.receipt_jws, f.ledger_entry_id, f.body_removed_at, f.created_at
    FROM pc.effect_receipts f WHERE f.org_id = sqlc.arg(org_id) AND f.transaction_id = sqlc.arg(transaction_id)
) r
ORDER BY created_at, ledger_entry_id;

-- name: ReceiptsOfEntries :many
-- The receipts that the given ledger entries record.
SELECT coalesce(receipt_jws, '')::text AS receipt_jws, ledger_entry_id, body_removed_at, created_at
FROM (
    SELECT d.receipt_jws, d.ledger_entry_id, d.body_removed_at, d.created_at
    FROM pc.decision_receipts d WHERE d.org_id = sqlc.arg(org_id) AND d.ledger_entry_id = ANY(sqlc.arg(entry_ids)::uuid[])
    UNION ALL
    SELECT x.receipt_jws, x.ledger_entry_id, x.body_removed_at, x.created_at
    FROM pc.execution_receipts x WHERE x.org_id = sqlc.arg(org_id) AND x.ledger_entry_id = ANY(sqlc.arg(entry_ids)::uuid[])
    UNION ALL
    SELECT f.receipt_jws, f.ledger_entry_id, f.body_removed_at, f.created_at
    FROM pc.effect_receipts f WHERE f.org_id = sqlc.arg(org_id) AND f.ledger_entry_id = ANY(sqlc.arg(entry_ids)::uuid[])
) r
ORDER BY created_at, ledger_entry_id;

-- name: ChainedEntriesByID :many
SELECT c.seq, c.prev_hash, c.entry_hash, e.id, e.kind, e.actor_type, e.actor_id, e.occurred_at, e.body,
       e.body_removed_at, e.removed_by_policy
FROM pc.ledger_chain c
JOIN pc.ledger_entries e ON e.org_id = c.org_id AND e.id = c.entry_id
WHERE c.org_id = sqlc.arg(org_id) AND c.entry_id = ANY(sqlc.arg(entry_ids)::uuid[])
ORDER BY c.seq;

-- Sandbox closures in the ledger (G0 M12 D3, HR-227): the chained
-- sandbox.closure entries of closures, with the agent each is of. Entries
-- whose body retention removed name no closure and are not matched.
-- name: ClosureEntryRefs :many
SELECT e.id AS entry_id, coalesce(x.body ->> 'closure', '')::text AS closure_id, coalesce(x.body ->> 'agent', '')::text AS agent_id
FROM pc.ledger_entries e
JOIN pc.ledger_chain c ON c.org_id = e.org_id AND c.entry_id = e.id
CROSS JOIN LATERAL (SELECT CASE WHEN e.body_removed_at IS NULL THEN convert_from(e.body, 'UTF8')::jsonb END AS body) x
WHERE e.org_id = sqlc.arg(org_id) AND e.kind = 'sandbox.closure'
  AND x.body ->> 'closure' = ANY(sqlc.arg(closure_ids)::text[])
ORDER BY c.seq;

-- The chained sandbox.closure entries that record any of the probe runs,
-- as ClosureEntryRefs gives them.
-- name: ClosureEntryRefsOfRuns :many
SELECT e.id AS entry_id, coalesce(x.body ->> 'closure', '')::text AS closure_id, coalesce(x.body ->> 'agent', '')::text AS agent_id
FROM pc.ledger_entries e
JOIN pc.ledger_chain c ON c.org_id = e.org_id AND c.entry_id = e.id
CROSS JOIN LATERAL (SELECT CASE WHEN e.body_removed_at IS NULL THEN convert_from(e.body, 'UTF8')::jsonb END AS body) x
WHERE e.org_id = sqlc.arg(org_id) AND e.kind = 'sandbox.closure'
  AND EXISTS (SELECT 1 FROM jsonb_array_elements(x.body -> 'reports') r WHERE r ->> 'run' = ANY(sqlc.arg(run_ids)::text[]))
ORDER BY c.seq;

-- The signed probe reports of probe runs, exactly as stored.
-- name: ProbeRunReports :many
SELECT id, report FROM pc.probe_runs
WHERE org_id = sqlc.arg(org_id) AND id = ANY(sqlc.arg(run_ids)::uuid[])
ORDER BY id;
