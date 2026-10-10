-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Budget accounts and counters (M4 part 2, HR-048, HR-049). Rows are
-- ensured before finalization; finalization only runs the conditional
-- updates below, last, in the fixed (rank, id) order. A 0-row update means
-- the limit is reached and rolls the whole finalization back. An outcome
-- only records its reservations settled and pending; a background job
-- applies them to the rows in batches (ADR-0015).

-- name: EnsureBudgetAccount :exec
INSERT INTO pc.budget_accounts (org_id, id, owner_kind, owner_id, rule, key_hash, period_start, rank, currency)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(owner_kind), sqlc.arg(owner_id), sqlc.arg(rule), sqlc.arg(key_hash),
        sqlc.arg(period_start), sqlc.arg(rank), sqlc.narg(currency))
ON CONFLICT (org_id, owner_id, rule, key_hash, period_start) DO NOTHING;

-- name: GetBudgetAccount :one
SELECT id, reserved, spent, reserved_count, spent_count
FROM pc.budget_accounts
WHERE org_id = sqlc.arg(org_id) AND owner_id = sqlc.arg(owner_id) AND rule = sqlc.arg(rule)
  AND key_hash = sqlc.arg(key_hash) AND period_start = sqlc.arg(period_start);

-- name: EnsureCounter :exec
INSERT INTO pc.counters (org_id, id, owner_kind, owner_id, rule, key_hash, window_start, rank)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(owner_kind), sqlc.arg(owner_id), sqlc.arg(rule), sqlc.arg(key_hash),
        sqlc.arg(window_start), sqlc.arg(rank))
ON CONFLICT (org_id, owner_id, rule, key_hash, window_start) DO NOTHING;

-- name: GetCounter :one
SELECT id, reserved, spent
FROM pc.counters
WHERE org_id = sqlc.arg(org_id) AND owner_id = sqlc.arg(owner_id) AND rule = sqlc.arg(rule)
  AND key_hash = sqlc.arg(key_hash) AND window_start = sqlc.arg(window_start);

-- name: CountCounterRows :one
SELECT count(*)::integer AS rows
FROM pc.counters
WHERE org_id = sqlc.arg(org_id) AND owner_id = sqlc.arg(owner_id) AND rule = sqlc.arg(rule)
  AND window_start = sqlc.arg(window_start);

-- name: ReserveBudgetAccount :execresult
UPDATE pc.budget_accounts
SET reserved = reserved + sqlc.arg(amount), reserved_count = reserved_count + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND (sqlc.narg(limit_amount)::numeric IS NULL OR spent + reserved + sqlc.arg(amount) <= sqlc.narg(limit_amount)::numeric)
  AND (sqlc.narg(max_count)::integer IS NULL OR spent_count + reserved_count + 1 <= sqlc.narg(max_count)::integer);

-- name: ReserveCounter :execresult
UPDATE pc.counters
SET reserved = reserved + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND reserved + spent + 1 <= sqlc.arg(max)
  AND (sqlc.narg(max_outstanding)::integer IS NULL OR reserved + 1 <= sqlc.narg(max_outstanding)::integer);

-- ApplyToBudgetAccount applies settled reservations to an account: amount
-- and n are all of them, spent and spent_n the committed ones.
-- name: ApplyToBudgetAccount :execresult
UPDATE pc.budget_accounts
SET reserved = reserved - sqlc.arg(amount), reserved_count = reserved_count - sqlc.arg(n)::integer,
    spent = spent + sqlc.arg(spent), spent_count = spent_count + sqlc.arg(spent_n)::integer
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
  AND reserved >= sqlc.arg(amount) AND reserved_count >= sqlc.arg(n)::integer;

-- ApplyToCounter applies n settled reservations, spent_n of them
-- committed, to a counter.
-- name: ApplyToCounter :execresult
UPDATE pc.counters
SET reserved = reserved - sqlc.arg(n)::integer, spent = spent + sqlc.arg(spent_n)::integer
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND reserved >= sqlc.arg(n)::integer;

-- name: InsertReservation :exec
INSERT INTO pc.reservations (org_id, id, transaction_id, permit_id, account_id, counter_id, amount)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(transaction_id), sqlc.arg(permit_id), sqlc.narg(account_id),
        sqlc.narg(counter_id), sqlc.arg(amount));

-- SettleHeldReservations records an outcome on every held reservation of a
-- permit and leaves them pending: the rows are updated later, by
-- ApplyToBudgetAccount and ApplyToCounter (ADR-0015).
-- name: SettleHeldReservations :execrows
UPDATE pc.reservations SET state = sqlc.arg(to_state), settled_at = now(), pending = true
WHERE org_id = sqlc.arg(org_id) AND permit_id = sqlc.arg(permit_id) AND state = 'HELD';

-- LockPendingReservations takes a batch of pending reservations, with the
-- rank of the row each one reserved (for the lock order), skipping any
-- that another settlement holds.
-- name: LockPendingReservations :many
SELECT r.id, r.account_id, r.counter_id, r.amount, r.state, coalesce(a.rank, c.rank)::smallint AS rank
FROM pc.reservations r
LEFT JOIN pc.budget_accounts a ON a.org_id = r.org_id AND a.id = r.account_id
LEFT JOIN pc.counters c ON c.org_id = r.org_id AND c.id = r.counter_id
WHERE r.org_id = sqlc.arg(org_id) AND r.pending
ORDER BY r.id
LIMIT sqlc.arg(max_rows)
FOR UPDATE OF r SKIP LOCKED;

-- name: ClearPendingReservations :execrows
UPDATE pc.reservations SET pending = false
WHERE org_id = sqlc.arg(org_id) AND id = ANY(sqlc.arg(ids)::uuid[]) AND pending;

-- GetSettledBudgetAccount is GetBudgetAccount with the account's pending
-- reservations applied, for views that show a budget (ADR-0015).
-- name: GetSettledBudgetAccount :one
SELECT a.id,
       (a.reserved - coalesce(p.amount, 0))::numeric(26,8) AS reserved,
       (a.spent + coalesce(p.spent, 0))::numeric(26,8) AS spent,
       (a.reserved_count - coalesce(p.n, 0))::integer AS reserved_count,
       (a.spent_count + coalesce(p.spent_n, 0))::integer AS spent_count
FROM pc.budget_accounts a
LEFT JOIN LATERAL (
    SELECT sum(r.amount) AS amount, count(*) AS n,
           sum(r.amount) FILTER (WHERE r.state = 'COMMITTED') AS spent,
           count(*) FILTER (WHERE r.state = 'COMMITTED') AS spent_n
    FROM pc.reservations r
    WHERE r.org_id = a.org_id AND r.account_id = a.id AND r.pending
) p ON true
WHERE a.org_id = sqlc.arg(org_id) AND a.owner_id = sqlc.arg(owner_id) AND a.rule = sqlc.arg(rule)
  AND a.key_hash = sqlc.arg(key_hash) AND a.period_start = sqlc.arg(period_start);

-- ListOwnerBudgetAccounts returns the latest period of every budget
-- account the given grants and guardrails own, with its pending
-- reservations applied (ADR-0015).
-- name: ListOwnerBudgetAccounts :many
SELECT DISTINCT ON (a.owner_id, a.rule, a.key_hash)
       a.id, a.owner_kind, a.owner_id, a.rule, a.period_start, a.rank, a.currency,
       (a.reserved - coalesce(p.amount, 0))::numeric(26,8) AS reserved,
       (a.spent + coalesce(p.spent, 0))::numeric(26,8) AS spent,
       (a.reserved_count - coalesce(p.n, 0))::integer AS reserved_count,
       (a.spent_count + coalesce(p.spent_n, 0))::integer AS spent_count
FROM pc.budget_accounts a
LEFT JOIN LATERAL (
    SELECT sum(r.amount) AS amount, count(*) AS n,
           sum(r.amount) FILTER (WHERE r.state = 'COMMITTED') AS spent,
           count(*) FILTER (WHERE r.state = 'COMMITTED') AS spent_n
    FROM pc.reservations r
    WHERE r.org_id = a.org_id AND r.account_id = a.id AND r.pending
) p ON true
WHERE a.org_id = sqlc.arg(org_id) AND a.owner_id = ANY(sqlc.arg(owner_ids)::uuid[])
ORDER BY a.owner_id, a.rule, a.key_hash, a.period_start DESC;

-- SetLockTimeout bounds lock waits for the rest of the transaction.
-- name: SetLockTimeout :exec
SELECT set_config('lock_timeout', sqlc.arg(timeout)::text, true);
