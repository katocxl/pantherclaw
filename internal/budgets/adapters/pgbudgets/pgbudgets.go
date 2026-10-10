// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgbudgets keeps budget accounts and counters in PostgreSQL
// (HR-048, HR-049; G0 M4 part 2, design decisions 9-10). Ensure creates the
// rows a plan needs in its own short transaction; the finalization then
// calls Reserve inside its transaction, last, which applies one conditional
// update per row in the fixed (rank, id) order and records a reservation
// per row. Settle records an outcome on every reservation of a permit
// without touching the rows; Apply later applies settled reservations to
// their rows in batches, off the hot path (ADR-0015).
package pgbudgets

import (
	"context"
	"errors"
	"fmt"

	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Errors.
var (
	// ErrExhausted: a row had no room left; the transaction must roll back.
	ErrExhausted = errors.New("budgets: limit reached")
	// ErrCapacity: a counter rule already tracks MaxCounterRows keys in this
	// window (T-023).
	ErrCapacity = errors.New("budgets: counter capacity reached")
)

// Rows maps the refs of a plan to their row ids.
type Rows struct {
	Accounts map[bdomain.Ref]ids.UUID
	Counters map[bdomain.Ref]ids.UUID
}

func ownerKey(r bdomain.Ref) (string, ids.UUID) { return r.Owner.Kind, r.Owner.ID }

// Ensure creates the rows of a plan that do not exist yet and resolves every
// row id, in one short transaction of its own (never inside a
// finalization, so a finalization only updates rows and cannot deadlock on
// inserts).
func Ensure(ctx context.Context, pool *db.Pool, org ids.OrgID, budgets []bdomain.Debit, counters []bdomain.CounterDebit) (Rows, error) {
	out := Rows{Accounts: map[bdomain.Ref]ids.UUID{}, Counters: map[bdomain.Ref]ids.UUID{}}
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		for _, d := range budgets {
			kind, owner := ownerKey(d.Ref)
			var currency *string
			if d.Currency != "" {
				c := string(d.Currency)
				currency = &c
			}
			if err := q.EnsureBudgetAccount(ctx, dbq.EnsureBudgetAccountParams{
				OrgID: org, ID: ids.NewV7(), OwnerKind: kind, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:],
				PeriodStart: d.Ref.Start, Rank: int16(d.Ref.Owner.Rank), Currency: currency, //nolint:gosec // 0..5
			}); err != nil {
				return err
			}
			row, err := q.GetBudgetAccount(ctx, dbq.GetBudgetAccountParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], PeriodStart: d.Ref.Start})
			if err != nil {
				return err
			}
			out.Accounts[d.Ref] = row.ID
		}
		for _, d := range counters {
			kind, owner := ownerKey(d.Ref)
			row, err := q.GetCounter(ctx, dbq.GetCounterParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], WindowStart: d.Ref.Start})
			if db.IsNoRows(err) {
				n, cerr := q.CountCounterRows(ctx, dbq.CountCounterRowsParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, WindowStart: d.Ref.Start})
				if cerr != nil {
					return cerr
				}
				if n >= bdomain.MaxCounterRows {
					return ErrCapacity
				}
				if err := q.EnsureCounter(ctx, dbq.EnsureCounterParams{
					OrgID: org, ID: ids.NewV7(), OwnerKind: kind, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:],
					WindowStart: d.Ref.Start, Rank: int16(d.Ref.Owner.Rank), //nolint:gosec // 0..5
				}); err != nil {
					return err
				}
				row, err = q.GetCounter(ctx, dbq.GetCounterParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], WindowStart: d.Ref.Start})
			}
			if err != nil {
				return err
			}
			out.Counters[d.Ref] = row.ID
		}
		return nil
	})
	return out, err
}

// Usage reads what is reserved and spent on the rows of a plan, and how many
// rows each counter rule has in its window. Rows that do not exist yet have
// no usage.
func Usage(ctx context.Context, q *dbq.Queries, org ids.OrgID, budgets []bdomain.Debit, counters []bdomain.CounterDebit) (
	map[bdomain.Ref]bdomain.Account, map[bdomain.Ref]bdomain.Counter, map[bdomain.Ref]int, error,
) {
	accounts := map[bdomain.Ref]bdomain.Account{}
	ctrs := map[bdomain.Ref]bdomain.Counter{}
	rows := map[bdomain.Ref]int{}
	for _, d := range budgets {
		_, owner := ownerKey(d.Ref)
		row, err := q.GetBudgetAccount(ctx, dbq.GetBudgetAccountParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], PeriodStart: d.Ref.Start})
		if db.IsNoRows(err) {
			continue
		}
		if err != nil {
			return nil, nil, nil, err
		}
		accounts[d.Ref] = bdomain.Account{
			ID: row.ID, Reserved: row.Reserved, Spent: row.Spent,
			ReservedCount: int64(row.ReservedCount), SpentCount: int64(row.SpentCount),
		}
	}
	for _, d := range counters {
		_, owner := ownerKey(d.Ref)
		row, err := q.GetCounter(ctx, dbq.GetCounterParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], WindowStart: d.Ref.Start})
		switch {
		case err == nil:
			ctrs[d.Ref] = bdomain.Counter{ID: row.ID, Reserved: int64(row.Reserved), Spent: int64(row.Spent)}
		case !db.IsNoRows(err):
			return nil, nil, nil, err
		}
		capRef := d.Ref
		capRef.Key = [32]byte{}
		n, err := q.CountCounterRows(ctx, dbq.CountCounterRowsParams{OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, WindowStart: d.Ref.Start})
		if err != nil {
			return nil, nil, nil, err
		}
		rows[capRef] = int(n)
	}
	return accounts, ctrs, rows, nil
}

// Line is one row to reserve, with the current rule limits.
type Line struct {
	bdomain.Line
	Limit          *money.Decimal
	MaxCount       *int64
	Max            int64
	MaxOutstanding *int64
}

// Lines builds the reservation lines of a plan on resolved rows, in the lock
// order (HR-048).
func Lines(budgets []bdomain.Debit, counters []bdomain.CounterDebit, rows Rows) []Line {
	byID := map[ids.UUID]Line{}
	var plain []bdomain.Line
	for _, d := range budgets {
		id := rows.Accounts[d.Ref]
		l := bdomain.Line{Kind: bdomain.KindBudget, ID: id, Rank: d.Ref.Owner.Rank, Amount: d.Amount}
		byID[id] = Line{Line: l, Limit: d.Limit, MaxCount: d.MaxCount}
		plain = append(plain, l)
	}
	for _, d := range counters {
		id := rows.Counters[d.Ref]
		l := bdomain.Line{Kind: bdomain.KindCounter, ID: id, Rank: d.Ref.Owner.Rank}
		byID[id] = Line{Line: l, Max: d.Max, MaxOutstanding: d.MaxOutstanding}
		plain = append(plain, l)
	}
	out := make([]Line, 0, len(plain))
	for _, l := range bdomain.Order(plain) {
		out = append(out, byID[l.ID])
	}
	return out
}

// ReserveLines applies one conditional update per line, in order. The first
// that matches no row returns ErrExhausted: the caller rolls back.
func ReserveLines(ctx context.Context, q *dbq.Queries, org ids.OrgID, lines []Line) error {
	for _, l := range lines {
		var err error
		switch l.Kind {
		case bdomain.KindBudget:
			var maxCount *int32
			if l.MaxCount != nil {
				m := int32(min(*l.MaxCount, 1<<31-1)) //nolint:gosec // clamped
				maxCount = &m
			}
			err = db.ExpectOneRow(q.ReserveBudgetAccount(ctx, dbq.ReserveBudgetAccountParams{
				Amount: l.Amount, OrgID: org, ID: l.ID, LimitAmount: l.Limit, MaxCount: maxCount,
			}))
		case bdomain.KindCounter:
			var outstanding *int32
			if l.MaxOutstanding != nil {
				m := int32(min(*l.MaxOutstanding, 1<<31-1)) //nolint:gosec // clamped
				outstanding = &m
			}
			err = db.ExpectOneRow(q.ReserveCounter(ctx, dbq.ReserveCounterParams{
				OrgID: org, ID: l.ID, Max: int32(min(l.Max, 1<<31-1)), MaxOutstanding: outstanding, //nolint:gosec // clamped
			}))
		}
		if errors.Is(err, db.ErrLostRace) {
			return fmt.Errorf("%w: %s row %s", ErrExhausted, kindName(l.Kind), l.ID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func kindName(k bdomain.Kind) string {
	if k == bdomain.KindCounter {
		return "counter"
	}
	return "budget"
}

// Record records one reservation per line for a permit. It locks no account
// or counter row: the reservations' keys to them are checked at COMMIT
// (migration 00027), after ReserveLines has updated every row, because FOR
// KEY SHARE held by other transactions while a row is updated and rolled
// back can fail the next update in PostgreSQL with "new multixact has more
// than one updating member".
func Record(ctx context.Context, q *dbq.Queries, org ids.OrgID, txn, permit ids.UUID, lines []Line) error {
	for _, l := range lines {
		p := dbq.InsertReservationParams{OrgID: org, ID: ids.NewV7(), TransactionID: txn, PermitID: permit, Amount: l.Amount}
		id := l.ID
		if l.Kind == bdomain.KindCounter {
			p.CounterID = &id
		} else {
			p.AccountID = &id
		}
		if err := q.InsertReservation(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

// Settle records an outcome on every held reservation of a permit: commit
// will move it to spent, release give it back, hold keeps it (HR-003,
// F115). The reservations become pending and their rows are left to Apply,
// so an outcome never waits on a hot row (ADR-0015). Until then a row
// still counts them as reserved, which only makes its budget look more
// consumed than it is.
func Settle(ctx context.Context, q *dbq.Queries, org ids.OrgID, permit ids.UUID, o bdomain.Outcome) error {
	if o == bdomain.Hold {
		return nil
	}
	state := "RELEASED"
	if o == bdomain.Commit {
		state = "COMMITTED"
	}
	_, err := q.SettleHeldReservations(ctx, state, org, permit)
	return err
}

// MaxApplyBatch is how many settled reservations one Apply takes.
const MaxApplyBatch = 1000

// settled is what a batch of settled reservations applies to one row.
type settled struct {
	line          bdomain.Line
	amount, spent money.Decimal
	n, spentN     int32
}

// Apply applies up to max settled reservations to their account and
// counter rows, in q's transaction: it clears their pending flag, then
// updates each row once, in the lock order (HR-048), last, so the rows are
// locked only until COMMIT. Reservations another Apply holds are skipped.
// It returns how many it applied.
func Apply(ctx context.Context, q *dbq.Queries, org ids.OrgID, maxRows int) (int, error) {
	batch, err := q.LockPendingReservations(ctx, org, int32(min(maxRows, MaxApplyBatch))) //nolint:gosec // clamped
	if err != nil || len(batch) == 0 {
		return 0, err
	}
	rows := map[ids.UUID]*settled{}
	var lines []bdomain.Line
	done := make([]ids.UUID, 0, len(batch))
	for _, r := range batch {
		kind, id := bdomain.KindBudget, r.AccountID
		if r.CounterID != nil {
			kind, id = bdomain.KindCounter, r.CounterID
		}
		if id == nil {
			return 0, fmt.Errorf("budgets: reservation %s names no row", r.ID)
		}
		s := rows[*id]
		if s == nil {
			s = &settled{line: bdomain.Line{Kind: kind, ID: *id, Rank: int(r.Rank)}}
			rows[*id] = s
			lines = append(lines, s.line)
		}
		if s.amount, err = s.amount.Add(r.Amount); err != nil {
			return 0, err
		}
		s.n++
		if r.State == "COMMITTED" {
			if s.spent, err = s.spent.Add(r.Amount); err != nil {
				return 0, err
			}
			s.spentN++
		}
		done = append(done, r.ID)
	}
	cleared, err := q.ClearPendingReservations(ctx, org, done)
	if err != nil {
		return 0, err
	}
	if cleared != int64(len(done)) {
		return 0, fmt.Errorf("budgets: cleared %d of %d pending reservations", cleared, len(done))
	}
	for _, l := range bdomain.Order(lines) {
		s := rows[l.ID]
		if l.Kind == bdomain.KindCounter {
			err = db.ExpectOneRow(q.ApplyToCounter(ctx, dbq.ApplyToCounterParams{N: s.n, SpentN: s.spentN, OrgID: org, ID: l.ID}))
		} else {
			err = db.ExpectOneRow(q.ApplyToBudgetAccount(ctx, dbq.ApplyToBudgetAccountParams{
				Amount: s.amount, N: s.n, Spent: s.spent, SpentN: s.spentN, OrgID: org, ID: l.ID,
			}))
		}
		if err != nil {
			return 0, fmt.Errorf("budgets: apply to %s row %s: %w", kindName(l.Kind), l.ID, err)
		}
	}
	return len(batch), nil
}

// Settled reads the budget accounts of a plan as they are once their
// settled reservations are applied (ADR-0015), for views that show a
// budget; decisions use Usage, which reads the rows alone. Accounts that do
// not exist yet are absent.
func Settled(ctx context.Context, q *dbq.Queries, org ids.OrgID, budgets []bdomain.Debit) (map[bdomain.Ref]bdomain.Account, error) {
	out := map[bdomain.Ref]bdomain.Account{}
	for _, d := range budgets {
		_, owner := ownerKey(d.Ref)
		row, err := q.GetSettledBudgetAccount(ctx, dbq.GetSettledBudgetAccountParams{
			OrgID: org, OwnerID: owner, Rule: d.Ref.Rule, KeyHash: d.Ref.Key[:], PeriodStart: d.Ref.Start,
		})
		if db.IsNoRows(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[d.Ref] = bdomain.Account{
			ID: row.ID, Reserved: row.Reserved, Spent: row.Spent,
			ReservedCount: int64(row.ReservedCount), SpentCount: int64(row.SpentCount),
		}
	}
	return out, nil
}
