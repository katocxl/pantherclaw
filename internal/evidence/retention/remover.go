// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package retention

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Limits of one run.
const (
	// DefaultBatch is how many items one batch removes: one transaction and
	// one audit entry.
	DefaultBatch = 500
	// maxBatchesPerStep bounds one run; the next day's run continues.
	maxBatchesPerStep = 200
)

// Actor records removals in the audit ledger.
var Actor = domain.Actor{Type: "system", ID: "evidence-retention"}

// Failure codes recorded in retention_status.last_error.
const (
	// CodeRoleUnavailable: the pc_retention pool is not configured or
	// cannot connect; nothing was removed.
	CodeRoleUnavailable = "ROLE_UNAVAILABLE"
	// CodeFailed: a batch failed; the batches before it were committed.
	CodeFailed = "REMOVAL_FAILED"
)

// step removes one kind of item of a category.
type step struct {
	category Category
	items    string // what the audit entry names
	remove   func(ctx context.Context, q *dbq.Queries, b batch) ([]time.Time, error)
}

// batch is one removal's parameters.
type batch struct {
	org    ids.OrgID
	policy ids.UUID
	cutoff time.Time
	sealed int64
	max    int32
}

// ledgerStep removes the bodies of chained, checkpointed ledger entries
// whose kind matches like and not notLike (LIKE patterns; "" excludes
// nothing).
func ledgerStep(c Category, like, notLike string) step {
	return step{category: c, items: "ledger_entries", remove: func(ctx context.Context, q *dbq.Queries, b batch) ([]time.Time, error) {
		return q.RemoveLedgerBodies(ctx, dbq.RemoveLedgerBodiesParams{
			PolicyID: &b.policy, OrgID: b.org, Cutoff: b.cutoff, KindLike: like, KindNotLike: notLike, SealedSeq: b.sealed,
			MaxRows: b.max,
		})
	}}
}

// steps lists what each category removes (design decision 9). Payload
// captures (B9) join the payloads category with their table.
var steps = []step{
	{category: NormalizedFacts, items: "observations", remove: func(ctx context.Context, q *dbq.Queries, b batch) ([]time.Time, error) {
		return q.RemoveObservedValues(ctx, dbq.RemoveObservedValuesParams{PolicyID: &b.policy, OrgID: b.org, Cutoff: b.cutoff, MaxRows: b.max})
	}},
	{category: NormalizedFacts, items: "evaluation_inputs", remove: func(ctx context.Context, q *dbq.Queries, b batch) ([]time.Time, error) {
		return q.DeleteEvaluationInputs(ctx, b.org, b.cutoff, b.max)
	}},
	{category: Receipts, items: "decision_receipts", remove: func(ctx context.Context, q *dbq.Queries, b batch) ([]time.Time, error) {
		return q.RemoveDecisionReceiptBodies(ctx, dbq.RemoveDecisionReceiptBodiesParams{PolicyID: &b.policy, OrgID: b.org, Cutoff: b.cutoff, MaxRows: b.max})
	}},
	{category: Receipts, items: "execution_receipts", remove: func(ctx context.Context, q *dbq.Queries, b batch) ([]time.Time, error) {
		return q.RemoveExecutionReceiptBodies(ctx, dbq.RemoveExecutionReceiptBodiesParams{PolicyID: &b.policy, OrgID: b.org, Cutoff: b.cutoff, MaxRows: b.max})
	}},
	{category: Receipts, items: "effect_receipts", remove: func(ctx context.Context, q *dbq.Queries, b batch) ([]time.Time, error) {
		return q.RemoveEffectReceiptBodies(ctx, dbq.RemoveEffectReceiptBodiesParams{PolicyID: &b.policy, OrgID: b.org, Cutoff: b.cutoff, MaxRows: b.max})
	}},
	ledgerStep(Receipts, "receipt.%", ""),
	{category: Approvals, items: "approval_evidence", remove: func(ctx context.Context, q *dbq.Queries, b batch) ([]time.Time, error) {
		return q.RemoveApprovalNotes(ctx, dbq.RemoveApprovalNotesParams{PolicyID: &b.policy, OrgID: b.org, Cutoff: b.cutoff, MaxRows: b.max})
	}},
	ledgerStep(Approvals, "audit.approval.%", ""),
	ledgerStep(SecurityAudit, "audit.%", "audit.approval.%"),
}

// Remover removes expired bodies of one org at a time. Pool is the
// pc_retention pool, used by nothing else; App is the pc_app pool, used
// only to record the defaults and the run's status.
type Remover struct {
	Pool *db.Pool
	App  *db.Pool
	Log  *slog.Logger
	// Batch is the batch size (DefaultBatch when 0).
	Batch int
	// Shift moves the database clock forward. Tests only; zero in
	// production.
	Shift time.Duration
}

// Removed counts one step's removals.
type Removed struct {
	Category Category
	Items    string
	Count    int
}

// Result is one run of one org.
type Result struct {
	Removed []Removed
}

// Total is the number of items removed.
func (r Result) Total() int {
	n := 0
	for _, x := range r.Removed {
		n += x.Count
	}
	return n
}

// ErrUnavailable reports a run without the pc_retention role.
var ErrUnavailable = errors.New("retention: the pc_retention role is not configured")

// Run removes org's expired bodies, batch by batch, and records the run in
// retention_status. When the retention role is unavailable nothing is
// removed and the run is recorded as failed.
func (r *Remover) Run(ctx context.Context, org ids.OrgID) (Result, error) {
	if err := EnsureDefaults(ctx, r.App, org); err != nil {
		return Result{}, err
	}
	var res Result
	var runErr error
	if r.Pool == nil {
		runErr = ErrUnavailable
	} else {
		runErr = r.run(ctx, org, &res)
	}
	code := (*string)(nil)
	if runErr != nil {
		c := CodeFailed
		var connect *pgconn.ConnectError
		if errors.Is(runErr, ErrUnavailable) || errors.As(runErr, &connect) {
			c = CodeRoleUnavailable
		}
		code = &c
		if r.Log != nil {
			r.Log.WarnContext(ctx, "evidence.retention_failed", slog.String("org", org.String()), slog.String("code", c))
		}
	}
	if err := r.App.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).RecordRetentionRun(ctx, org, code, int64(res.Total()))
	}); err != nil {
		return res, errors.Join(runErr, err)
	}
	if runErr == nil && r.Log != nil && res.Total() > 0 {
		r.Log.InfoContext(ctx, "evidence.retention_removed", slog.String("org", org.String()), slog.Int("count", res.Total()))
	}
	return res, runErr
}

func (r *Remover) run(ctx context.Context, org ids.OrgID, res *Result) error {
	size := r.Batch
	if size <= 0 {
		size = DefaultBatch
	}
	for _, s := range steps {
		total := 0
		for range maxBatchesPerStep {
			n, err := r.batch(ctx, org, s, size)
			if err != nil {
				return fmt.Errorf("retention: %s %s: %w", s.category, s.items, err)
			}
			total += n
			if n < size {
				break
			}
		}
		res.Removed = append(res.Removed, Removed{Category: s.category, Items: s.items, Count: total})
	}
	return nil
}

// batch removes up to size items of one step in one transaction holding
// the org's retention lock, under the revision in effect now, and audits
// it.
func (r *Remover) batch(ctx context.Context, org ids.OrgID, s step, size int) (int, error) {
	var n int
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockRetention(ctx, org.UUID()); err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		now = now.Add(r.Shift)
		rows, err := q.ListRetentionRevisions(ctx, org)
		if err != nil {
			return err
		}
		cur, ok := Current(revisionsOf(rows), s.category, now)
		if !ok {
			return nil
		}
		sealed, err := q.RetentionSealedSeq(ctx, org)
		if err != nil {
			return err
		}
		times, err := s.remove(ctx, q, batch{
			org: org, policy: cur.ID, cutoff: now.Add(-time.Duration(cur.Days) * 24 * time.Hour), sealed: sealed,
			max: int32(size), //nolint:gosec // G115: a small batch size
		})
		if err != nil || len(times) == 0 {
			return err
		}
		n = len(times)
		oldest, newest := times[0], times[0]
		for _, t := range times[1:] {
			if t.Before(oldest) {
				oldest = t
			}
			if t.After(newest) {
				newest = t
			}
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "evidence.retention_removed", Actor: Actor, Outcome: audit.Success,
			Object: &audit.Object{Type: "retention_policy", ID: cur.ID.String()},
			Details: map[string]string{
				"category": string(s.category), "items": s.items, "count": strconv.Itoa(n),
				"oldest": oldest.UTC().Format(time.RFC3339Nano), "newest": newest.UTC().Format(time.RFC3339Nano),
				"revision": strconv.Itoa(cur.Number), "days": strconv.Itoa(cur.Days),
			},
		})
		return err
	})
	return n, err
}
