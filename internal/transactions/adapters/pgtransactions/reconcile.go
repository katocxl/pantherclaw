// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgtransactions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

var _ app.ReconcileStore = (*Store)(nil)

// require checks that c holds p where agent lives.
func require(ctx context.Context, q *dbq.Queries, c tenancy.Caller, p td.Permission, agent ids.UUID) error {
	a, err := q.GetAgent(ctx, c.Org, agent)
	if err != nil {
		return err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return err
	}
	return c.Require(p, path)
}

// ResolveOccurred implements app.ReconcileStore (HR-192, design decision 3).
func (s *Store) ResolveOccurred(ctx context.Context, c tenancy.Caller, r app.Resolution, sign app.Sign) (app.Reconciliation, error) {
	user := c.Principal.ID
	var out app.Reconciliation
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		k, err := q.ReconciliationByID(ctx, c.Org, r.Reconciliation)
		if db.IsNoRows(err) {
			return app.ErrReconciliationNotFound
		} else if err != nil {
			return err
		}
		if err := require(ctx, q, c, td.PermTransactionReconcile, k.AgentID); err != nil {
			return err
		}
		if k.State != string(domain.TaskOpen) {
			return domain.ErrNotOpen
		}
		if err := shown(ctx, q, c.Org, k.TransactionID, r.Evidence); err != nil {
			return err
		}
		basis := r.Basis
		evidence := r.Evidence
		if evidence == nil {
			evidence = []ids.UUID{}
		}
		n, err := q.ResolveReconciliationByPerson(ctx, dbq.ResolveReconciliationByPersonParams{
			UserID: &user, Basis: &basis, Evidence: evidence, ObservationID: r.Authoritative, OrgID: c.Org, ID: k.ID,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return domain.ErrNotOpen
		}
		// An unknown outcome's held budget is committed and an exact repeat
		// stays refused; a conflicting effect's budget was committed already.
		if k.Kind == string(domain.KindUnknownOutcome) && k.PermitID != nil {
			if err := pgbudgets.Settle(ctx, q, c.Org, *k.PermitID, bdomain.Commit); err != nil {
				return err
			}
			if err := q.SettleDedupeClaim(ctx, claimSucceeded, c.Org, k.TransactionID); err != nil {
				return err
			}
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		te, err := q.TransactionEffect(ctx, c.Org, k.TransactionID)
		if err != nil {
			return err
		}
		actor := evdomain.Actor{Type: string(td.KindUser), ID: user.String()}
		if deref(te.EffectState, "") != string(domain.Confirmed) {
			e := app.Effect{
				Org: c.Org, Transaction: k.TransactionID, State: domain.Confirmed, Basis: "person", Person: &user,
				Observations: r.Evidence, Required: defs.Level(deref(te.EffectLevelRequired, string(defs.LevelAcceptance))),
				Achieved: defs.Level(deref(te.EffectLevelAchieved, "")), Reason: "RESOLVED_BY_PERSON", At: now,
			}
			if err := appendEffect(ctx, tx, q, e, actor, sign); err != nil {
				return err
			}
		}
		sum := sha256.Sum256([]byte(basis))
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "transaction.reconciliation_resolved", Actor: actor, Outcome: audit.Success, ReasonCode: "OCCURRED",
			Object: &audit.Object{Type: "reconciliation", ID: k.ID.String()},
			Details: map[string]string{
				"transaction": k.TransactionID.String(), "kind": k.Kind, "basis_sha256": hex.EncodeToString(sum[:]),
			},
		}); err != nil {
			return err
		}
		row, err := q.ReconciliationOf(ctx, c.Org, k.ID)
		if err != nil {
			return err
		}
		out = app.ReconciliationOf(row)
		return nil
	})
	return out, err
}

// shown checks that evidence names only the transaction's observations:
// its own, and those its effect receipts and reconciliations name.
func shown(ctx context.Context, q *dbq.Queries, org ids.OrgID, txn ids.UUID, evidence []ids.UUID) error {
	if len(evidence) == 0 {
		return nil
	}
	receipts, err := q.EffectReceiptsOf(ctx, org, txn)
	if err != nil {
		return err
	}
	named := []ids.UUID{}
	for _, f := range receipts {
		named = append(named, app.ReceiptObservations(f.ReceiptJws)...)
	}
	obs, err := q.ObservationsOf(ctx, org, &txn, named)
	if err != nil {
		return err
	}
	for _, e := range evidence {
		if !slices.ContainsFunc(obs, func(o dbq.ObservationsOfRow) bool { return o.ID == e }) {
			return domain.ErrNotEvidence
		}
	}
	return nil
}

// RequestVerification implements app.ReconcileStore.
func (s *Store) RequestVerification(ctx context.Context, c tenancy.Caller, txn ids.UUID) (ids.UUID, error) {
	var out ids.UUID
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := q.TransactionSummary(ctx, c.Org, txn)
		if db.IsNoRows(err) {
			return app.ErrTransactionNotFound
		} else if err != nil {
			return err
		}
		if err := require(ctx, q, c, td.PermTransactionReconcile, t.AgentID); err != nil {
			return err
		}
		due, err := q.VerifyNow(ctx, c.Org, &txn)
		if err != nil {
			return err
		}
		if len(due) == 0 {
			if due, err = q.OpenVerifications(ctx, c.Org, &txn); err != nil {
				return err
			}
		}
		if len(due) > 0 {
			out = due[0]
		} else {
			latest, err := q.LatestVerification(ctx, c.Org, &txn)
			if db.IsNoRows(err) {
				return app.ErrNoVerifier
			} else if err != nil {
				return err
			}
			purpose := domain.PurposeFollowUp
			recs, err := q.ReconciliationsOf(ctx, c.Org, txn)
			if err != nil {
				return err
			}
			if slices.ContainsFunc(recs, func(k dbq.ReconciliationsOfRow) bool {
				return k.Kind == string(domain.KindUnknownOutcome) && k.State == string(domain.TaskOpen)
			}) {
				purpose = domain.PurposeReconcile
			}
			now, err := q.DBNow(ctx)
			if err != nil {
				return err
			}
			out = ids.NewV7()
			if err := q.ScheduleVerification(ctx, dbq.ScheduleVerificationParams{
				OrgID: c.Org, ID: out, Purpose: string(purpose), TransactionID: &txn, ConnectionID: latest.ConnectionID,
				Operation: latest.Operation, Request: latest.Request,
				DeadlineAt: now.Add(time.Duration(latest.WindowSeconds * float64(time.Second))),
			}); err != nil {
				return err
			}
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "transaction.verification_requested", Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "transaction", ID: txn.String()},
			Details: map[string]string{"verification": out.String()},
		})
		return err
	})
	return out, err
}

// Link implements app.ReconcileStore (HR-193). The earlier transaction's
// records and budget never change; it gains a COMPENSATED receipt only
// when both effects are confirmed.
func (s *Store) Link(ctx context.Context, c tenancy.Caller, l app.LinkRequest, sign app.Sign) (app.Link, error) {
	var out app.Link
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if l.From == l.To {
			return domain.ErrLinkSelf
		}
		// Lock both ends in id order.
		ends := map[ids.UUID]dbq.LinkEndRow{}
		pair := []ids.UUID{l.From, l.To}
		slices.SortFunc(pair, compareUUID)
		for _, id := range pair {
			e, err := q.LinkEnd(ctx, c.Org, id)
			if db.IsNoRows(err) {
				return app.ErrTransactionNotFound
			} else if err != nil {
				return err
			}
			if err := require(ctx, q, c, td.PermTransactionReconcile, e.AgentID); err != nil {
				return err
			}
			ends[id] = e
		}
		later, earlier := ends[l.From], ends[l.To]
		var dispatched time.Time
		if earlier.DispatchingAt != nil {
			dispatched = *earlier.DispatchingAt
		}
		if err := domain.CheckLink(l.From, l.To, later.CreatedAt, dispatched); err != nil {
			return err
		}
		by := "user:" + c.Principal.ID.String()
		n, err := q.InsertTransactionLink(ctx, dbq.InsertTransactionLinkParams{
			OrgID: c.Org, FromTransactionID: l.From, ToTransactionID: l.To, Kind: string(l.Kind), CreatedBy: by,
		})
		if err != nil {
			return err
		}
		if n != 1 {
			return app.ErrLinkExists
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "transaction.linked", Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "transaction", ID: l.To.String()},
			Details: map[string]string{"from": l.From.String(), "kind": string(l.Kind)},
		}); err != nil {
			return err
		}
		if l.Kind == domain.LinkCompensates && deref(later.EffectState, "") == string(domain.Confirmed) {
			if err := compensate(ctx, tx, q, c.Org, l.To, l.From, sign); err != nil {
				return err
			}
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		out = app.Link{From: l.From, To: l.To, Kind: l.Kind, CreatedBy: by, Created: now}
		return nil
	})
	return out, err
}

// compensate appends original's COMPENSATED receipt, compensated by by,
// when its effect is confirmed (F487): the receipt keeps the definition's
// reversibility, and nothing else about the original changes.
func compensate(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, original, by ids.UUID, sign app.Sign) error {
	te, err := q.TransactionEffect(ctx, org, original)
	if err != nil {
		return err
	}
	switch err := domain.CompensatedFrom(domain.EffectState(deref(te.EffectState, ""))); {
	case errors.Is(err, domain.ErrNotCompensateable):
		return nil // only a confirmed effect becomes compensated
	case err != nil:
		return err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	e := app.Effect{
		Org: org, Transaction: original, State: domain.Compensated, Basis: "compensation", Compensation: &by,
		Required: defs.Level(deref(te.EffectLevelRequired, string(defs.LevelAcceptance))),
		Achieved: defs.Level(deref(te.EffectLevelAchieved, "")), Reason: "COMPENSATING_EFFECT_CONFIRMED", At: now,
	}
	if te.DefinitionDigest != nil {
		if d, err := definition(ctx, q, org, *te.DefinitionDigest); err == nil {
			e.Reversibility = d.Reversibility
		}
	}
	return appendEffect(ctx, tx, q, e, evdomain.Actor{Type: "system", ID: "compensation"}, sign)
}

// compensations follows a newly confirmed effect: the transactions it
// compensates, and those that compensated it before it was confirmed.
func compensations(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, txn ids.UUID, sign app.Sign) error {
	originals, err := q.Compensated(ctx, org, txn)
	if err != nil {
		return err
	}
	for _, o := range originals {
		if err := compensate(ctx, tx, q, org, o, txn, sign); err != nil {
			return err
		}
	}
	by, err := q.CompensatedBy(ctx, org, txn)
	if err != nil || len(by) == 0 {
		return err
	}
	return compensate(ctx, tx, q, org, txn, by[0], sign)
}
