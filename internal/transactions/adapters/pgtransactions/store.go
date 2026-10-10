// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgtransactions is the PostgreSQL store of verification (G0 M7
// track A): leases, observations, effect receipts and the resolution of
// reconciliations from evidence.
package pgtransactions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json/v2"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// receiptKindEffect is the ledger kind of an effect receipt.
const receiptKindEffect = "receipt.effect"

// claimSucceeded is the dedupe claim's state once its action happened
// (pipeline.ClaimSucceeded).
const claimSucceeded = "SUCCEEDED"

// Notifier queues a notification in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Store implements app.Store.
type Store struct {
	Pool *db.Pool
	// Notify tells admins about effects without a receipt; nil sends
	// nothing.
	Notify Notifier
}

var _ app.Store = (*Store)(nil)

// Claim implements app.Store (HR-190): each lease gets its own random
// secret, of which only the SHA-256 is stored.
func (s *Store) Claim(ctx context.Context, org ids.OrgID, gateway ids.UUID, limit int, leaseFor time.Duration) ([]app.Lease, error) {
	var out []app.Lease
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		due, err := q.DueVerifications(ctx, org, gateway, int32(min(limit, app.MaxClaim))) //nolint:gosec // G115: at most MaxClaim
		if err != nil {
			return err
		}
		gw := gateway
		for _, v := range due {
			secret := make([]byte, 32)
			if _, err := rand.Read(secret); err != nil {
				return err
			}
			hash := sha256.Sum256(secret)
			n, err := q.LeaseVerification(ctx, dbq.LeaseVerificationParams{
				LeaseHash: hash[:], GatewayID: &gw, LeaseSeconds: leaseFor.Seconds(), OrgID: org, ID: v.ID,
			})
			if err != nil {
				return err
			}
			if n != 1 {
				continue
			}
			l := app.Lease{
				Task: v.ID, Secret: secret, Purpose: domain.Purpose(v.Purpose), Connection: v.ConnectionID, Operation: v.Operation,
				Request: v.Request, Attempt: int(v.Attempts) + 1, Deadline: v.DeadlineAt,
			}
			if v.TransactionID != nil {
				l.Correlate = "pc-" + v.TransactionID.String()
			}
			out = append(out, l)
		}
		return nil
	})
	return out, err
}

// Report implements app.Store (HR-190, HR-191, HR-192).
func (s *Store) Report(ctx context.Context, org ids.OrgID, gateway ids.UUID, r app.Report, sign app.Sign) (app.Applied, error) {
	var out app.Applied
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		hash := sha256.Sum256(r.Secret)
		gw := gateway
		task, err := q.LeasedVerification(ctx, dbq.LeasedVerificationParams{OrgID: org, ID: r.Task, GatewayID: &gw, LeaseHash: hash[:]})
		if db.IsNoRows(err) {
			tl, err := q.LeasedTargetLog(ctx, dbq.LeasedTargetLogParams{OrgID: org, ID: r.Task, GatewayID: &gw, LeaseHash: hash[:]})
			if db.IsNoRows(err) {
				return app.ErrLease
			} else if err != nil {
				return err
			}
			out, err = s.targetLog(ctx, tx, q, org, gateway, tl, r, sign)
			return err
		} else if err != nil {
			return err
		}
		if task.TransactionID == nil || task.DefinitionDigest == nil || task.DispatchingAt == nil {
			return app.ErrLease
		}
		d, err := definition(ctx, q, org, *task.DefinitionDigest)
		if err != nil {
			return err
		}
		v := d.Verifier
		if v == nil || !v.Extended() {
			return app.ErrLease
		}
		declared := app.Declared(v)
		for k := range r.Fields {
			if !declared[k] {
				return app.ErrUndeclared
			}
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		txn := *task.TransactionID
		obs, err := observe(ctx, q, org, gateway, task, r)
		if err != nil {
			return err
		}
		out.Observation = obs
		var expected domain.Expected
		if len(task.VerifyExpect) > 0 {
			if err := json.Unmarshal(task.VerifyExpect, &expected); err != nil {
				return fmt.Errorf("pgtransactions: verify plan: %w", err)
			}
		}
		purpose := domain.Purpose(task.Purpose)
		a := domain.Assess(v, purpose, expected, domain.Observation{
			HTTPStatus: r.HTTPStatus, Found: r.Found, Complete: r.Complete, Fields: r.Fields, At: now,
		}, *task.DispatchingAt)
		out.State = a.State

		required := defs.Level(deref(task.EffectLevelRequired, string(defs.LevelAcceptance)))
		if a.State != "" && deref(task.EffectState, "") != string(a.State) {
			achieved := defs.Level(deref(task.EffectLevelAchieved, string(defs.LevelAcceptance)))
			if a.Level != "" && a.Level.Rank() > achieved.Rank() {
				achieved = a.Level
			}
			e := app.Effect{
				Org: org, Transaction: txn, State: a.State, Required: required, Achieved: achieved, Basis: "verifier",
				Observations: []ids.UUID{obs}, Expected: expected, Observed: r.Fields, Effects: app.Effects(d, a.State),
				Verifier: &app.VerifierRef{Operation: v.Operation, Establishes: v.Establishes, Gateway: gateway.String(), Connection: task.ConnectionID.String()},
				Limits:   v.Limits, Reason: a.Reason, At: now,
			}
			if err := appendEffect(ctx, tx, q, e, evdomain.Actor{Type: "gateway", ID: gateway.String()}, sign); err != nil {
				return err
			}
		}

		// Evidence resolves a reconciliation only towards occurred (HR-192).
		if a.Occurred() {
			via := string(domain.ViaVerifier)
			n, err := q.ResolveReconciliationOccurred(ctx, dbq.ResolveReconciliationOccurredParams{
				Via: &via, ObservationID: &obs, OrgID: org, TransactionID: txn,
			})
			if err != nil {
				return err
			}
			if n == 1 {
				out.Resolved = true
				if err := pgbudgets.Settle(ctx, q, org, task.PermitID, bdomain.Commit); err != nil {
					return err
				}
				if err := q.SettleDedupeClaim(ctx, claimSucceeded, org, txn); err != nil {
					return err
				}
			}
		}
		// The target accepted and a read disagrees: someone decides which
		// is authoritative; committed budget stays committed.
		if a.State == domain.Conflicting && purpose == domain.PurposeFollowUp {
			if err := q.OpenReconciliation(ctx, dbq.OpenReconciliationParams{
				OrgID: org, ID: ids.NewV7(), TransactionID: txn, Kind: string(domain.KindConflictingEffect),
			}); err != nil {
				return err
			}
		}

		switch {
		case a.Final || (purpose == domain.PurposeReconcile && a.Occurred()):
			out.Done = true
			return q.FinishVerification(ctx, "DONE", org, task.ID)
		case !now.Before(task.DeadlineAt):
			out.Done = true
			if err := q.FinishVerification(ctx, "EXPIRED", org, task.ID); err != nil {
				return err
			}
			return deadline(ctx, tx, q, org, txn, sign, now)
		}
		return q.RetryVerification(ctx, app.Backoff(int(task.Attempts)).Seconds(), org, task.ID)
	})
	return out, err
}

// Expire implements app.Store.
func (s *Store) Expire(ctx context.Context, org ids.OrgID, sign app.Sign) (int, error) {
	ended := 0
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		var closed []ids.UUID
		released, err := q.ReleaseExpiredLeases(ctx, org)
		if err != nil {
			return err
		}
		for _, r := range released {
			if r.State == "EXPIRED" && r.TransactionID != nil {
				closed = append(closed, *r.TransactionID)
			}
		}
		past, err := q.ExpirePastDeadline(ctx, org)
		if err != nil {
			return err
		}
		for _, r := range past {
			if r.TransactionID != nil {
				closed = append(closed, *r.TransactionID)
			}
		}
		slices.SortFunc(closed, compareUUID)
		for _, txn := range slices.Compact(closed) {
			if err := deadline(ctx, tx, q, org, txn, sign, now); err != nil {
				return err
			}
			ended++
		}
		return nil
	})
	return ended, err
}

// deadline appends the effect receipt of a closed window (F499): the state
// stays when it was conclusive; otherwise it is UNKNOWN, and a status still
// pending is named.
func deadline(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, txn ids.UUID, sign app.Sign, now time.Time) error {
	te, err := q.TransactionEffect(ctx, org, txn)
	if err != nil {
		return err
	}
	current := domain.EffectState(deref(te.EffectState, ""))
	if current != "" && current != domain.PropagationPending && current != domain.Unknown {
		return nil
	}
	if current == domain.Unknown {
		return nil
	}
	reason := "NOTHING_CONCLUSIVE"
	if current == domain.PropagationPending {
		reason = "STILL_PENDING_AT_DEADLINE"
	}
	e := app.Effect{
		Org: org, Transaction: txn, State: domain.Unknown, Basis: "deadline", Reason: reason, At: now,
		Required: defs.Level(deref(te.EffectLevelRequired, string(defs.LevelAcceptance))),
	}
	if a := deref(te.EffectLevelAchieved, ""); a != "" {
		e.Achieved = defs.Level(a)
	}
	if te.DefinitionDigest != nil {
		if d, err := definition(ctx, q, org, *te.DefinitionDigest); err == nil && d.Verifier != nil {
			e.Verifier = &app.VerifierRef{Operation: d.Verifier.Operation, Establishes: d.Verifier.Establishes}
			e.Limits, e.Effects = d.Verifier.Limits, app.Effects(d, domain.Unknown)
		}
	}
	return appendEffect(ctx, tx, q, e, evdomain.Actor{Type: "system", ID: "verifier"}, sign)
}

// appendEffect signs and appends one effect receipt and makes its state
// the transaction's (HR-191: appended, never rewritten).
func appendEffect(ctx context.Context, tx db.TenantTx, q *dbq.Queries, e app.Effect, actor evdomain.Actor, sign app.Sign) error {
	seq, err := q.NextEffectSeq(ctx, e.Org, e.Transaction)
	if err != nil {
		return err
	}
	e.Seq = int(seq)
	signed, err := sign(e)
	if err != nil {
		return err
	}
	entry, err := ledger.Append(ctx, tx, receiptKindEffect, actor, signed.Body)
	if err != nil {
		return err
	}
	var achieved *string
	if e.Achieved != "" {
		a := string(e.Achieved)
		achieved = &a
	}
	if err := q.InsertEffectReceipt(ctx, dbq.InsertEffectReceiptParams{
		OrgID: e.Org, TransactionID: e.Transaction, Seq: seq, State: string(e.State), LevelRequired: string(e.Required),
		LevelAchieved: achieved, Basis: e.Basis, ReceiptJws: signed.JWS, LedgerEntryID: entry.ID,
	}); err != nil {
		return err
	}
	state := string(e.State)
	if err := q.SetEffectState(ctx, dbq.SetEffectStateParams{State: &state, Achieved: achieved, OrgID: e.Org, ID: e.Transaction}); err != nil {
		return err
	}
	if e.State != domain.Confirmed {
		return nil
	}
	return compensations(ctx, tx, q, e.Org, e.Transaction, sign) // HR-193
}

// observe records what the gateway reported (HR-190).
func observe(ctx context.Context, q *dbq.Queries, org ids.OrgID, gateway ids.UUID, task dbq.LeasedVerificationRow, r app.Report) (ids.UUID, error) {
	id, txn, task2, attempt := ids.NewV7(), *task.TransactionID, task.ID, task.Attempts
	o := dbq.InsertObservationParams{
		OrgID: org, ID: id, Source: "verifier", TransactionID: &txn, VerificationID: &task2, GatewayID: gateway,
		Attempt: &attempt, Found: pgtype.Bool{Bool: r.Found, Valid: true},
	}
	if r.HTTPStatus >= 100 && r.HTTPStatus <= 599 {
		st := int32(r.HTTPStatus)
		o.HttpStatus = &st
	}
	// Only a target-log listing records completeness on its observation
	// (00060); a lookup's completeness decides its assessment and is named
	// by the effect receipt's reason (NOT_IN_COMPLETE_LISTING).
	if domain.Purpose(task.Purpose) == domain.PurposeTargetLog {
		o.Complete = pgtype.Bool{Bool: r.Complete, Valid: true}
	}
	if len(r.Fields) > 0 {
		b, err := json.Marshal(r.Fields, json.Deterministic(true))
		if err != nil {
			return ids.UUID{}, err
		}
		o.Fields = b
	}
	if len(r.ResponseDigest) == sha256.Size {
		o.ResponseDigest = r.ResponseDigest
	}
	return id, q.InsertObservation(ctx, o)
}

func definition(ctx context.Context, q *dbq.Queries, org ids.OrgID, digest string) (*defs.Definition, error) {
	raw, err := q.DefinitionCanonical(ctx, org, digest)
	if err != nil {
		return nil, err
	}
	var d defs.Definition
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("pgtransactions: stored definition: %w", err)
	}
	return &d, nil
}

func deref(p *string, def string) string {
	if p == nil {
		return def
	}
	return *p
}

func compareUUID(a, b ids.UUID) int {
	for i := range a {
		if a[i] != b[i] {
			return int(a[i]) - int(b[i])
		}
	}
	return 0
}
