// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgauthority is the PostgreSQL side of the M4 Transaction
// Authority: Store implements finalize.Store (the finalization transaction
// and settlement, design decisions 15-18) and Reader implements
// pipeline.Reader over the other modules' stores.
package pgauthority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pgwaitlist "github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

const (
	receiptKindDecision  = "receipt.decision"
	receiptKindExecution = "receipt.execution"
)

// Store implements finalize.Store.
type Store struct {
	Pool *db.Pool
	// LockTimeout bounds how long a finalization waits for a budget account
	// or counter row (ADR-0015): past it, Finalize returns finalize.ErrBusy.
	// Zero keeps the pool's lock timeout.
	LockTimeout time.Duration
}

var _ finalize.Store = (*Store)(nil)

// Lookup implements finalize.Store.
func (s *Store) Lookup(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*finalize.Stored, error) {
	var out *finalize.Stored
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = lookup(ctx, dbq.New(tx), org, run, action)
		return err
	}, db.ReadOnly())
	return out, err
}

func lookup(ctx context.Context, q *dbq.Queries, org ids.OrgID, run, action ids.UUID) (*finalize.Stored, error) {
	row, err := q.GetDecision(ctx, org, run, action)
	if db.IsNoRows(err) {
		return nil, nil //nolint:nilnil // no transaction yet
	}
	if err != nil {
		return nil, err
	}
	return &finalize.Stored{
		TransactionID: row.ID, ActionHash: hex.EncodeToString(row.ActionHash), Decision: decision(row.Decision),
		Reason: row.ReasonCode, Final: row.State == "FINAL", Evaluations: int(row.Evaluations), Receipt: row.Receipt,
	}, nil
}

// Prepare implements finalize.Store.
func (s *Store) Prepare(ctx context.Context, org ids.OrgID, plan gdomain.Plan) ([]finalize.Row, error) {
	rows, err := pgbudgets.Ensure(ctx, s.Pool, org, plan.Budgets, plan.Counters)
	if errors.Is(err, pgbudgets.ErrCapacity) {
		return nil, finalize.ErrConflict // the next evaluation explains it
	}
	if err != nil {
		return nil, err
	}
	var out []finalize.Row
	for ref, id := range rows.Accounts {
		out = append(out, finalize.Row{Ref: ref, Kind: bdomain.KindBudget, ID: id})
	}
	for ref, id := range rows.Counters {
		out = append(out, finalize.Row{Ref: ref, Kind: bdomain.KindCounter, ID: id})
	}
	return out, nil
}

// Finalize implements finalize.Store: one transaction, in the lock order.
func (s *Store) Finalize(ctx context.Context, org ids.OrgID, w finalize.Write) error {
	ev := w.Eval
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		holds := finalize.Holds(ev)
		if w.Permit != nil || holds {
			// A hold takes the same containment and chain check as a permit:
			// no request is recorded under the kill switch or on authority
			// that changed (HR-171).
			check := checkAuthority
			if ev.MonitorPermit() {
				check = checkContainment // a monitor permit binds no authority (HR-184)
			}
			if err := check(ctx, q, org, ev); err != nil {
				return err
			}
		}
		if err := s.idempotency(ctx, q, org, w); err != nil {
			return err
		}
		actor := evdomain.Actor{Type: "gateway", ID: w.GatewayID}
		if holds && !w.HoldRequest.IsZero() {
			if err := approvals(pgapprovals.RecordHold(ctx, tx, org, holdOf(w, ev, actor))); err != nil {
				return err
			}
		}
		if h := ev.Hold; h != nil && h.Expire && h.Request != nil && ev.Decision == adomain.Deny {
			if err := pgapprovals.Expire(ctx, tx, org, h.Request.ID, actor); err != nil {
				return err
			}
		}
		if w.Permit != nil && w.Claim != nil {
			if err := claim(ctx, q, org, w, ev); err != nil {
				return err
			}
		}
		// The receipt shows each budget as read just before the reservation
		// plus this action, so the reservation can stay the last statement.
		states, err := budgetStates(ctx, q, org, ev)
		if err != nil {
			return err
		}
		receipt, err := w.Sign(states)
		if err != nil {
			return err
		}
		if err := writeReceipt(ctx, tx, org, w.TransactionID, w.Evaluation, w.GatewayID, receipt); err != nil {
			return err
		}
		if w.Permit != nil {
			rows := pgbudgets.Rows{Accounts: map[bdomain.Ref]ids.UUID{}, Counters: map[bdomain.Ref]ids.UUID{}}
			for _, r := range w.Rows {
				if r.Kind == bdomain.KindCounter {
					rows.Counters[r.Ref] = r.ID
				} else {
					rows.Accounts[r.Ref] = r.ID
				}
			}
			lines := pgbudgets.Lines(ev.Plan.Budgets, ev.Plan.Counters, rows)
			mode := pipeline.ModeEnforce
			if ev.MonitorPermit() {
				mode = pipeline.ModeMonitor
			}
			ins := dbq.InsertPermitForTransactionParams{
				OrgID: org, ID: w.Permit.ID, TransactionID: w.TransactionID, GatewayID: w.Permit.GatewayID,
				Epoch: w.Permit.Epoch, ExpiresAt: w.Permit.ExpiresAt, Mode: mode, ConnectionID: connectionOf(ev),
			}
			if err := verifyPlan(&ins, ev.Verify); err != nil {
				return err
			}
			if err := q.InsertPermitForTransaction(ctx, ins); err != nil {
				return err
			}
			// The permit consumes the approval it rests on, once, after every
			// approver's eligibility is checked again (HR-031, HR-170, HR-171).
			if h := ev.Hold; h != nil && h.Satisfied && h.Request != nil && !ev.MonitorPermit() {
				if err := approvals(pgapprovals.Consume(ctx, tx, org, h.Request.ID, h.Binding.Hash, w.Permit.ID, actor)); err != nil {
					return err
				}
			}
			// Record locks no budget row: its keys are checked at COMMIT.
			if err := pgbudgets.Record(ctx, q, org, w.TransactionID, w.Permit.ID, lines); err != nil {
				return err
			}
			// Budget last: the hot rows are locked only until COMMIT, and a
			// row another transaction holds for longer than LockTimeout
			// fails fast instead of queueing (ADR-0015).
			if s.LockTimeout > 0 && len(lines) > 0 {
				if err := q.SetLockTimeout(ctx, fmt.Sprintf("%dms", max(s.LockTimeout.Milliseconds(), 1))); err != nil {
					return err
				}
			}
			if err := pgbudgets.ReserveLines(ctx, q, org, lines); err != nil {
				switch {
				case errors.Is(err, pgbudgets.ErrExhausted):
					return finalize.ErrExhausted
				case db.IsLockTimeout(err):
					return finalize.ErrBusy
				}
				return err
			}
		}
		return nil
	})
	if db.IsUniqueViolation(err) {
		return finalize.ErrDuplicate
	}
	return err
}

// approvals maps the approvals adapter's errors onto the finalization's.
func approvals(err error) error {
	switch {
	case errors.Is(err, pgapprovals.ErrHoldLimit):
		return finalize.ErrHoldLimit
	case errors.Is(err, pgapprovals.ErrNotMet):
		return finalize.ErrApprovalNotMet
	case errors.Is(err, pgapprovals.ErrChanged):
		return finalize.ErrConflict
	}
	return err
}

// holdOf is the hold a finalization records for ev.
func holdOf(w finalize.Write, ev *pipeline.Evaluation, actor evdomain.Actor) pgapprovals.Hold {
	h := ev.Hold
	leaf, _ := ev.Chain.Leaf()
	agent, _ := ids.ParseUUID(ev.Identity.Agent)
	out := pgapprovals.Hold{
		RequestID: w.HoldRequest, TransactionID: w.TransactionID, Evaluation: w.Evaluation, AgentID: agent, RunID: ev.RunID,
		GrantID: leaf.ID.UUID(), GrantRevision: leaf.Revision, Operation: ev.Operation,
		Reversibility: h.Display.Consequence.Reversibility, VariantKey: h.VariantKey, First: h.Request == nil,
		Binding: h.Binding, Requirements: h.Requirements, Display: h.Display, DisplayHash: h.DisplayHash,
		Deadline: h.Deadline, Action: h.Action, Actor: actor,
	}
	if r := h.Request; r != nil && r.State.Live() {
		id := r.ID
		out.Previous = &id
	}
	return out
}

// Revalidate implements finalize.Store (HR-170).
func (s *Store) Revalidate(ctx context.Context, org ids.OrgID, request ids.UUID) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return pgapprovals.Revalidate(ctx, tx, org, request)
	})
}

// checkAuthority takes the containment row FOR SHARE first and then checks
// that the epoch, every grant and every guardrail are as evaluated (design
// decision 8): a removal of authority either finished before, and the
// revisions differ, or waits for this transaction and its epoch increment
// makes the permit fail BeginDispatch.
func checkAuthority(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *pipeline.Evaluation) error {
	if err := checkContainment(ctx, q, org, ev); err != nil {
		return err
	}
	leaf, ok := ev.Chain.Leaf()
	if !ok {
		return finalize.ErrConflict
	}
	rows, err := q.GetGrantChain(ctx, org, leaf.ID.UUID())
	if err != nil {
		return err
	}
	var cur gdomain.Chain
	for _, r := range rows {
		if r.State != string(gdomain.StateActive) {
			return finalize.ErrConflict
		}
		id, err := gdomain.ParseGrantID(r.ID.String())
		if err != nil {
			return err
		}
		cur.Grants = append(cur.Grants, gdomain.Grant{ID: id, Revision: int(r.CurrentRevision)})
	}
	keys := make([]string, 0, len(ev.Chain.Envelopes))
	for _, e := range ev.Chain.Envelopes {
		keys = append(keys, gpg.ScopeKey(e.Scope))
	}
	envs, err := q.GetEnvelopes(ctx, org, keys)
	if err != nil {
		return err
	}
	for _, e := range envs {
		id, err := gdomain.ParseEnvelopeID(e.ID.String())
		if err != nil {
			return err
		}
		cur.Envelopes = append(cur.Envelopes, gdomain.Envelope{ID: id, Revision: int(e.Revision), Scope: gdomain.Scope{Kind: gdomain.ScopeKind(e.ScopeKind)}})
	}
	if !sameVersions(cur.Versions(), ev.Chain.Versions()) {
		return finalize.ErrConflict
	}
	return nil
}

// checkContainment takes the containment row FOR SHARE: the epoch must
// still be the evaluated one and the kill switch off.
func checkContainment(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *pipeline.Evaluation) error {
	cont, err := q.ShareContainment(ctx, org)
	if err != nil {
		return fmt.Errorf("authority: containment: %w", err)
	}
	if cont.Epoch != ev.Epoch || cont.KillSwitch {
		return finalize.ErrConflict
	}
	return nil
}

func sameVersions(a, b []gdomain.Version) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Store) idempotency(ctx context.Context, q *dbq.Queries, org ids.OrgID, w finalize.Write) error {
	ev := w.Eval
	state := "OPEN"
	if w.Final {
		state = "FINAL"
	}
	var grantID *ids.UUID
	var grantRev *int32
	if leaf, ok := ev.Chain.Leaf(); ok {
		g, r := leaf.ID.UUID(), int32(leaf.Revision) //nolint:gosec // small
		grantID, grantRev = &g, &r
	}
	basis := ev.Basis.Digest()
	effective, err := hex.DecodeString(ev.EffectiveHash)
	if err != nil {
		return err
	}
	if w.Prev == nil {
		act, err := hex.DecodeString(ev.ActionHash)
		if err != nil {
			return err
		}
		var dedupe *string
		if ev.DedupeKey != "" {
			k := ev.DedupeKey
			dedupe = &k
		}
		channel, ttype, tid := ev.Channel, ev.Target.Type, ev.Target.ID
		return q.InsertDecision(ctx, dbq.InsertDecisionParams{
			OrgID: org, ID: w.TransactionID, RunID: ev.RunID, ActionID: ev.ActionID, ActionHash: act, Operation: ev.Operation,
			Decision: string(ev.Decision), ReasonCode: w.Reason, GatewayID: w.GatewayID, State: state,
			GrantID: grantID, GrantRevision: grantRev, BasisDigest: &basis, EffectiveHash: effective, DedupeKey: dedupe,
			Mode: ev.Mode, ConnectionID: connectionOf(ev), Channel: &channel, TargetType: &ttype, TargetID: &tid,
		})
	}
	return expect(q.UpdateDecision(ctx, dbq.UpdateDecisionParams{
		Decision: string(ev.Decision), ReasonCode: w.Reason, State: state, Evaluations: int32(w.Evaluation), //nolint:gosec // ≤ 33
		GrantID: grantID, GrantRevision: grantRev, BasisDigest: &basis, EffectiveHash: effective, Mode: ev.Mode,
		OrgID: org, ID: w.TransactionID, PrevEvaluations: int32(w.Prev.Evaluations), //nolint:gosec // ≤ 32
	}))
}

// connectionOf is the connection an evaluation accepted, or nil.
func connectionOf(ev *pipeline.Evaluation) *ids.UUID {
	if ev.Connection == nil {
		return nil
	}
	id := ev.Connection.ID
	return &id
}

// claim takes the dedupe key for this transaction, or parks the request
// when an earlier attempt holds it (HR-007). The row lock serializes
// identical actions: the second waits for the first to commit and then
// sees its claim.
func claim(ctx context.Context, q *dbq.Queries, org ids.OrgID, w finalize.Write, ev *pipeline.Evaluation) error {
	if err := q.InsertDedupeClaim(ctx, org, w.Claim.Key, w.TransactionID); err != nil {
		return err
	}
	row, err := q.LockDedupeClaim(ctx, org, w.Claim.Key)
	if err != nil {
		return err
	}
	if row.TransactionID == w.TransactionID {
		return nil
	}
	c := &pipeline.Claim{TransactionID: row.TransactionID, State: pipeline.ClaimState(row.State), At: row.ChangedAt}
	if parked, _ := pipeline.Parked(c, ev.ActionID, ev.Now, ev.RepeatWindow); parked {
		return finalize.ErrParked
	}
	return expect(q.TakeDedupeClaim(ctx, w.TransactionID, org, w.Claim.Key))
}

func budgetStates(ctx context.Context, q *dbq.Queries, org ids.OrgID, ev *pipeline.Evaluation) ([]finalize.BudgetState, error) {
	if len(ev.Plan.Budgets) == 0 {
		return nil, nil
	}
	// The receipt shows each budget as settled: an outcome recorded but
	// not yet applied to its row counts as spent or released (ADR-0015).
	acc, err := pgbudgets.Settled(ctx, q, org, ev.Plan.Budgets)
	if err != nil {
		return nil, err
	}
	var out []finalize.BudgetState
	for _, d := range ev.Plan.Budgets {
		a := acc[d.Ref]
		a.Limit, a.MaxCount = d.Limit, d.MaxCount
		if ev.Permits() {
			a.Reserved, _ = a.Reserved.Add(d.Amount)
			a.ReservedCount++
		}
		st := finalize.BudgetState{
			Level: d.Ref.Owner.ID.String(), Rule: d.Ref.Rule, Currency: string(d.Currency),
			Reserved: a.Reserved.String(), Spent: a.Spent.String(),
		}
		amt, cnt := a.Available()
		if amt != nil {
			st.Available = amt.String()
		}
		if cnt != nil {
			st.Count = fmt.Sprint(*cnt)
		}
		out = append(out, st)
	}
	return out, nil
}

func writeReceipt(ctx context.Context, tx db.TenantTx, org ids.OrgID, txn ids.UUID, evaluation int, gateway string, r finalize.Receipt) error {
	entry, err := ledger.Append(ctx, tx, receiptKindDecision, evdomain.Actor{Type: "gateway", ID: gateway}, r.Body)
	if err != nil {
		return err
	}
	if err := dbq.New(tx).InsertEvaluationReceipt(ctx, dbq.InsertEvaluationReceiptParams{
		OrgID: org, TransactionID: txn, Evaluation: int32(evaluation), ReceiptJws: r.JWS, LedgerEntryID: entry.ID, //nolint:gosec // ≤ 33
	}); err != nil {
		return err
	}
	return writeInputs(ctx, tx, org, txn, evaluation, r.Inputs)
}

// Tamper implements finalize.Store.
func (s *Store) Tamper(ctx context.Context, org ids.OrgID, prev finalize.Stored, receipt *finalize.Receipt, gatewayID string) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "security.action_tampered", Actor: evdomain.Actor{Type: "gateway", ID: gatewayID}, Outcome: audit.Denied,
			ReasonCode: "ACTION_TAMPERED", Object: &audit.Object{Type: "transaction", ID: prev.TransactionID.String()},
		}); err != nil {
			return err
		}
		if prev.Final || receipt == nil {
			return nil
		}
		// Only the decision changes: the transaction keeps its mode, grant
		// and hashes.
		if err := expect(dbq.New(tx).CloseTampered(ctx, org, prev.TransactionID, int32(prev.Evaluations))); err != nil { //nolint:gosec // ≤ 32
			return err
		}
		return writeReceipt(ctx, tx, org, prev.TransactionID, prev.Evaluations+1, gatewayID, *receipt)
	})
}

// BeginDispatch implements finalize.Store (HR-001, HR-188).
func (s *Store) BeginDispatch(ctx context.Context, org ids.OrgID, gatewayID string, permit ids.UUID, epoch int64, out finalize.Outbound,
	mint func(finalize.Dispatching) (*ids.UUID, error),
) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		_, err := q.BeginDispatch(ctx, dbq.BeginDispatchParams{OrgID: org, ID: permit, GatewayID: gatewayID, Epoch: epoch})
		if err == nil {
			return dispatching(ctx, q, org, permit, out, mint)
		}
		if !db.IsNoRows(err) {
			return err
		}
		st, err := q.GetPermit(ctx, org, permit)
		switch {
		case db.IsNoRows(err):
			return finalize.ErrPermitUnknown
		case err != nil:
			return err
		case st.GatewayID != gatewayID:
			return finalize.ErrPermitUnknown
		case st.State != "ISSUED":
			return finalize.ErrPermitUsed
		case st.KillSwitch:
			return finalize.ErrKillSwitch
		case st.Expired:
			return finalize.ErrPermitExpired
		}
		return finalize.ErrEpochStale
	})
}

// dispatching records the outbound request on a permit that just moved to
// DISPATCHING and lets mint issue its action token over what the permit
// bound: a monitor permit the requested action, any other the effective
// one.
func dispatching(ctx context.Context, q *dbq.Queries, org ids.OrgID, permit ids.UUID, out finalize.Outbound,
	mint func(finalize.Dispatching) (*ids.UUID, error),
) error {
	p, err := q.DispatchingPermit(ctx, org, permit)
	if err != nil {
		return err
	}
	d := finalize.Dispatching{
		Transaction: p.TransactionID, Connection: p.ConnectionID, Operation: p.Operation, EffectiveHash: p.EffectiveHash, Now: p.Now,
	}
	if p.AccessMode != nil {
		d.AccessMode = *p.AccessMode
	}
	if p.TargetType != nil && p.TargetID != nil {
		d.TargetType, d.TargetID = *p.TargetType, *p.TargetID
	}
	if p.Mode == pipeline.ModeMonitor || len(p.EffectiveHash) == 0 {
		d.EffectiveHash = p.ActionHash
	}
	jti, err := mint(d)
	if err != nil {
		return err
	}
	rec := dbq.RecordOutboundParams{OrgID: org, ID: permit, ActionTokenJti: jti}
	if out.Method != "" {
		rec.OutboundMethod, rec.OutboundUrl = &out.Method, &out.URL
	}
	if len(out.BodySHA256) == sha256.Size {
		rec.OutboundBodySha256 = out.BodySHA256
	}
	return q.RecordOutbound(ctx, rec)
}

// RecordExecution implements finalize.Store: the attempt, the execution
// receipt and its ledger entry, then the settlement, in one transaction.
func (s *Store) RecordExecution(ctx context.Context, org ids.OrgID, gatewayID string, e finalize.Execution,
	sign func(x finalize.Executed, now time.Time) (finalize.Receipt, error),
) (string, error) {
	var receipt string
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		o, permit := e.Outcome, e.Permit
		pc, err := q.ExecutionContext(ctx, org, permit, gatewayID)
		if db.IsNoRows(err) {
			return finalize.ErrNotDispatching
		} else if err != nil {
			return err
		}
		x := executed(pc, finalize.RecordedByGateway)
		if o == finalize.Delegated {
			if pc.Channel == nil || (*pc.Channel != "hook" && *pc.Channel != "sdk") {
				return finalize.ErrNotCooperative
			}
			x.AccessMode = finalize.AccessAgentHeld // the agent performed it with its own access (HR-186)
		}
		to := "DISPATCHED"
		if o == finalize.Unknown {
			to = "UNKNOWN"
		}
		txn, err := q.FinishPermitForTransaction(ctx, dbq.FinishPermitForTransactionParams{ToState: to, OrgID: org, ID: permit, GatewayID: gatewayID})
		if db.IsNoRows(err) {
			// Too late: the sweeper may have marked it UNKNOWN (G0 M7).
			receipt, err = lateReport(ctx, q, org, gatewayID, e, pc)
			return err
		}
		if err != nil {
			return err
		}
		x.Transaction = txn
		if x.TargetRef, err = scheduleVerification(ctx, q, org, pc, o, e.TargetRef); err != nil {
			return err
		}
		attempt := dbq.InsertExecutionAttemptParams{
			OrgID: org, ID: ids.NewV7(), PermitID: permit, TransactionID: txn, Outcome: string(o), AccessMode: &x.AccessMode,
			RecordedBy: finalize.RecordedByGateway,
		}
		if x.TargetRef != "" {
			attempt.TargetRef = &x.TargetRef
		}
		if e.TargetStatus > 0 {
			attempt.TargetStatus = &e.TargetStatus
		}
		if len(e.ResponseDigest) == sha256.Size {
			attempt.ResponseDigest = e.ResponseDigest
		}
		if e.DispatchMS >= 0 {
			attempt.DispatchMs = &e.DispatchMS
		}
		if err := q.InsertExecutionAttempt(ctx, attempt); err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		r, err := sign(x, now)
		if err != nil {
			return err
		}
		if err := keepReceipt(ctx, tx, q, org, attempt.ID, txn, permit, evdomain.Actor{Type: "gateway", ID: gatewayID}, r); err != nil {
			return err
		}
		receipt = r.JWS
		switch o {
		case finalize.Accepted, finalize.Delegated:
			if err := pgbudgets.Settle(ctx, q, org, permit, bdomain.Commit); err != nil {
				return err
			}
			return q.SettleDedupeClaim(ctx, string(pipeline.ClaimSucceeded), org, txn)
		case finalize.Failed:
			if err := pgbudgets.Settle(ctx, q, org, permit, bdomain.Release); err != nil {
				return err
			}
			return q.SettleDedupeClaim(ctx, string(pipeline.ClaimReleased), org, txn)
		case finalize.Unknown: // reservations and claim stay held until reconciled (HR-003, HR-192, F115)
			if err := openReconciliation(ctx, q, org, txn); err != nil {
				return err
			}
			// The waitlist entry people work it from (G0 M5 part 2); A11
			// links it to the reconciliation.
			_, err := pgwaitlist.OpenReconciliation(ctx, tx, org, txn, evdomain.Actor{Type: "gateway", ID: gatewayID})
			return err
		}
		return nil
	})
	return receipt, err
}

// Sweep implements finalize.Store (HR-003, HR-192).
func (s *Store) Sweep(ctx context.Context, org ids.OrgID, staleAfter time.Duration,
	sign func(gatewayID string, e finalize.Execution, x finalize.Executed, now time.Time) (finalize.Receipt, error),
) (int, int, error) {
	var released, unknown int
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		expired, err := q.ReleaseExpiredIssued(ctx, org)
		if err != nil {
			return err
		}
		for _, p := range expired {
			if err := pgbudgets.Settle(ctx, q, org, p.ID, bdomain.Release); err != nil {
				return err
			}
			if err := q.SettleDedupeClaim(ctx, string(pipeline.ClaimReleased), org, p.TransactionID); err != nil {
				return err
			}
		}
		stale, err := q.MarkStaleDispatching(ctx, org, staleAfter.Seconds())
		if err != nil {
			return err
		}
		// Each unknown outcome gets its evidence and a reconciliation, and
		// waits on the waitlist (G0 M5 part 2).
		for _, p := range stale {
			if err := sweptEvidence(ctx, tx, q, org, p, sign); err != nil {
				return err
			}
			if _, err := pgwaitlist.OpenReconciliation(ctx, tx, org, p.TransactionID, pgwaitlist.System); err != nil {
				return err
			}
		}
		released, unknown = len(expired), len(stale)
		return nil
	})
	return released, unknown, err
}

// maxApplyRounds bounds one ApplySettlements call; the next sweep goes on.
const maxApplyRounds = 20

// ApplySettlements implements finalize.Store: batches of pending
// reservations, each applied in its own short transaction (ADR-0015).
func (s *Store) ApplySettlements(ctx context.Context, org ids.OrgID) (int, error) {
	total := 0
	for range maxApplyRounds {
		var n int
		if err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			n, err = pgbudgets.Apply(ctx, dbq.New(tx), org, pgbudgets.MaxApplyBatch)
			return err
		}); err != nil {
			return total, err
		}
		total += n
		if n < pgbudgets.MaxApplyBatch {
			break
		}
	}
	return total, nil
}

func expect(tag interface{ RowsAffected() int64 }, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return finalize.ErrConflict
	}
	return nil
}

func decision(s string) adomain.Decision { return adomain.Decision(s) }
