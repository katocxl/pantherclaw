// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipelinetest

import (
	"context"
	"encoding/hex"
	"slices"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The world also implements finalize.Store, with the same conditions as the
// database adapter, so a decision's reservations and claims are what the
// next evaluation reads.

type txnKey struct{ run, action ids.UUID }

type permitRow struct {
	gateway    string
	txn        ids.UUID
	epoch      int64
	state      string // ISSUED, DISPATCHING, DISPATCHED, UNKNOWN, RELEASED
	expires    time.Time
	dispatched time.Time
	lines      []bdomain.Line
	claim      string
	// What the permit bound (G0 M6), and what BeginDispatch recorded.
	dispatch Dispatched
	channel  string
	monitor  bool
}

type finalState struct {
	txns     map[txnKey]*finalize.Stored
	permits  map[ids.UUID]*permitRow
	rowRefs  map[ids.UUID]bdomain.Ref
	refRows  map[bdomain.Ref]ids.UUID
	debits   map[bdomain.Ref]bdomain.Debit
	counters map[bdomain.Ref]bdomain.CounterDebit
	events   []string
	// receipts are every evaluation's receipt, with its sealed inputs (G0 M7).
	receipts map[InputKey]finalize.Receipt
}

func (w *World) fin() *finalState {
	if w.final == nil {
		w.final = &finalState{
			txns: map[txnKey]*finalize.Stored{}, permits: map[ids.UUID]*permitRow{}, rowRefs: map[ids.UUID]bdomain.Ref{},
			refRows: map[bdomain.Ref]ids.UUID{}, debits: map[bdomain.Ref]bdomain.Debit{}, counters: map[bdomain.Ref]bdomain.CounterDebit{},
			receipts: map[InputKey]finalize.Receipt{},
		}
	}
	return w.final
}

// Advance moves the database clock.
func (w *World) Advance(d time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Cont.Now = w.Cont.Now.Add(d)
}

// SecurityEvents returns the security events recorded (action_tampered).
func (w *World) SecurityEvents() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.fin().events)
}

// PermitState returns a permit's state.
func (w *World) PermitState(id ids.UUID) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if p, ok := w.fin().permits[id]; ok {
		return p.state
	}
	return ""
}

// AccountState returns the usage of the budget account of a debit.
func (w *World) AccountState(ref bdomain.Ref) bdomain.Account {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.accounts[ref]
}

// DeleteRow removes the budget account or counter row of ref, as an
// operator deleting it from the database would (the application never
// does).
func (w *World) DeleteRow(ref bdomain.Ref) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f := w.fin()
	delete(f.rowRefs, f.refRows[ref])
	delete(f.refRows, ref)
	delete(w.accounts, ref)
	delete(w.counters, ref)
}

// Lookup implements finalize.Store.
func (w *World) Lookup(_ context.Context, _ ids.OrgID, run, action ids.UUID) (*finalize.Stored, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.fin().txns[txnKey{run, action}]; ok {
		c := *s
		return &c, nil
	}
	return nil, nil //nolint:nilnil // no transaction yet
}

// Prepare implements finalize.Store.
func (w *World) Prepare(_ context.Context, _ ids.OrgID, plan gdomain.Plan) ([]finalize.Row, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f := w.fin()
	var out []finalize.Row
	resolve := func(ref bdomain.Ref, kind bdomain.Kind) {
		id, ok := f.refRows[ref]
		if !ok {
			id = ids.NewV7()
			f.refRows[ref], f.rowRefs[id] = id, ref
		}
		out = append(out, finalize.Row{Ref: ref, Kind: kind, ID: id})
	}
	for _, d := range plan.Budgets {
		f.debits[d.Ref] = d
		resolve(d.Ref, bdomain.KindBudget)
	}
	for _, d := range plan.Counters {
		f.counters[d.Ref] = d
		resolve(d.Ref, bdomain.KindCounter)
	}
	return out, nil
}

// Finalize implements finalize.Store.
func (w *World) Finalize(ctx context.Context, org ids.OrgID, wr finalize.Write) error {
	// Current revisions are read before taking the world's lock; the
	// grants store has its own.
	var current []gdomain.Version
	var active bool
	if (wr.Permit != nil || finalize.Holds(wr.Eval)) && len(wr.Eval.Chain.Grants) > 0 {
		leaf, _ := wr.Eval.Chain.Leaf()
		grants, err := w.Grants.Chain(ctx, org, leaf.ID)
		if err != nil {
			return finalize.ErrConflict
		}
		scopes := make([]gdomain.Scope, 0, len(wr.Eval.Chain.Envelopes))
		for _, e := range wr.Eval.Chain.Envelopes {
			scopes = append(scopes, e.Scope)
		}
		envs, err := w.Grants.Envelopes(ctx, org, scopes)
		if err != nil {
			return finalize.ErrConflict
		}
		active = !slices.ContainsFunc(grants, func(g gdomain.Grant) bool { return g.State != gdomain.StateActive })
		current = gdomain.Chain{Envelopes: envs, Grants: grants}.Versions()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	f := w.fin()
	ev := wr.Eval
	if wr.Permit != nil || finalize.Holds(ev) {
		// A monitor permit binds no authority, only containment (HR-184).
		authority := ev.MonitorPermit() || (active && slices.Equal(current, ev.Chain.Versions()))
		if w.Cont.Epoch != ev.Epoch || w.Cont.KillSwitch || !authority {
			return finalize.ErrConflict
		}
	}
	key := txnKey{ev.RunID, ev.ActionID}
	cur := f.txns[key]
	switch {
	case wr.Prev == nil && cur != nil:
		return finalize.ErrDuplicate
	case wr.Prev != nil && (cur == nil || cur.Final || cur.Evaluations != wr.Prev.Evaluations):
		return finalize.ErrConflict
	}
	if wr.Claim != nil {
		if parked, _ := pipeline.Parked(w.claims[wr.Claim.Key], ev.ActionID, w.Cont.Now, ev.RepeatWindow); parked {
			return finalize.ErrParked
		}
	}
	if err := w.holdWrite(wr); err != nil {
		return err
	}
	// The limits are the evaluated plan's, as the database adapter passes
	// them to its conditional updates, whether or not Prepare ran.
	for _, d := range ev.Plan.Budgets {
		f.debits[d.Ref] = d
	}
	for _, d := range ev.Plan.Counters {
		f.counters[d.Ref] = d
	}
	if err := w.reserve(wr.Lines); err != nil {
		return err
	}
	if wr.Claim != nil {
		w.claims[wr.Claim.Key] = &pipeline.Claim{TransactionID: wr.TransactionID, State: pipeline.ClaimHeld, At: w.Cont.Now}
	}
	if wr.Permit != nil {
		claim := ""
		if wr.Claim != nil {
			claim = wr.Claim.Key
		}
		f.permits[wr.Permit.ID] = &permitRow{
			gateway: wr.Permit.GatewayID, txn: wr.TransactionID, epoch: wr.Permit.Epoch,
			state: "ISSUED", expires: wr.Permit.ExpiresAt, lines: wr.Lines, claim: claim, channel: ev.Channel, monitor: ev.MonitorPermit(),
			dispatch: dispatchOf(ev, wr.TransactionID),
		}
	}
	receipt, err := wr.Sign(w.budgetStates(ev))
	if err != nil {
		return err
	}
	f.receipts[InputKey{wr.TransactionID, wr.Evaluation}] = receipt
	f.txns[key] = &finalize.Stored{
		TransactionID: wr.TransactionID, ActionHash: ev.ActionHash, Decision: ev.Decision,
		Reason: wr.Reason, Final: wr.Final, Evaluations: wr.Evaluation, Receipt: receipt.JWS,
	}
	return nil
}

// reserve applies lines all or nothing, with the limits of their rules.
func (w *World) reserve(lines []bdomain.Line) error {
	f := w.fin()
	book := bdomain.NewBook()
	for _, l := range lines {
		ref, ok := f.rowRefs[l.ID]
		if !ok {
			return finalize.ErrExhausted // the database's conditional update matches no row
		}
		switch l.Kind {
		case bdomain.KindBudget:
			a := w.accounts[ref]
			d := f.debits[ref]
			a.ID, a.Rank, a.Currency, a.Limit, a.MaxCount = l.ID, l.Rank, d.Currency, d.Limit, d.MaxCount
			book.Accounts[l.ID] = &a
		case bdomain.KindCounter:
			c := w.counters[ref]
			d := f.counters[ref]
			c.ID, c.Rank, c.Max, c.MaxOutstanding = l.ID, l.Rank, d.Max, d.MaxOutstanding
			book.Counters[l.ID] = &c
		}
	}
	if _, err := book.Reserve(lines); err != nil {
		return finalize.ErrExhausted
	}
	w.store(book)
	return nil
}

func (w *World) store(book *bdomain.Book) {
	f := w.fin()
	for id, a := range book.Accounts {
		w.accounts[f.rowRefs[id]] = *a
	}
	for id, c := range book.Counters {
		w.counters[f.rowRefs[id]] = *c
	}
}

func (w *World) budgetStates(ev *pipeline.Evaluation) []finalize.BudgetState {
	var out []finalize.BudgetState
	for _, d := range ev.Plan.Budgets {
		a := w.accounts[d.Ref]
		a.Limit, a.MaxCount = d.Limit, d.MaxCount
		s := finalize.BudgetState{
			Level: d.Ref.Owner.ID.String(), Rule: d.Ref.Rule, Currency: string(d.Currency),
			Reserved: a.Reserved.String(), Spent: a.Spent.String(),
		}
		if amt, cnt := a.Available(); amt != nil {
			s.Available = amt.String()
		} else if cnt != nil {
			s.Count = strconv.FormatInt(*cnt, 10)
		}
		out = append(out, s)
	}
	return out
}

// Tamper implements finalize.Store.
func (w *World) Tamper(_ context.Context, _ ids.OrgID, prev finalize.Stored, receipt *finalize.Receipt, _ string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	f := w.fin()
	f.events = append(f.events, "security.action_tampered:"+prev.TransactionID.String())
	if prev.Final || receipt == nil {
		return nil
	}
	for k, s := range f.txns {
		if s.TransactionID == prev.TransactionID {
			if s.Final || s.Evaluations != prev.Evaluations {
				return finalize.ErrConflict
			}
			f.receipts[InputKey{s.TransactionID, s.Evaluations + 1}] = *receipt
			f.txns[k] = &finalize.Stored{
				TransactionID: s.TransactionID, ActionHash: s.ActionHash, Decision: "DENY",
				Reason: "ACTION_TAMPERED", Final: true, Evaluations: s.Evaluations + 1, Receipt: receipt.JWS,
			}
		}
	}
	return nil
}

// Dispatched is what a permit bound for its dispatch and what BeginDispatch
// recorded on it.
type Dispatched struct {
	finalize.Dispatching
	Outbound finalize.Outbound
	TokenID  *ids.UUID
}

func dispatchOf(ev *pipeline.Evaluation, txn ids.UUID) Dispatched {
	d := finalize.Dispatching{Transaction: txn, Operation: ev.Operation, TargetType: ev.Target.Type, TargetID: ev.Target.ID}
	hash := ev.EffectiveHash
	if ev.MonitorPermit() {
		hash = ev.ActionHash
	}
	d.EffectiveHash, _ = hex.DecodeString(hash)
	if c := ev.Connection; c != nil {
		id := c.ID
		d.Connection, d.AccessMode = &id, c.AccessMode
	}
	return Dispatched{Dispatching: d}
}

// Dispatch returns what a permit's BeginDispatch recorded.
func (w *World) Dispatch(permit ids.UUID) Dispatched {
	w.mu.Lock()
	defer w.mu.Unlock()
	if p, ok := w.fin().permits[permit]; ok {
		return p.dispatch
	}
	return Dispatched{}
}

// BeginDispatch implements finalize.Store.
func (w *World) BeginDispatch(_ context.Context, _ ids.OrgID, gatewayID string, permit ids.UUID, epoch int64, out finalize.Outbound,
	mint func(finalize.Dispatching) (*ids.UUID, error),
) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	p, ok := w.fin().permits[permit]
	switch {
	case !ok || p.gateway != gatewayID:
		return finalize.ErrPermitUnknown
	case p.state != "ISSUED":
		return finalize.ErrPermitUsed
	case w.Cont.KillSwitch:
		return finalize.ErrKillSwitch
	case !w.Cont.Now.Before(p.expires):
		return finalize.ErrPermitExpired
	case epoch != p.epoch || epoch != w.Cont.Epoch:
		return finalize.ErrEpochStale
	}
	d := p.dispatch
	d.Now = w.Cont.Now
	jti, err := mint(d.Dispatching)
	if err != nil {
		return err // nothing changes: the permit stays ISSUED
	}
	d.Outbound, d.TokenID = out, jti
	p.state, p.dispatched, p.dispatch = "DISPATCHING", w.Cont.Now, d
	return nil
}

// RecordExecution implements finalize.Store.
func (w *World) RecordExecution(_ context.Context, _ ids.OrgID, gatewayID string, e finalize.Execution,
	sign func(x finalize.Executed, now time.Time) (finalize.Receipt, error),
) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	p, ok := w.fin().permits[e.Permit]
	if !ok || p.gateway != gatewayID || p.state != "DISPATCHING" {
		return "", finalize.ErrNotDispatching
	}
	x := finalize.Executed{Transaction: p.txn, Connection: p.dispatch.Connection, AccessMode: finalize.AccessPantherClawHeld, Monitor: p.monitor}
	if p.dispatch.AccessMode != "" {
		x.AccessMode = p.dispatch.AccessMode
	}
	if e.Outcome == finalize.Delegated {
		if p.channel != "hook" && p.channel != "sdk" {
			return "", finalize.ErrNotCooperative
		}
		x.AccessMode = finalize.AccessAgentHeld
	}
	r, err := sign(x, w.Cont.Now)
	if err != nil {
		return "", err
	}
	switch e.Outcome {
	case finalize.Accepted, finalize.Delegated:
		p.state = "DISPATCHED"
		w.settle(p, bdomain.Commit, pipeline.ClaimSucceeded)
	case finalize.Failed:
		p.state = "DISPATCHED"
		w.settle(p, bdomain.Release, pipeline.ClaimReleased)
	case finalize.Unknown:
		p.state = "UNKNOWN" // reservation and claim stay held (HR-003)
	}
	return r.JWS, nil
}

func (w *World) settle(p *permitRow, o bdomain.Outcome, claim pipeline.ClaimState) {
	f := w.fin()
	book := bdomain.NewBook()
	for _, l := range p.lines {
		ref := f.rowRefs[l.ID]
		switch l.Kind {
		case bdomain.KindBudget:
			a := w.accounts[ref]
			book.Accounts[l.ID] = &a
		case bdomain.KindCounter:
			c := w.counters[ref]
			book.Counters[l.ID] = &c
		}
	}
	book.Settle(p.lines, o)
	w.store(book)
	if c, ok := w.claims[p.claim]; ok && p.claim != "" && c.TransactionID == p.txn {
		c.State, c.At = claim, w.Cont.Now
	}
}

// ApplySettlements implements finalize.Store: the world settles its
// accounts and counters at once, so nothing is left to apply.
func (w *World) ApplySettlements(context.Context, ids.OrgID) (int, error) { return 0, nil }

// Sweep implements finalize.Store. A swept permit's receipt is signed as
// the sweeper's, like the database store's (HR-192).
func (w *World) Sweep(_ context.Context, _ ids.OrgID, staleAfter time.Duration,
	sign func(gatewayID string, e finalize.Execution, x finalize.Executed, now time.Time) (finalize.Receipt, error),
) (int, int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	released, unknown := 0, 0
	for id, p := range w.fin().permits {
		switch {
		case p.state == "ISSUED" && !w.Cont.Now.Before(p.expires):
			p.state = "RELEASED"
			w.settle(p, bdomain.Release, pipeline.ClaimReleased)
			released++
		case p.state == "DISPATCHING" && w.Cont.Now.Sub(p.dispatched) > staleAfter:
			x := finalize.Executed{
				Transaction: p.txn, Connection: p.dispatch.Connection, AccessMode: finalize.AccessPantherClawHeld,
				Monitor: p.monitor, DispatchedAt: p.dispatched, RecordedBy: finalize.RecordedBySweeper,
			}
			if _, err := sign(p.gateway, finalize.Execution{Permit: id, Outcome: finalize.Unknown, DispatchMS: -1}, x, w.Cont.Now); err != nil {
				return released, unknown, err
			}
			p.state = "UNKNOWN"
			unknown++
		}
	}
	return released, unknown, nil
}
