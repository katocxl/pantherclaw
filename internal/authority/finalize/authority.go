// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Signer signs a JOSE payload with a typed header (platform keys).
type Signer interface {
	Sign(typ string, payload []byte) (string, error)
}

// Reason codes of the final binding. BUDGET_BUSY: a budget or counter was
// too contended to reserve within the lock timeout (ADR-0015); the agent
// may resubmit.
const (
	ReasonConcurrentChange = "CONCURRENT_CHANGE"
	ReasonDuplicateRequest = "DUPLICATE_REQUEST"
	ReasonBudgetBusy       = "BUDGET_BUSY"
	maxAttempts            = 3
)

// DefaultPermitTTL is the permit lifetime (HR-009).
const DefaultPermitTTL = 5 * time.Second

// Gateway is the authenticated gateway asking. Its org comes from its
// credential, never from the request (HR-020).
type Gateway struct {
	ID  string
	Org ids.OrgID
}

// Authority decides and binds actions.
type Authority struct {
	Pipeline *pipeline.Pipeline
	Store    Store
	Receipts Signer
	Permits  Signer
	// ActionTokens signs the action tokens of target-enforced dispatches
	// (HR-188); nil when none are configured.
	ActionTokens Signer
	Issuer       string
	PermitTTL    time.Duration
	Log          *slog.Logger
	// Inputs seals every evaluation's inputs for decision replay, written
	// with its receipt (G0 M7 design decision 11); nil keeps none.
	Inputs InputSealer
}

// Result is the answer to Authorize.
type Result struct {
	Decision      adomain.Decision
	TransactionID ids.UUID
	Evaluation    int
	ActionHash    string
	EffectiveHash string
	BasisDigest   string
	Reasons       []adomain.Reason
	Checklist     []pipeline.Item
	Obligations   []pdomain.Obligation
	Permit        string
	PermitID      ids.UUID
	Epoch         int64
	Receipt       string
	// Mode is the route's mode (pipeline.ModeEnforce or ModeMonitor); in
	// monitor mode the decision is hypothetical and a permit, when present,
	// is what tells the gateway to dispatch (HR-184). AccessMode is how the
	// connection's credential reaches the target, when the action names one.
	Mode       string
	AccessMode string
	// Repeat is set when the answer is a stored decision (HR-005).
	Repeat bool
	// Wait is the wait handle of a held action, or of one its approval
	// request ended (G0 M5 part 2); nil otherwise.
	Wait *Wait
}

// DefaultRetryAfter is how long a held agent waits before waiting again or
// resubmitting (PAP-1 §7.1 retry_after_s).
const DefaultRetryAfter = 5 * time.Second

// Wait is a wait handle (PAP-1 §7.1, §8): the transaction id, the state of
// its approval request as a waiter sees it, and its times. It never carries
// approver identities, notes or the display (HR-174).
type Wait struct {
	Handle           ids.UUID
	RetryAfter       time.Duration
	Deadline         time.Time
	State            string
	ConsumeBy        *time.Time
	RequestID        ids.UUID
	Code             string
	EvidenceDeadline *time.Time
	ProposedParams   []byte
}

// waitOf returns the wait handle of an evaluation: for a hold, and for a
// DENY that its approval request decided (declined, narrower proposed or
// expired).
func waitOf(ev *pipeline.Evaluation, txn ids.UUID) *Wait {
	h := ev.Hold
	if h == nil {
		return nil
	}
	held := ev.Decision == adomain.RequireApproval || ev.Decision == adomain.RequireStepUp
	ended := ev.Decision == adomain.Deny && h.Code != "" && ev.Decisive().Code == h.Code
	if !held && !ended {
		return nil
	}
	w := &Wait{Handle: txn, RetryAfter: DefaultRetryAfter, Deadline: h.Deadline, State: h.State, Code: h.Code}
	if r := h.Request; r != nil && (h.Keep || ended) {
		w.RequestID, w.Deadline = r.ID, r.Deadline
		switch h.State {
		case apdomain.WaitEvidenceRequested:
			w.Code, w.EvidenceDeadline = r.Question, r.EvidenceDeadline
		case apdomain.WaitReady:
			w.ConsumeBy = r.ConsumeBy
		case apdomain.WaitNarrowerProposed:
			w.ProposedParams = r.ProposedParams
		}
	}
	if ended {
		w.RetryAfter = 0
	}
	return w
}

// Authorize decides one action and binds the decision. A finalized
// (run, action) never yields a second permit: repeats return the stored
// decision (HR-005); the same ids with another action hash are denied as
// tampering (HR-006); an OPEN transaction is evaluated again, at most
// MaxEvaluations times.
func (a *Authority) Authorize(ctx context.Context, gw Gateway, req pipeline.Request) (Result, error) {
	act := req.Action.Action
	if org, err := act.OrgID(); err != nil || org != gw.Org || req.Org != gw.Org {
		a.log(ctx).WarnContext(ctx, "authz.org_mismatch", slog.String("gateway_id", gw.ID))
		// A decision, not an error: the gateway asserted another org (HR-020).
		return Result{Decision: adomain.Deny, ActionHash: req.Action.HashHex(), Reasons: []adomain.Reason{{ //nolint:nilerr // decision, not a failure
			Code: adomain.ReasonOrgMismatch, Check: "identity", Decisive: true,
		}}}, nil
	}
	run, err1 := ids.ParseUUID(act.RunID)
	action, err2 := ids.ParseUUID(act.ActionID)
	if err1 != nil || err2 != nil {
		return Result{Decision: adomain.CannotAuthorize, ActionHash: req.Action.HashHex(), Reasons: []adomain.Reason{{ //nolint:nilerr // decision, not a failure
			Code: adomain.ReasonAmbiguousInput, Check: "exact_meaning", Decisive: true,
		}}}, nil
	}
	req.Gateway = gw.ID // the certificate's gateway, never the request's
	for attempt := 0; ; attempt++ {
		if attempt > maxAttempts+1 {
			return Result{}, fmt.Errorf("finalize: no stable decision after %d attempts", attempt)
		}
		prev, ev, rec, err := a.evaluate(ctx, req, run, action)
		if err != nil {
			return Result{}, err
		}
		if ev == nil { // the stored transaction answers
			if prev.ActionHash != req.Action.HashHex() {
				return a.tampered(ctx, gw, req, *prev)
			}
			return repeat(*prev, req.Action.HashHex()), nil
		}
		if attempt >= maxAttempts {
			ev = override(ev, ReasonConcurrentChange, "the authority changed while deciding; try again")
		}
		res, err := a.bind(ctx, gw, ev, prev, rec)
		switch {
		case err == nil:
			a.log(ctx).InfoContext(ctx, "authz.decision", slog.String("txn_id", res.TransactionID.String()),
				slog.String("decision", string(res.Decision)), slog.String("reason_code", ev.Decisive().Code))
			return res, nil
		case errors.Is(err, ErrParked), errors.Is(err, ErrHoldLimit), errors.Is(err, ErrBusy):
			code, detail := pipeline.ReasonReconciliation, "an identical irreversible action is in flight, unknown or recently succeeded"
			switch {
			case errors.Is(err, ErrHoldLimit):
				code, detail = apdomain.ReasonHoldLimitReached, "the grant or the run already has its maximum of pending holds"
			case errors.Is(err, ErrBusy):
				code, detail = ReasonBudgetBusy, "a budget is busy with other actions; try again"
			}
			ev = override(ev, code, detail)
			if res, err = a.bind(ctx, gw, ev, prev, rec); err == nil {
				return res, nil
			}
			if !retryable(err) {
				return Result{}, err
			}
		case errors.Is(err, ErrApprovalNotMet):
			// An approver is no longer eligible (HR-170): record it, then
			// decide again, which holds the action until the request is met.
			if err := a.Store.Revalidate(ctx, gw.Org, ev.Hold.Request.ID); err != nil {
				return Result{}, err
			}
		case retryable(err):
		default:
			return Result{}, err
		}
	}
}

// Lookuper reads the stored transaction for (run, action). A pipeline
// snapshot Reader that implements it (pgauthority's) lets Authorize look the
// transaction up in the evaluation's own snapshot.
type Lookuper interface {
	Lookup(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*Stored, error)
}

// evaluate looks up the stored transaction for (run, action) and, unless it
// answers the request (another action hash, a final decision, or the
// evaluation cap), evaluates the action: both from one snapshot when the
// pipeline's Reader offers one. A nil evaluation means prev answers. The
// recorder holds what the evaluation read, when the Authority keeps inputs.
func (a *Authority) evaluate(ctx context.Context, req pipeline.Request, run, action ids.UUID) (
	*Stored, *pipeline.Evaluation, *recording.Recorder, error,
) {
	var prev *Stored
	var ev *pipeline.Evaluation
	var rec *recording.Recorder
	err := a.Pipeline.Snapshot(ctx, req.Org, func(ctx context.Context, r pipeline.Reader) error {
		l, ok := r.(Lookuper)
		if !ok {
			l = a.Store
		}
		var err error
		if prev, err = l.Lookup(ctx, req.Org, run, action); err != nil {
			return fmt.Errorf("finalize: lookup: %w", err)
		}
		if prev != nil && (prev.ActionHash != req.Action.HashHex() || prev.Final || prev.Evaluations >= MaxEvaluations) {
			return nil
		}
		var reader pipeline.Reader
		reader, rec = a.recorder(r, req)
		ev, err = a.Pipeline.EvaluateWith(ctx, reader, req)
		return err
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return prev, ev, rec, nil
}

// Holds reports whether an evaluation records a hold: an enforced
// REQUIRE_APPROVAL or REQUIRE_STEP_UP with what step 8 established (a
// DENY or CANNOT_AUTHORIZE never does, even when it lists approvals: S03).
func Holds(ev *pipeline.Evaluation) bool {
	return ev.Hold != nil && !ev.MonitorPermit() &&
		(ev.Decision == adomain.RequireApproval || ev.Decision == adomain.RequireStepUp)
}

func retryable(err error) bool {
	return errors.Is(err, ErrConflict) || errors.Is(err, ErrExhausted) || errors.Is(err, ErrDuplicate) || errors.Is(err, ErrParked)
}

// override records ev as CANNOT_AUTHORIZE for a final-binding reason,
// without reservations: an OPEN transaction the agent may resubmit.
func override(ev *pipeline.Evaluation, code, detail string) *pipeline.Evaluation {
	out := *ev
	out.Decision = adomain.CannotAuthorize
	out.Checklist = append([]pipeline.Item{{
		Step: pipeline.StepFinalBinding, Check: "final_binding", Status: pipeline.StatusMissing,
		Code: code, Detail: detail, Decisive: true,
	}}, undecided(ev.Checklist)...)
	out.Plan.Budgets, out.Plan.Counters = nil, nil
	return &out
}

func undecided(items []pipeline.Item) []pipeline.Item {
	out := make([]pipeline.Item, len(items))
	for i, it := range items {
		it.Decisive = false
		out[i] = it
	}
	return out
}

// monitorView is what a monitor-mode evaluation binds (HR-184): the
// hypothetical decision and its explanation, but no reservation, so
// nothing is reserved, counted or claimed.
func monitorView(ev *pipeline.Evaluation) *pipeline.Evaluation {
	out := *ev
	out.Plan = gdomain.Plan{}
	return &out
}

// bind writes one evaluation. A monitor-mode evaluation whose identity and
// containment passed gets a permit whatever its (hypothetical) decision,
// with nothing reserved, and closes its transaction so no second permit
// can follow (HR-184).
func (a *Authority) bind(ctx context.Context, gw Gateway, ev *pipeline.Evaluation, prev *Stored, rec *recording.Recorder) (Result, error) {
	monitor := ev.MonitorPermit()
	if monitor {
		ev = monitorView(ev)
	}
	w := Write{
		Eval: ev, Prev: prev, Final: Final(ev.Decision) || monitor, Reason: ev.Decisive().Code, GatewayID: gw.ID,
		TransactionID: ids.NewV7(), Evaluation: 1,
	}
	if prev != nil {
		w.TransactionID, w.Evaluation = prev.TransactionID, prev.Evaluations+1
	}
	if Holds(ev) && !ev.Hold.Keep {
		w.HoldRequest = ids.NewV7()
	}
	res := Result{
		Decision: ev.Decision, TransactionID: w.TransactionID, Evaluation: w.Evaluation, ActionHash: ev.ActionHash,
		EffectiveHash: ev.EffectiveHash, BasisDigest: ev.Basis.Digest(), Checklist: ev.Checklist,
		Obligations: ev.Obligations, Reasons: reasons(ev.Checklist), Mode: ev.Mode, Wait: waitOf(ev, w.TransactionID),
	}
	if res.Wait != nil && !w.HoldRequest.IsZero() {
		res.Wait.RequestID = w.HoldRequest
	}
	if ev.Connection != nil {
		res.AccessMode = ev.Connection.AccessMode
	}
	if monitor {
		p, err := a.permit(gw, ev, w.TransactionID)
		if err != nil {
			return Result{}, err
		}
		w.Permit = p
		res.Permit, res.PermitID, res.Epoch = p.JWS, p.ID, p.Epoch
	} else if ev.Permits() {
		rows, err := a.rows(ctx, gw.Org, ev)
		if err != nil {
			return Result{}, err
		}
		w.Rows, w.Lines = rows, lines(ev, rows)
		if ev.DedupeKey != "" {
			w.Claim = &ClaimWrite{Key: ev.DedupeKey, TransactionID: w.TransactionID}
		}
		p, err := a.permit(gw, ev, w.TransactionID)
		if err != nil {
			return Result{}, err
		}
		w.Permit = p
		res.Permit, res.PermitID, res.Epoch = p.JWS, p.ID, p.Epoch
	}
	inputs, err := a.sealInputs(ctx, gw.Org, w.TransactionID, w.Evaluation, rec)
	if err != nil {
		return Result{}, err
	}
	// The receipt Finalize records is the one Sign returned last, so it
	// needs no second lookup.
	w.Sign = func(budgets []BudgetState) (Receipt, error) {
		r, err := a.receipt(gw, ev, w.TransactionID, w.Evaluation, budgets)
		r.Inputs = inputs
		res.Receipt = r.JWS
		return r, err
	}
	if err := a.Store.Finalize(ctx, gw.Org, w); err != nil {
		return Result{}, err
	}
	return res, nil
}

// rows resolves the rows of ev's plan. When the evaluation found every one,
// it reserves on those: a row is never deleted and its ref never changes,
// so they are the rows Prepare would resolve, and Prepare's insert does not
// wait on a hot row's updaters before Finalize does. A row gone anyway
// fails Finalize's conditional update (ErrExhausted), and the next
// evaluation, not finding it, prepares it. A row not found yet (a new
// period or window) is created by Prepare.
func (a *Authority) rows(ctx context.Context, org ids.OrgID, ev *pipeline.Evaluation) ([]Row, error) {
	out := make([]Row, 0, len(ev.Plan.Budgets)+len(ev.Plan.Counters))
	for _, d := range ev.Plan.Budgets {
		id := ev.Rows.Accounts[d.Ref]
		if id.IsZero() {
			return a.Store.Prepare(ctx, org, ev.Plan)
		}
		out = append(out, Row{Ref: d.Ref, Kind: bdomain.KindBudget, ID: id})
	}
	for _, d := range ev.Plan.Counters {
		id := ev.Rows.Counters[d.Ref]
		if id.IsZero() {
			return a.Store.Prepare(ctx, org, ev.Plan)
		}
		out = append(out, Row{Ref: d.Ref, Kind: bdomain.KindCounter, ID: id})
	}
	return out, nil
}

// lines turns a plan into reservation lines on resolved rows.
func lines(ev *pipeline.Evaluation, rows []Row) []bdomain.Line {
	byRef := map[bdomain.Ref]Row{}
	for _, r := range rows {
		byRef[r.Ref] = r
	}
	var out []bdomain.Line
	for _, d := range ev.Plan.Budgets {
		r := byRef[d.Ref]
		out = append(out, bdomain.Line{Kind: bdomain.KindBudget, ID: r.ID, Rank: d.Ref.Owner.Rank, Amount: d.Amount})
	}
	for _, d := range ev.Plan.Counters {
		r := byRef[d.Ref]
		out = append(out, bdomain.Line{Kind: bdomain.KindCounter, ID: r.ID, Rank: d.Ref.Owner.Rank})
	}
	return bdomain.Order(out)
}

// reasons lists the decisive item and every blocking item (PAP-1 §7.1).
func reasons(items []pipeline.Item) []adomain.Reason {
	var out []adomain.Reason
	for _, it := range items {
		if it.Decisive || (it.Status != pipeline.StatusPassed && it.Status != pipeline.StatusNotApplicable &&
			it.Status != pipeline.StatusNotEvaluated && it.Status != pipeline.StatusAnnotated) {
			out = append(out, adomain.Reason{Code: it.Code, Check: it.Check, Detail: it.Detail, Decisive: it.Decisive})
		}
	}
	return out
}

func repeat(s Stored, hash string) Result {
	return Result{
		Decision: s.Decision, TransactionID: s.TransactionID, Evaluation: s.Evaluations, ActionHash: hash, EffectiveHash: hash,
		Receipt: s.Receipt, Repeat: true, Reasons: []adomain.Reason{
			{Code: s.Reason, Check: "stored", Decisive: true},
			{Code: ReasonDuplicateRequest, Check: "idempotency"},
		},
	}
}

// tampered answers a request whose action hash differs from the stored one
// for the same (run, action): DENY ACTION_TAMPERED and a security event
// (HR-006). An OPEN transaction is closed with that denial so the original
// action cannot be resumed.
func (a *Authority) tampered(ctx context.Context, gw Gateway, req pipeline.Request, prev Stored) (Result, error) {
	a.log(ctx).WarnContext(ctx, "security.action_tampered", slog.String("txn_id", prev.TransactionID.String()), slog.String("gateway_id", gw.ID))
	res := Result{
		Decision: adomain.Deny, TransactionID: prev.TransactionID, ActionHash: req.Action.HashHex(), EffectiveHash: req.Action.HashHex(),
		Reasons: []adomain.Reason{{
			Code: adomain.ReasonActionTampered, Check: "identity", Decisive: true,
			Detail: "this run and action id were already used for another action",
		}},
	}
	var receipt *Receipt
	if !prev.Final {
		ev := &pipeline.Evaluation{
			Decision: adomain.Deny, Org: gw.Org, ActionHash: req.Action.HashHex(), EffectiveHash: req.Action.HashHex(),
			Checklist: []pipeline.Item{{
				Step: pipeline.StepFinalBinding, Check: "final_binding", Status: pipeline.StatusFailed,
				Code: adomain.ReasonActionTampered, Detail: res.Reasons[0].Detail, Decisive: true,
			}},
		}
		ev.RunID, _ = ids.ParseUUID(req.Action.Action.RunID)
		ev.ActionID, _ = ids.ParseUUID(req.Action.Action.ActionID)
		r, err := a.receipt(gw, ev, prev.TransactionID, prev.Evaluations+1, nil)
		if err != nil {
			return Result{}, err
		}
		if r.Inputs, err = a.sealTampered(ctx, gw.Org, req, prev, prev.Evaluations+1); err != nil {
			return Result{}, err
		}
		receipt, res.Receipt, res.Evaluation = &r, r.JWS, prev.Evaluations+1
	}
	if err := a.Store.Tamper(ctx, gw.Org, prev, receipt, gw.ID); err != nil && !errors.Is(err, ErrConflict) {
		return Result{}, err
	}
	return res, nil
}

// BeginDispatch is the commit point before the gateway sends anything
// (HR-001, PAP-1 §7.3). Any error means: do not dispatch. It records the
// outbound request the gateway built and, for a target-enforced
// connection, returns the action token minted over its exact body
// (HR-188); a token that cannot be minted leaves the permit unused.
func (a *Authority) BeginDispatch(ctx context.Context, gw Gateway, permit ids.UUID, epoch int64, out Outbound) (string, error) {
	if err := out.check(); err != nil {
		return "", err
	}
	var token string
	err := a.Store.BeginDispatch(ctx, gw.Org, gw.ID, permit, epoch, out, func(d Dispatching) (*ids.UUID, error) {
		tok, jti, err := a.actionToken(d, out)
		token = tok
		return jti, err
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// RecordExecution settles a dispatched permit (step 10) and returns the
// signed execution receipt. Delegated is for cooperative channels only
// (HR-186): the agent performs the allowed action itself.
func (a *Authority) RecordExecution(ctx context.Context, gw Gateway, e Execution) (string, error) {
	if e.Outcome != Accepted && e.Outcome != Failed && e.Outcome != Unknown && e.Outcome != Delegated {
		return "", ErrOutcomeInvalid
	}
	return a.Store.RecordExecution(ctx, gw.Org, gw.ID, e, func(x Executed, now time.Time) (Receipt, error) {
		return a.executionReceipt(gw, e, x, now)
	})
}

// Sweep releases expired permits and marks stale DISPATCHING ones UNKNOWN
// (HR-003). A swept permit leaves the same evidence as an unknown outcome
// its gateway reported: an attempt, a signed execution receipt recorded by
// the sweeper, and an open reconciliation task (HR-192).
func (a *Authority) Sweep(ctx context.Context, org ids.OrgID, staleAfter time.Duration) (int, int, error) {
	return a.Store.Sweep(ctx, org, staleAfter, func(gatewayID string, e Execution, x Executed, now time.Time) (Receipt, error) {
		return a.executionReceipt(Gateway{Org: org, ID: gatewayID}, e, x, now)
	})
}

// Errors of RecordExecution.
var (
	ErrOutcomeInvalid = pcerr.New(pcerr.InvalidArgument, "OUTCOME_INVALID", "unknown outcome")
	// ErrNotCooperative refuses delegated on a channel where the gateway
	// dispatches (HR-186).
	ErrNotCooperative = pcerr.New(pcerr.FailedPrecondition, "OUTCOME_NOT_DELEGABLE",
		"only a cooperative channel (hook, sdk) reports delegated")
)

func (a *Authority) log(context.Context) *slog.Logger {
	if a.Log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return a.Log
}

func (a *Authority) ttl() time.Duration {
	if a.PermitTTL <= 0 {
		return DefaultPermitTTL
	}
	return a.PermitTTL
}
