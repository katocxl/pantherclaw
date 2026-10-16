// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Bounds of the driver (D24).
const (
	// MaxTransitions bounds one Advance; the driver enqueues the rest.
	MaxTransitions = 20
	// PollInterval is how soon a waiting step without its own wake time is
	// polled again.
	PollInterval = 15 * time.Second
	// MaxAttempts bounds retries of one step (HR-280).
	MaxAttempts = 5
)

// Owned-failure kinds the engine raises (D38).
const (
	FailureAuthorityChanged   = "automation.authority_changed"
	FailureLaunchBlocked      = "automation.launch_blocked"
	FailureNeedsReconcile     = "automation.needs_reconciliation"
	FailureStepEscalated      = "automation.step_escalated"
	FailureContainmentFailed  = "automation.containment_failed"
	FailureToolQuarantined    = "automation.tool_quarantined"
	FailureExecutionCancelled = "automation.execution_cancelled" //nolint:misspell // stored value
)

// Hooks are the Machine's ties to the platform. The database driver
// implements them; Simulate uses NopHooks. Every method runs in the
// driver's transaction.
type Hooks interface {
	// Revalidate checks the execution's authority before its first step
	// and before every effectful step of a LIVE execution (HR-273): owner,
	// enabled version, ceiling and its approvers, identity, principal,
	// containment, kill switch, edition. It returns "" when everything
	// holds, else a stable reason (KILL_SWITCH cancels; anything else
	// fails the execution).
	Revalidate(ctx context.Context, tx pgx.Tx, x *Exec) (reason string, err error)
	// Quarantined reports whether a ceiling operation's definition is
	// QUARANTINED or RETIRED (D59), checked before launch_run and at every
	// poll of a waiting step of a LIVE execution.
	Quarantined(ctx context.Context, tx pgx.Tx, x *Exec) (bool, error)
	// Escalate tells the automation's owner (owned failure of kind, D38).
	Escalate(ctx context.Context, tx pgx.Tx, x *Exec, kind, step, reason string) error
	// Cleanup runs at every terminal state of a LIVE execution: still
	// active grants it issued are revoked, its runs ended, pending
	// launches and deliveries canceled (D24). It returns the refs of what
	// it did.
	Cleanup(ctx context.Context, tx pgx.Tx, x *Exec) ([]reflexdomain.EvidenceRef, error)
	// Reconciled reports whether every unknown outcome of an execution in
	// NEEDS_RECONCILIATION is resolved (M7 reconciliation), and whether
	// any resolved as a change.
	Reconciled(ctx context.Context, tx pgx.Tx, x *Exec) (resolved, changed bool, err error)
}

// NopHooks accept everything and do nothing (Simulate, HR-288).
type NopHooks struct{}

// Revalidate implements Hooks.
func (NopHooks) Revalidate(context.Context, pgx.Tx, *Exec) (string, error) { return "", nil }

// Quarantined implements Hooks.
func (NopHooks) Quarantined(context.Context, pgx.Tx, *Exec) (bool, error) { return false, nil }

// Escalate implements Hooks.
func (NopHooks) Escalate(context.Context, pgx.Tx, *Exec, string, string, string) error { return nil }

// Cleanup implements Hooks.
func (NopHooks) Cleanup(context.Context, pgx.Tx, *Exec) ([]reflexdomain.EvidenceRef, error) {
	return nil, nil
}

// Reconciled implements Hooks.
func (NopHooks) Reconciled(context.Context, pgx.Tx, *Exec) (bool, bool, error) {
	return false, false, nil
}

// Expirer is implemented by wait kinds that decide their own result when
// their timeout passes (wait_effect: UNKNOWN, not FAILED). Others fail
// with TIMEOUT.
type Expirer interface {
	Expire(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error)
}

// Machine advances executions.
type Machine struct {
	Steps autoports.StepRegistry
	Hooks Hooks
	Now   func() time.Time
	// Stubbed is set by Simulate: the registry returns the scenario's
	// would-be results, so steps of a TEST execution are not previewed and
	// effectful results are not marked SHADOWED.
	Stubbed bool
	guards  *guards
}

// NewMachine returns a Machine over steps and hooks.
func NewMachine(steps autoports.StepRegistry, hooks Hooks, now func() time.Time) (*Machine, error) {
	g, err := newGuards()
	if err != nil {
		return nil, err
	}
	if hooks == nil {
		hooks = NopHooks{}
	}
	return &Machine{Steps: steps, Hooks: hooks, Now: now, guards: g}, nil
}

// errStop ends an Advance early; the execution is persisted as it is.
var errStop = errors.New("engine: stop")

// Advance works the execution until it waits, ends, or makes
// MaxTransitions transitions. It mutates x; the caller stores it. It
// returns true when the execution should be advanced again at once.
func (m *Machine) Advance(ctx context.Context, tx pgx.Tx, x *Exec) (bool, error) {
	if x.State == autodomain.ExecNeedsReconciliation {
		return false, m.recheck(ctx, tx, x)
	}
	for range MaxTransitions {
		if !x.Active() {
			return false, nil
		}
		err := m.step(ctx, tx, x)
		x.Transitions++
		if errors.Is(err, errStop) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
	return x.Active() && x.State != autodomain.ExecWaiting, nil
}

// step makes one transition.
func (m *Machine) step(ctx context.Context, tx pgx.Tx, x *Exec) error {
	now := m.Now()
	if x.State == autodomain.ExecPending {
		x.State, x.StartedAt = autodomain.ExecRunning, now
		if r, err := m.revalidate(ctx, tx, x); err != nil || r != "" {
			return m.authorityLost(ctx, tx, x, r, err)
		}
		return nil
	}
	if x.CancelReason != "" {
		return m.finish(ctx, tx, x, x.CancelReason, true)
	}
	if !now.Before(x.DeadlineAt) {
		return m.finish(ctx, tx, x, autodomain.ReasonDeadline, false)
	}
	specs := x.steps(x.Compensating)
	if x.Current >= len(specs) {
		if x.Compensating {
			return m.finish(ctx, tx, x, x.Reason, false)
		}
		return m.finish(ctx, tx, x, "", false)
	}
	spec := specs[x.Current]
	last := x.latest(x.Current, x.Compensating)
	switch {
	case last == nil:
		return m.start(ctx, tx, x, spec, 1)
	case !last.Terminal():
		if now.Before(last.WakeAt) {
			return m.wait(x, last.WakeAt)
		}
		return m.poll(ctx, tx, x, spec, last)
	case passed(last.State):
		x.Current++
		x.State = autodomain.ExecRunning
		return nil
	default:
		if at, ok := m.retryAt(x, spec, last); ok {
			if now.Before(at) {
				return m.wait(x, at)
			}
			return m.start(ctx, tx, x, spec, last.Number+1)
		}
		return m.failed(ctx, tx, x, spec, last)
	}
}

// passed reports whether a terminal step state lets the execution go on.
func passed(s autodomain.StepState) bool {
	return s == autodomain.StepDone || s == autodomain.StepSkipped || s == autodomain.StepShadowed
}

func (m *Machine) wait(x *Exec, at time.Time) error {
	x.State = autodomain.ExecWaiting
	x.WakeAt = minTime(at, x.DeadlineAt)
	return errStop
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// revalidate runs the HR-273 checks on LIVE executions.
func (m *Machine) revalidate(ctx context.Context, tx pgx.Tx, x *Exec) (string, error) {
	if x.Mode != autodomain.ModeLive {
		return "", nil
	}
	return m.Hooks.Revalidate(ctx, tx, x)
}

// authorityLost ends an execution whose authority no longer holds: the
// kill switch cancels it, anything else fails it with an owned failure.
func (m *Machine) authorityLost(ctx context.Context, tx pgx.Tx, x *Exec, reason string, err error) error {
	if err != nil {
		return err
	}
	if reason == autodomain.ReasonKillSwitch {
		return m.finish(ctx, tx, x, reason, true)
	}
	if err := m.Hooks.Escalate(ctx, tx, x, FailureAuthorityChanged, "", reason); err != nil {
		return err
	}
	return m.finish(ctx, tx, x, reason, false)
}

// context builds a step's input: the rendered `with`, parameters and
// earlier outputs.
func (m *Machine) context(x *Exec, spec autodomain.StepSpec, index, number int) (autodomain.StepContext, error) {
	outs := x.outputs()
	with, err := render(spec, x.View.Trigger.Params, outs)
	if err != nil {
		return autodomain.StepContext{}, err
	}
	return autodomain.StepContext{
		Org: x.Org, Execution: x.View, Def: x.Def, Spec: spec, With: with, Index: index, Attempt: number,
		Params: x.View.Trigger.Params, Outputs: outs, Mode: x.Mode, Now: m.Now(),
	}, nil
}

// start runs a new attempt of spec.
func (m *Machine) start(ctx context.Context, tx pgx.Tx, x *Exec, spec autodomain.StepSpec, number int) error {
	a := &Attempt{
		ID: ids.NewV7(), Index: x.Current, StepID: spec.ID, Number: number, Kind: spec.Step, Compensation: x.Compensating,
		StartedAt: m.Now(), Effect: autodomain.EffectNone, New: true,
	}
	x.Attempts = append(x.Attempts, a)
	x.State = autodomain.ExecRunning
	kind, known := autodomain.Catalog[spec.Step]
	rt, ok := m.Steps[spec.Step]
	if !known || !ok {
		return m.record(x, a, refused(ReasonUnsupported))
	}
	if spec.When != "" {
		ok, err := m.guards.eval(ctx, spec.When, x.View.Trigger, x.outputs())
		if err != nil {
			return m.record(x, a, refused(ReasonGuard))
		}
		if !ok {
			return m.record(x, a, autodomain.StepResult{State: autodomain.StepSkipped, Effect: autodomain.EffectNone})
		}
	}
	sc, err := m.context(x, spec, x.Current, number)
	if err != nil {
		return m.record(x, a, refused(ReasonTemplate))
	}
	sc.Outputs[spec.ID] = map[string]string{OutputAttempt: a.ID.String()}
	if x.Mode != autodomain.ModeLive && !m.Stubbed {
		res, err := rt.Preview(ctx, tx, sc)
		if err != nil {
			return err
		}
		return m.record(x, a, shadowed(kind, res))
	}
	if x.Mode == autodomain.ModeLive {
		if kind.Effectful {
			if r, err := m.revalidate(ctx, tx, x); err != nil || r != "" {
				if err == nil {
					_ = m.record(x, a, refused(r))
				}
				return m.authorityLost(ctx, tx, x, r, err)
			}
		}
		if spec.Step == autodomain.KindLaunchRun {
			if q, err := m.Hooks.Quarantined(ctx, tx, x); err != nil {
				return err
			} else if q {
				return m.quarantined(ctx, tx, x, a)
			}
		}
	}
	res, err := rt.Run(ctx, tx, sc)
	if err != nil {
		return err
	}
	return m.record(x, a, res)
}

// poll re-checks a waiting attempt, or expires it at its timeout.
func (m *Machine) poll(ctx context.Context, tx pgx.Tx, x *Exec, spec autodomain.StepSpec, a *Attempt) error {
	rt, ok := m.Steps[spec.Step]
	if !ok {
		return m.record(x, a, refused(ReasonUnsupported))
	}
	if x.Mode == autodomain.ModeLive {
		if q, err := m.Hooks.Quarantined(ctx, tx, x); err != nil {
			return err
		} else if q {
			return m.quarantined(ctx, tx, x, a)
		}
	}
	sc, err := m.context(x, spec, a.Index, a.Number)
	if err != nil {
		return m.record(x, a, refused(ReasonTemplate))
	}
	// A waiting step reads what it recorded when it started (its launch,
	// gate or delivery ids) under its own id.
	sc.Outputs[spec.ID] = a.Output
	var res autodomain.StepResult
	if x.Mode != autodomain.ModeLive && !m.Stubbed {
		res, err = rt.Preview(ctx, tx, sc)
		res = shadowed(autodomain.Catalog[spec.Step], res)
	} else {
		res, err = rt.Poll(ctx, tx, sc)
	}
	if err != nil {
		return err
	}
	if res.State == autodomain.StepWaiting || res.State == autodomain.StepRunning {
		if at, ok := timeoutAt(spec, a); ok && !m.Now().Before(at) {
			if e, ok := rt.(Expirer); ok {
				if res, err = e.Expire(ctx, tx, sc); err != nil {
					return err
				}
			} else {
				res = autodomain.StepResult{
					State: autodomain.StepFailed, Reason: ReasonTimeout, Effect: a.Effect,
					Output: res.Output, Refs: res.Refs,
				}
			}
		}
	}
	return m.record(x, a, res)
}

// timeoutAt is when a waiting attempt times out: its declared timeout,
// or none (the step's own deadline and the execution's bound it).
func timeoutAt(spec autodomain.StepSpec, a *Attempt) (time.Time, bool) {
	if spec.Timeout <= 0 {
		return time.Time{}, false
	}
	return a.StartedAt.Add(spec.Timeout.D()), true
}

func (m *Machine) quarantined(ctx context.Context, tx pgx.Tx, x *Exec, a *Attempt) error {
	if err := m.Hooks.Escalate(ctx, tx, x, FailureToolQuarantined, a.StepID, autodomain.ReasonToolQuarantined); err != nil {
		return err
	}
	return m.record(x, a, autodomain.StepResult{
		State: autodomain.StepFailed, Reason: autodomain.ReasonToolQuarantined, Effect: a.Effect, Output: a.Output, Refs: a.Refs,
	})
}

func refused(reason string) autodomain.StepResult {
	return autodomain.StepResult{State: autodomain.StepFailed, Reason: reason, Effect: autodomain.EffectNone}
}

// shadowed records a previewed result (HR-288): an effectful kind is
// SHADOWED with its would-be decision and changes nothing; a failed
// preview stays FAILED (the would-be refusal).
func shadowed(kind autodomain.KindSpec, r autodomain.StepResult) autodomain.StepResult {
	if r.State == autodomain.StepFailed || r.State == autodomain.StepSkipped {
		r.Effect = autodomain.EffectNone
		return r
	}
	if kind.Effectful || r.State == autodomain.StepDone {
		r.State = autodomain.StepShadowed
	}
	r.Effect = autodomain.EffectNone
	return r
}

// record stores a step result on its attempt and moves the execution.
func (m *Machine) record(x *Exec, a *Attempt, r autodomain.StepResult) error {
	if !r.Valid() {
		r = autodomain.StepResult{State: autodomain.StepFailed, Reason: ReasonOutputInvalid, Effect: autodomain.EffectUnknown}
	}
	a.Dirty = true
	a.State, a.Reason = r.State, r.Reason
	if r.Output != nil {
		a.Output = r.Output
	}
	if r.Refs != nil {
		a.Refs = cloneRefs(r.Refs)
	}
	if r.Effect != "" {
		a.Effect = r.Effect
	}
	a.Refused = r.State == autodomain.StepFailed && a.Effect == autodomain.EffectNone && r.Reason != ""
	now := m.Now()
	if r.State == autodomain.StepWaiting || r.State == autodomain.StepRunning {
		a.State = autodomain.StepWaiting
		at := r.WakeAt
		if at.IsZero() || !at.After(now) {
			at = now.Add(PollInterval)
		}
		if spec := x.steps(a.Compensation)[a.Index]; spec.Timeout > 0 {
			if t, _ := timeoutAt(spec, a); t.Before(at) {
				at = t
			}
		}
		a.WakeAt = minTime(at, x.DeadlineAt)
		return m.wait(x, a.WakeAt)
	}
	a.EndedAt, a.WakeAt = now, time.Time{}
	return nil
}

// retryAt is when a failed attempt is tried again, if it may be (HR-280):
// a retry-safe kind that declares retry, attempts left, a launch whose run
// never bound, never an unknown outcome of an irreversible operation, and
// the backoff inside the deadline.
func (m *Machine) retryAt(x *Exec, spec autodomain.StepSpec, a *Attempt) (time.Time, bool) {
	kind := autodomain.Catalog[spec.Step]
	if a.State != autodomain.StepFailed || a.Refused && a.Reason == ReasonUnsupported || spec.Retry == nil || !kind.RetrySafe {
		return time.Time{}, false
	}
	if kind.RetryUntilBind && a.Output[OutputRunBound] == "true" {
		return time.Time{}, false
	}
	if x.Mode != autodomain.ModeLive && !m.Stubbed {
		return time.Time{}, false
	}
	if a.Number >= min(spec.Retry.MaxAttempts, MaxAttempts) {
		return time.Time{}, false
	}
	at := a.EndedAt.Add(backoff(spec.Retry.Backoff, a.Number))
	if !at.Before(x.DeadlineAt) {
		return time.Time{}, false
	}
	return at, true
}

// backoff doubles from min (≥ 10 s) up to max (≤ 1 h).
func backoff(b autodomain.Backoff, attempt int) time.Duration {
	lo, hi := max(b.Min.D(), 10*time.Second), b.Max.D()
	if hi <= 0 || hi > time.Hour {
		hi = time.Hour
	}
	d := lo
	for range attempt - 1 {
		d *= 2
		if d >= hi {
			return hi
		}
	}
	return min(d, hi)
}

// failed applies a finally failed (or unknown) step's on_failure (D27).
func (m *Machine) failed(ctx context.Context, tx pgx.Tx, x *Exec, spec autodomain.StepSpec, a *Attempt) error {
	if a.State == autodomain.StepUnknown && a.Output[OutputIrreversible] == "true" {
		// HR-280: never retried, never compensated, never continued.
		return m.finish(ctx, tx, x, ReasonEffectUnknown, false)
	}
	reason := a.Reason
	if reason == "" || a.State == autodomain.StepUnknown {
		reason = autodomain.ReasonStepFailed
	}
	if x.Compensating {
		// Compensation is best effort: record and go on.
		x.Current++
		return nil
	}
	behavior := spec.OnFailure
	if behavior == "" && x.Def.IfFails != nil {
		behavior = x.Def.IfFails.Default
	}
	switch behavior {
	case autodomain.OnFailureContinue:
		x.Current++
		return nil
	case autodomain.OnFailureEscalate:
		if err := m.Hooks.Escalate(ctx, tx, x, FailureStepEscalated, a.StepID, reason); err != nil {
			return err
		}
	case autodomain.OnFailureStop:
	default:
		if behavior != "" {
			return fmt.Errorf("engine: unknown on_failure %q", behavior)
		}
	}
	if a.Reason == autodomain.ReasonLaunchNotClaimed {
		if err := m.Hooks.Escalate(ctx, tx, x, FailureLaunchBlocked, a.StepID, a.Reason); err != nil {
			return err
		}
	}
	return m.stop(ctx, tx, x, reason)
}

// stop ends the main steps: declared compensation runs next, then the
// final state (D27).
func (m *Machine) stop(ctx context.Context, tx pgx.Tx, x *Exec, reason string) error {
	if !x.Compensating && len(x.steps(true)) > 0 {
		x.Compensating, x.Current, x.Reason = true, 0, reason
		x.State = autodomain.ExecRunning
		return nil
	}
	return m.finish(ctx, tx, x, reason, false)
}

// finish computes the final state (D27, HR-282), cleans up and records
// the result.
func (m *Machine) finish(ctx context.Context, tx pgx.Tx, x *Exec, reason string, canceled bool) error {
	if err := m.settle(ctx, tx, x, cmpOr(reason, ReasonTimeout)); err != nil {
		return err
	}
	res := m.account(x)
	switch {
	case unknownIrreversible(x):
		res.State, res.Reason = autodomain.ExecNeedsReconciliation, cmpOr(reason, ReasonEffectUnknown)
	case finishMet(res.Finish):
		res.State, res.Reason = autodomain.ExecSucceeded, ""
	case len(res.Changed) > 0:
		res.State, res.Reason = autodomain.ExecPartiallyCompleted, cmpOr(reason, ReasonFinishNotMet)
	case canceled:
		res.State, res.Reason = autodomain.ExecCancelled, reason
	default:
		res.State, res.Reason = autodomain.ExecFailed, cmpOr(reason, ReasonFinishNotMet)
	}
	if x.Mode == autodomain.ModeLive {
		refs, err := m.Hooks.Cleanup(ctx, tx, x)
		if err != nil {
			return err
		}
		res.Cleanup = refs
		if res.State == autodomain.ExecNeedsReconciliation {
			if err := m.Hooks.Escalate(ctx, tx, x, FailureNeedsReconcile, "", res.Reason); err != nil {
				return err
			}
		}
	}
	x.State, x.Reason, x.Result, x.WakeAt = res.State, res.Reason, &res, time.Time{}
	if res.State == autodomain.ExecNeedsReconciliation {
		x.WakeAt = m.Now().Add(ReconcileInterval)
	}
	return errStop
}

// ReconcileInterval is how often NEEDS_RECONCILIATION is checked again.
const ReconcileInterval = 5 * time.Minute

// recheck resolves an execution in NEEDS_RECONCILIATION once M7
// reconciliation resolved its unknown outcomes (D27).
func (m *Machine) recheck(ctx context.Context, tx pgx.Tx, x *Exec) error {
	resolved, changed, err := m.Hooks.Reconciled(ctx, tx, x)
	if err != nil {
		return err
	}
	if !resolved {
		x.WakeAt = m.Now().Add(ReconcileInterval)
		return nil
	}
	res := m.account(x)
	switch {
	case finishMet(res.Finish):
		res.State, res.Reason = autodomain.ExecSucceeded, ""
	case changed || len(res.Changed) > 0:
		res.State, res.Reason = autodomain.ExecPartiallyCompleted, x.Reason
	default:
		res.State, res.Reason = autodomain.ExecFailed, x.Reason
	}
	if x.Result != nil {
		res.Cleanup = x.Result.Cleanup
	}
	x.State, x.Reason, x.Result, x.WakeAt = res.State, res.Reason, &res, time.Time{}
	return nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// unknownIrreversible reports a step whose outcome on an irreversible
// operation is unknown (HR-280).
func unknownIrreversible(x *Exec) bool {
	return slices.ContainsFunc(x.Attempts, func(a *Attempt) bool {
		return a.State == autodomain.StepUnknown && a.Output[OutputIrreversible] == "true"
	})
}

// account itemizes the steps and the finish conditions (HR-282).
func (m *Machine) account(x *Exec) Result {
	res := Result{
		Changed: []string{}, Unchanged: []string{}, Unknown: []string{}, Finish: []FinishStatus{},
		Unresolved: []Unresolved{},
	}
	for _, a := range x.Latest() {
		if a.Compensation {
			if a.State == autodomain.StepDone {
				res.Compensated = append(res.Compensated, a.StepID)
			}
		}
		switch x.effectOf(a.Index, a.Compensation) {
		case autodomain.EffectUnknown:
			res.Unknown = append(res.Unknown, a.StepID)
			res.Unresolved = append(res.Unresolved, Unresolved{Step: a.StepID, Kind: "UNKNOWN_OUTCOME", Detail: a.Reason})
		case autodomain.EffectChanged:
			res.Changed = append(res.Changed, a.StepID)
		case autodomain.EffectUnchanged, autodomain.EffectNone:
			res.Unchanged = append(res.Unchanged, a.StepID)
		default:
			res.Unchanged = append(res.Unchanged, a.StepID)
		}
		if a.Kind == autodomain.KindGate && !a.Terminal() {
			res.Unresolved = append(res.Unresolved, Unresolved{Step: a.StepID, Kind: "PENDING_GATE"})
		}
	}
	for _, f := range x.Def.Finish {
		st := FinishStatus{Step: f.Step, Condition: f.Condition}
		for i, s := range x.Def.Do {
			if s.ID != f.Step {
				continue
			}
			if a := x.latest(i, false); a != nil && a.State == autodomain.StepDone && len(a.Refs) > 0 &&
				autodomain.Catalog[s.Step].Satisfies(f.Condition) {
				st.Met, st.Refs = true, cloneRefs(a.Refs)
			}
		}
		res.Finish = append(res.Finish, st)
	}
	return res
}

// finishMet: every finish_when entry holds evidence (at least one entry,
// D2).
func finishMet(fs []FinishStatus) bool {
	return len(fs) > 0 && !slices.ContainsFunc(fs, func(f FinishStatus) bool { return !f.Met })
}

// effectOf is a step's effect across all its attempts, the strongest
// first (HR-282): UNKNOWN, then CHANGED, then UNCHANGED. A retried step
// whose first attempt issued a grant still changed something.
func (x *Exec) effectOf(index int, compensation bool) autodomain.Effect {
	out := autodomain.EffectUnchanged
	for _, a := range x.Attempts {
		if a.Index != index || a.Compensation != compensation {
			continue
		}
		switch {
		case a.Effect == autodomain.EffectUnknown || a.State == autodomain.StepUnknown:
			return autodomain.EffectUnknown
		case a.Effect == autodomain.EffectChanged:
			out = autodomain.EffectChanged
		}
	}
	return out
}

// settle ends every waiting attempt when the execution ends (deadline,
// cancel, kill switch, authority lost). A LIVE attempt is asked for its
// final state first, its Expirer or a last Poll, so an unknown outcome of
// an irreversible operation is never hidden behind a cancel (HR-280); what
// still waits then fails with reason.
func (m *Machine) settle(ctx context.Context, tx pgx.Tx, x *Exec, reason string) error {
	for _, a := range x.Attempts {
		if a.Terminal() {
			continue
		}
		res := autodomain.StepResult{State: autodomain.StepWaiting}
		if x.Mode == autodomain.ModeLive || m.Stubbed {
			specs := x.steps(a.Compensation)
			if rt, ok := m.Steps[a.Kind]; ok && a.Index < len(specs) {
				spec := specs[a.Index]
				if sc, err := m.context(x, spec, a.Index, a.Number); err == nil {
					sc.Outputs[spec.ID] = a.Output
					if e, ok := rt.(Expirer); ok {
						res, err = e.Expire(ctx, tx, sc)
					} else {
						res, err = rt.Poll(ctx, tx, sc)
					}
					if err != nil {
						return err
					}
				}
			}
		}
		if res.State == autodomain.StepWaiting || res.State == autodomain.StepRunning || !res.Valid() {
			res = autodomain.StepResult{
				State: autodomain.StepFailed, Reason: reason, Effect: res.Effect,
				Output: res.Output, Refs: res.Refs,
			}
		}
		a.Dirty = true
		a.State, a.Reason = res.State, cmpOr(res.Reason, reason)
		if res.Output != nil {
			a.Output = res.Output
		}
		if res.Refs != nil {
			a.Refs = cloneRefs(res.Refs)
		}
		if res.Effect != "" {
			a.Effect = res.Effect
		}
		a.EndedAt, a.WakeAt = m.Now(), time.Time{}
	}
	return nil
}
