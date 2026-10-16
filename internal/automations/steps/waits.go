// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package steps

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// launchOf is the run and launch a wait refers to.
func launchOf(sc autodomain.StepContext, step string) (dbq.GetAutomationLaunchRow, bool, error) {
	o, ok := stepOutput(sc, step)
	if !ok {
		return dbq.GetAutomationLaunchRow{}, false, nil
	}
	id, ok := parseID(o[OutLaunch])
	return dbq.GetAutomationLaunchRow{ID: id}, ok, nil
}

// waitRun waits until a launch_run step's run ends or its launch completes
// (D25). DONE carries the run as evidence (RUN_ENDED).
type waitRun struct{}

func (*waitRun) Kind() string { return autodomain.KindWaitRun }

func (s *waitRun) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.Poll(ctx, tx, sc)
}

func (*waitRun) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, ok := sc.With.(*autodomain.WaitRunWith)
	if !ok {
		return failed(ReasonBadWith)
	}
	l, ok, _ := launchOf(sc, w.Step)
	if !ok {
		return failed(ReasonBadWith)
	}
	launch, err := q(tx).GetAutomationLaunch(ctx, sc.Org, l.ID)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	r, err := q(tx).GetRun(ctx, sc.Org, launch.RunID)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	ended := r.EffectiveState != "ACTIVE"
	if !ended && launch.State != "COMPLETED" {
		return autodomain.StepResult{State: autodomain.StepWaiting, Effect: autodomain.EffectNone,
			WakeAt: sc.Now.Add(engine.PollInterval)}, nil
	}
	c, err := q(tx).RunTransactionCounts(ctx, sc.Org, launch.RunID)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	out := map[string]string{
		"run_state": r.EffectiveState, "transactions": strconv.Itoa(int(c.Total)), "unknown": strconv.Itoa(int(c.Unknown)),
	}
	if launch.Outcome != nil {
		out["launch_outcome"] = *launch.Outcome
	}
	return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone, Output: out,
		Refs: []reflexdomain.EvidenceRef{ref(reflexdomain.EvidenceRun, launch.RunID)}}, nil
}

func (s *waitRun) Preview(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if w, ok := sc.With.(*autodomain.WaitRunWith); ok && upstreamShadowed(sc, w.Step) {
		return shadowed(map[string]string{"shadow": "true"})
	}
	return s.Poll(ctx, tx, sc)
}

// waitEffect waits for confirmed effects of one ceiling operation in a
// launch's run (D25, F500). Enough transactions in the wanted states →
// DONE with them as evidence (EFFECT_CONFIRMED). When the run ended or the
// step timed out: an unknown outcome → UNKNOWN (irreversible operation:
// the execution needs reconciliation, HR-280); no confirmed effect →
// FAILED.
type waitEffect struct{}

func (*waitEffect) Kind() string { return autodomain.KindWaitEffect }

func (s *waitEffect) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.check(ctx, tx, sc, false)
}

func (s *waitEffect) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.check(ctx, tx, sc, false)
}

// Expire implements engine.Expirer: the timeout decides like a run end.
func (s *waitEffect) Expire(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	return s.check(ctx, tx, sc, true)
}

func (s *waitEffect) Preview(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if w, ok := sc.With.(*autodomain.WaitEffectWith); ok && upstreamShadowed(sc, w.Step) {
		return shadowed(map[string]string{"shadow": "true"})
	}
	return s.check(ctx, tx, sc, false)
}

func (*waitEffect) check(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext, timedOut bool) (autodomain.StepResult, error) {
	w, ok := sc.With.(*autodomain.WaitEffectWith)
	if !ok || !ceilingOperation(sc.Def, w.Operation) {
		return failed(ReasonBadWith)
	}
	states := w.States
	if len(states) == 0 {
		states = []string{"CONFIRMED"}
	}
	want := w.Min
	if want == 0 {
		want = 1
	}
	if want < 1 || want > 100 {
		return failed(ReasonBadWith)
	}
	l, ok, _ := launchOf(sc, w.Step)
	if !ok {
		return failed(ReasonBadWith)
	}
	launch, err := q(tx).GetAutomationLaunch(ctx, sc.Org, l.ID)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	qq := q(tx)
	c, err := qq.RunEffectCounts(ctx, dbq.RunEffectCountsParams{
		OrgID: sc.Org, RunID: launch.RunID, Operation: w.Operation, States: states,
	})
	if err != nil {
		return autodomain.StepResult{}, err
	}
	out := map[string]string{
		"matched": strconv.Itoa(int(c.Matched)), "unknown": strconv.Itoa(int(c.Unknown)),
		"none_confirmed": strconv.Itoa(int(c.NoneConfirmed)), "total": strconv.Itoa(int(c.Total)),
	}
	if int(c.Matched) >= want {
		txs, err := qq.RunEffectTransactions(ctx, dbq.RunEffectTransactionsParams{
			OrgID: sc.Org, RunID: launch.RunID, Operation: w.Operation, States: states,
		})
		if err != nil {
			return autodomain.StepResult{}, err
		}
		refs := make([]reflexdomain.EvidenceRef, 0, len(txs))
		for _, id := range txs {
			refs = append(refs, ref(reflexdomain.EvidenceTransaction, id))
		}
		return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone, Output: out, Refs: refs}, nil
	}
	r, err := qq.GetRun(ctx, sc.Org, launch.RunID)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	if !timedOut && (r.EffectiveState == "ACTIVE" || c.Pending > 0) {
		return autodomain.StepResult{State: autodomain.StepWaiting, Effect: autodomain.EffectNone, Output: out,
			WakeAt: sc.Now.Add(engine.PollInterval)}, nil
	}
	if c.Unknown > 0 || c.Pending > 0 {
		irreversible, err := qq.OperationIrreversible(ctx, sc.Org, w.Operation)
		if err != nil {
			return autodomain.StepResult{}, err
		}
		out[engine.OutputIrreversible] = strconv.FormatBool(irreversible)
		return autodomain.StepResult{State: autodomain.StepUnknown, Effect: autodomain.EffectUnknown, Output: out,
			Reason: engine.ReasonEffectUnknown, Refs: []reflexdomain.EvidenceRef{ref(reflexdomain.EvidenceRun, launch.RunID)}}, nil
	}
	reason := ReasonNoEffect
	if timedOut {
		reason = engine.ReasonTimeout
	}
	return autodomain.StepResult{State: autodomain.StepFailed, Effect: autodomain.EffectNone, Output: out, Reason: reason}, nil
}

// ceilingOperation reports whether op is a ceiling operation (D25).
func ceilingOperation(def *autodomain.Definition, op string) bool {
	c := def.Authority.Ceiling
	if c == nil || c.Bounds.Operations == nil || op == "" {
		return false
	}
	return slices.ContainsFunc(*c.Bounds.Operations, func(p string) bool {
		if pre, ok := cutStar(p); ok {
			return len(op) > len(pre) && op[:len(pre)] == pre
		}
		return p == op
	})
}

func cutStar(p string) (string, bool) {
	if len(p) > 0 && p[len(p)-1] == '*' {
		return p[:len(p)-1], true
	}
	return "", false
}

// wait waits a fixed time (D25, ≤ 24h).
type wait struct{}

func (*wait) Kind() string { return autodomain.KindWait }

func (*wait) Run(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	w, ok := sc.With.(*autodomain.WaitWith)
	if !ok || w.Duration <= 0 || w.Duration.D() > 24*time.Hour {
		return failed(ReasonBadWith)
	}
	until := sc.Now.Add(w.Duration.D())
	return autodomain.StepResult{State: autodomain.StepWaiting, Effect: autodomain.EffectNone,
		Output: map[string]string{OutUntil: rfc(until)}, WakeAt: until}, nil
}

func (*wait) Poll(_ context.Context, _ pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	until, ok := parseRFC(own(sc)[OutUntil])
	if !ok {
		return failed(ReasonBadWith)
	}
	if sc.Now.Before(until) {
		return autodomain.StepResult{State: autodomain.StepWaiting, Effect: autodomain.EffectNone, Output: own(sc),
			WakeAt: until}, nil
	}
	return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone, Output: own(sc)}, nil
}

func (s *wait) Preview(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if _, ok := own(sc)[OutUntil]; ok {
		return s.Poll(ctx, tx, sc)
	}
	return s.Run(ctx, tx, sc)
}
