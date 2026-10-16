// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine_test

import (
	"context"
	"strings"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

const base = `
apiVersion: automations.pantherclaw.dev/v1
kind: Automation
name: refund-tickets
purpose: Refund small tickets from Support.
work_kind: AGENT_WORK
owner: 0192f000-0000-7000-8000-000000000001
review_by: "2026-12-01"
when:
  inbound:
    source: 0192f000-0000-7000-8000-000000000002
    type: ticket.created
    params:
      ticket:
        from: /ticket/id
        type: string
        pattern: "T-[0-9]{1,10}"
authority:
  principal: self
  ceiling:
    agents: [0192f000-0000-7000-8000-000000000003]
    bounds:
      operations: [payments.refund]
    per_grant:
      ttl: 1h
    per_day:
      grants: 5
      runs: 5
do:
  - id: launch
    step: launch_run
    with:
      agent: 0192f000-0000-7000-8000-000000000003
      task_ref: "ticket {{params.ticket}}"
    RETRY
  - id: wait
    step: wait_run
    with:
      step: launch
    timeout: 2h
  - id: effect
    step: wait_effect
    with:
      step: launch
      operation: payments.refund
    timeout: 1h
COMPENSATE
finish_when:
  - step: wait
    condition: RUN_ENDED
  - step: effect
    condition: EFFECT_CONFIRMED
limits:
  deadline: 1d
`

func def(t *testing.T, retry, compensate string) *autodomain.Definition {
	t.Helper()
	doc := strings.Replace(strings.Replace(base, "RETRY", retry, 1), "COMPENSATE", compensate, 1)
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func trigger() autodomain.TriggerRef {
	id := ids.NewV7()
	return autodomain.TriggerRef{
		ID: id, Org: ids.New[ids.Org](), Automation: ids.NewV7(), Version: ids.NewV7(), Kind: autodomain.TriggerInbound,
		Params: map[string]autodomain.Value{"ticket": {Type: autodomain.ParamString, String: "T-42"}}, Root: id,
	}
}

var (
	t0      = time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	evRun   = []reflexdomain.EvidenceRef{{Kind: reflexdomain.EvidenceRun, ID: ids.NewV7()}}
	evTx    = []reflexdomain.EvidenceRef{{Kind: reflexdomain.EvidenceTransaction, ID: ids.NewV7()}}
	done    = autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone}
	changed = autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectChanged,
		Output: map[string]string{"run_id": "r"}}
	ended     = autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone, Refs: evRun}
	confirmed = autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone, Refs: evTx}
	waiting   = autodomain.StepResult{State: autodomain.StepWaiting}
)

func simulate(t *testing.T, d *autodomain.Definition, stubs engine.Stubs) engine.Simulation {
	t.Helper()
	s, err := engine.Simulate(context.Background(), d, trigger(), stubs, clock.NewFake(t0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func states(s engine.Simulation) map[string]autodomain.StepState {
	out := map[string]autodomain.StepState{}
	for _, a := range s.Attempts {
		out[a.StepID] = a.State
	}
	return out
}

// NORMAL: every finish condition met by evidence → SUCCEEDED.
func TestSimulate_NormalSucceedsOnEvidence(t *testing.T) {
	s := simulate(t, def(t, "", ""), engine.Stubs{
		"launch": {changed}, "wait": {waiting, ended}, "effect": {confirmed},
	})
	if s.State != autodomain.ExecSucceeded || s.Reason != "" {
		t.Fatalf("state %s %s, want SUCCEEDED", s.State, s.Reason)
	}
	if got := s.Result.Changed; len(got) != 1 || got[0] != "launch" {
		t.Errorf("changed %v", got)
	}
	if s.Elapsed != engine.PollInterval {
		t.Errorf("elapsed %s, want one poll", s.Elapsed)
	}
}

// HR-282: DONE without evidence never meets a finish condition.
func TestHR282_DoneWithoutEvidenceIsNotSuccess(t *testing.T) {
	s := simulate(t, def(t, "", ""), engine.Stubs{"launch": {changed}, "wait": {done}, "effect": {done}})
	if s.State != autodomain.ExecPartiallyCompleted || s.Reason != engine.ReasonFinishNotMet {
		t.Fatalf("state %s %s, want PARTIALLY_COMPLETED FINISH_NOT_MET", s.State, s.Reason)
	}
	for _, f := range s.Result.Finish {
		if f.Met {
			t.Errorf("finish %s met without evidence", f.Step)
		}
	}
}

// DENIED: the launch is refused → FAILED with the step's reason, nothing
// after it runs.
func TestSimulate_DeniedLaunchFails(t *testing.T) {
	s := simulate(t, def(t, "", ""), engine.Stubs{"launch": {{State: autodomain.StepFailed, Reason: "OUTSIDE_CEILING"}}})
	if s.State != autodomain.ExecFailed || s.Reason != "OUTSIDE_CEILING" {
		t.Fatalf("state %s %s", s.State, s.Reason)
	}
	if st := states(s); len(st) != 1 {
		t.Errorf("steps after the failure ran: %v", st)
	}
}

// TIMEOUT: a wait past its timeout fails with TIMEOUT; the effect of the
// launch is itemized as changed → PARTIALLY_COMPLETED.
func TestSimulate_WaitTimesOut(t *testing.T) {
	s := simulate(t, def(t, "", ""), engine.Stubs{"launch": {changed}, "wait": {waiting}})
	if s.State != autodomain.ExecPartiallyCompleted || s.Reason != engine.ReasonTimeout {
		t.Fatalf("state %s %s", s.State, s.Reason)
	}
	if s.Elapsed != 2*time.Hour {
		t.Errorf("timed out after %s, want 2h", s.Elapsed)
	}
}

// HR-280: an unknown outcome of an irreversible operation stops in
// NEEDS_RECONCILIATION; nothing retries, nothing compensates.
func TestHR280_UnknownIrreversibleNeedsReconciliation(t *testing.T) {
	comp := "if_fails:\n  compensate:\n    - id: undo\n      step: revoke_grant\n      with:\n        scope: EXECUTION\n"
	s := simulate(t, def(t, "", comp), engine.Stubs{
		"launch": {changed}, "wait": {ended},
		"effect": {{State: autodomain.StepUnknown, Effect: autodomain.EffectUnknown,
			Output: map[string]string{engine.OutputIrreversible: "true"}}},
	})
	if s.State != autodomain.ExecNeedsReconciliation {
		t.Fatalf("state %s, want NEEDS_RECONCILIATION", s.State)
	}
	if _, ok := states(s)["undo"]; ok {
		t.Error("compensation ran after an unknown irreversible outcome")
	}
	if len(s.Result.Unknown) != 1 || len(s.Result.Unresolved) == 0 {
		t.Errorf("result %+v", s.Result)
	}
}

// HR-280: a retry-safe kind retries with backoff up to its attempts; the
// step id stays the same.
func TestHR280_RetrySafeKindRetriesWithinAttempts(t *testing.T) {
	retry := "retry:\n      max_attempts: 3\n      backoff:\n        min: 10s\n        max: 1m"
	fail := autodomain.StepResult{State: autodomain.StepFailed, Reason: "USAGE_EXCEEDED"}
	s := simulate(t, def(t, retry, ""), engine.Stubs{"launch": {fail, fail, changed}, "wait": {ended}, "effect": {confirmed}})
	if s.State != autodomain.ExecSucceeded {
		t.Fatalf("state %s %s", s.State, s.Reason)
	}
	n := 0
	for _, a := range s.Attempts {
		if a.StepID == "launch" {
			n++
			if a.Number != n {
				t.Errorf("attempt numbers %d at %d", a.Number, n)
			}
		}
	}
	if n != 3 || s.Elapsed != 30*time.Second+engine.PollInterval*0 {
		t.Errorf("%d launch attempts after %s", n, s.Elapsed)
	}
}

// HR-280: a launch never retries once its run bound.
func TestHR280_LaunchNeverRetriesAfterBind(t *testing.T) {
	retry := "retry:\n      max_attempts: 3"
	bound := autodomain.StepResult{State: autodomain.StepFailed, Reason: "RUN_FAILED",
		Output: map[string]string{engine.OutputRunBound: "true"}, Effect: autodomain.EffectChanged}
	s := simulate(t, def(t, retry, ""), engine.Stubs{"launch": {bound, changed}})
	if n := len(s.Attempts); n != 1 || s.State != autodomain.ExecPartiallyCompleted {
		t.Fatalf("%d attempts, state %s", n, s.State)
	}
}

// Compensation runs after STOP and is reported as compensation, never as
// an undo (HR-282).
func TestHR282_CompensationRunsAfterStop(t *testing.T) {
	comp := "if_fails:\n  compensate:\n    - id: undo\n      step: revoke_grant\n      with:\n        scope: EXECUTION\n"
	s := simulate(t, def(t, "", comp), engine.Stubs{
		"launch": {changed}, "wait": {{State: autodomain.StepFailed, Reason: "RUN_FAILED"}},
		"undo": {{State: autodomain.StepDone, Effect: autodomain.EffectChanged}},
	})
	if s.State != autodomain.ExecPartiallyCompleted || s.Reason != "RUN_FAILED" {
		t.Fatalf("state %s %s", s.State, s.Reason)
	}
	if len(s.Result.Compensated) != 1 || s.Result.Compensated[0] != "undo" {
		t.Errorf("compensated %v", s.Result.Compensated)
	}
}

// Templates render only declared parameters into templatable fields
// (HR-276); a guard that is false skips the step.
func TestSimulate_GuardSkipsAndTemplatesRender(t *testing.T) {
	d := def(t, "when: trigger.params.ticket == 'T-1'", "")
	s := simulate(t, d, engine.Stubs{"wait": {ended}, "effect": {confirmed}})
	if st := states(s)["launch"]; st != autodomain.StepSkipped {
		t.Errorf("launch %s, want SKIPPED", st)
	}
	bad := strings.Replace(base, "ticket {{params.ticket}}", "ticket {{params.nope}}", 1)
	bad = strings.Replace(strings.Replace(bad, "RETRY", "", 1), "COMPENSATE", "", 1)
	d2, err := autodomain.Parse([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	s = simulate(t, d2, nil)
	if s.State != autodomain.ExecFailed || s.Reason != engine.ReasonTemplate {
		t.Errorf("state %s %s, want FAILED TEMPLATE_INVALID", s.State, s.Reason)
	}
}

// The execution deadline bounds every wait.
func TestSimulate_DeadlineFails(t *testing.T) {
	d := def(t, "", "")
	d.Do[1].Timeout = 0
	s := simulate(t, d, engine.Stubs{"launch": {done}, "wait": {waiting}})
	if s.State != autodomain.ExecFailed || s.Reason != autodomain.ReasonDeadline || s.Elapsed != 24*time.Hour {
		t.Fatalf("state %s %s after %s", s.State, s.Reason, s.Elapsed)
	}
}
