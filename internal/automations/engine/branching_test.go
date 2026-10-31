// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package engine_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../domain/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func parsed(t *testing.T, doc string) *autodomain.Definition {
	t.Helper()
	d, err := autodomain.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ticket(id string) autodomain.TriggerRef {
	tr := trigger()
	tr.Params["ticket"] = autodomain.Value{Type: autodomain.ParamString, String: id}
	return tr
}

func env(e string) autodomain.TriggerRef {
	tr := trigger()
	tr.Params = map[string]autodomain.Value{"env": {Type: autodomain.ParamEnum, String: e}}
	return tr
}

func run(t *testing.T, d *autodomain.Definition, tr autodomain.TriggerRef, stubs engine.Stubs) engine.Simulation {
	t.Helper()
	s, err := engine.Simulate(context.Background(), d, tr, stubs, clock.NewFake(t0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func stepIDs(s engine.Simulation, compensation bool) []string {
	var out []string
	for _, a := range s.Attempts {
		if a.Compensation == compensation {
			out = append(out, a.StepID)
		}
	}
	return out
}

var (
	opened = autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectChanged, Refs: evRun}
	failed = autodomain.StepResult{State: autodomain.StepFailed, Reason: "BOOM", Effect: autodomain.EffectChanged}
)

// TestSwitchRunsTheMatchingPath: the first case that holds, then the
// default; a join merges the paths; each terminal judges its own finish.
//
// Covers: F678
func TestSwitchRunsTheMatchingPath(t *testing.T) {
	d := parsed(t, fixture(t, "v2_route.yaml"))
	for _, tc := range []struct {
		env   string
		steps []string
		path  []string
		state autodomain.ExecutionState
	}{
		{"prod", []string{"approve", "log"}, []string{"route", "approve", "log", "approved"}, autodomain.ExecSucceeded},
		{"staging", []string{"tell", "file"}, []string{"route", "tell", "merge", "file", "filed"}, autodomain.ExecPartiallyCompleted},
		{"dev", []string{"record", "file"}, []string{"route", "record", "merge", "file", "filed"}, autodomain.ExecPartiallyCompleted},
	} {
		t.Run(tc.env, func(t *testing.T) {
			s := run(t, d, env(tc.env), engine.Stubs{"log": {opened}, "file": {opened}})
			if got := stepIDs(s, false); !slices.Equal(got, tc.steps) {
				t.Errorf("steps %v", got)
			}
			if !slices.Equal(s.Path, tc.path) {
				t.Errorf("path %v", s.Path)
			}
			if s.State != tc.state {
				t.Errorf("state %s %s", s.State, s.Reason)
			}
		})
	}
}

// TestTerminalOutcomeCapsTheState: the final state never exceeds what the
// terminal declares or what the evidence shows, and a change is never
// hidden under FAILED (D307).
//
// Covers: F678
func TestTerminalOutcomeCapsTheState(t *testing.T) {
	refund := parsed(t, fixture(t, "v2_refund.yaml"))
	t.Run("declared failed, nothing changed", func(t *testing.T) {
		noChange := autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone, Refs: evRun}
		s := run(t, refund, ticket("T-0"), engine.Stubs{"file": {noChange}})
		if s.State != autodomain.ExecFailed || s.Reason != engine.ReasonTerminalOutcome {
			t.Fatalf("%s %s", s.State, s.Reason)
		}
	})
	t.Run("declared failed, something changed", func(t *testing.T) {
		s := run(t, refund, ticket("T-0"), engine.Stubs{"file": {opened}})
		if s.State != autodomain.ExecPartiallyCompleted || s.Reason != engine.ReasonTerminalOutcome {
			t.Fatalf("%s %s", s.State, s.Reason)
		}
	})
	t.Run("declared succeeded without evidence", func(t *testing.T) {
		s := run(t, refund, ticket("T-7"), nil)
		if s.State != autodomain.ExecFailed || s.Reason != engine.ReasonFinishNotMet {
			t.Fatalf("%s %s", s.State, s.Reason)
		}
	})
	t.Run("declared succeeded with evidence", func(t *testing.T) {
		s := run(t, refund, ticket("T-7"), engine.Stubs{"confirm": {confirmed}})
		if s.State != autodomain.ExecSucceeded {
			t.Fatalf("%s %s", s.State, s.Reason)
		}
	})
}

// TestHR534_OnlyTheTakenPathIsCompensated: the other branch's compensation
// never runs, entries run backwards along the path, and a skipped or
// refused step did nothing to compensate.
//
// Covers: F678
func TestHR534_OnlyTheTakenPathIsCompensated(t *testing.T) {
	doc := fixture(t, "v2_refund.yaml")
	doc = strings.Replace(doc, "    - step: open_case\n", "    - step: open_case\n    - step: notify\n      scopes: [OWNER]\n    - step: contain\n", 1)
	doc = strings.Replace(doc, "    next: confirm\n", "    next: extra\n  - id: extra\n    step: contain\n    with:\n      action: SUSPEND_RUN\n      subject: TRIGGER_RUN\n    next: confirm\n", 1)
	doc = strings.Replace(doc, "    next: filed\n", "    next: tail\n  - id: tail\n    step: open_case\n    with:\n      title: Follow up\n    next: filed\n", 1)
	doc += `    - id: undo-extra
      step: notify
      compensates: extra
      with:
        to: [OWNER]
        message:
          title: Extra undone
    - id: undo-file
      step: notify
      compensates: file
      with:
        to: [OWNER]
        message:
          title: Case undone
`
	d := parsed(t, doc)
	t.Run("the failing branch only, backwards", func(t *testing.T) {
		s := run(t, d, ticket("T-7"), engine.Stubs{"confirm": {failed}})
		if got := stepIDs(s, true); !slices.Equal(got, []string{"undo-extra", "undo"}) {
			t.Fatalf("compensated %v", got)
		}
	})
	t.Run("the other branch", func(t *testing.T) {
		s := run(t, d, ticket("T-0"), engine.Stubs{"tail": {failed}})
		if got := stepIDs(s, true); !slices.Equal(got, []string{"undo-file"}) {
			t.Fatalf("compensated %v", got)
		}
	})
	t.Run("a refused step did nothing", func(t *testing.T) {
		refused := autodomain.StepResult{State: autodomain.StepFailed, Reason: "OUTSIDE_SCOPE", Effect: autodomain.EffectNone}
		s := run(t, d, ticket("T-0"), engine.Stubs{"file": {refused}})
		if got := stepIDs(s, true); len(got) != 0 {
			t.Fatalf("compensated %v", got)
		}
	})
	t.Run("a retried step that changed something and was then refused", func(t *testing.T) {
		changed := autodomain.StepResult{State: autodomain.StepFailed, Effect: autodomain.EffectChanged}
		refused := autodomain.StepResult{State: autodomain.StepFailed, Reason: "OUTSIDE_SCOPE", Effect: autodomain.EffectNone}
		retried := parsed(t, strings.Replace(doc, "    next: tail\n", "    retry:\n      max_attempts: 2\n      backoff:\n        min: 1s\n        max: 1s\n    next: tail\n", 1))
		s := run(t, retried, ticket("T-0"), engine.Stubs{"file": {changed, refused}})
		if got := stepIDs(s, true); !slices.Equal(got, []string{"undo-file"}) {
			t.Fatalf("compensated %v", got)
		}
	})
	t.Run("a skipped step did nothing", func(t *testing.T) {
		guarded := parsed(t, strings.Replace(doc, "    step: contain\n    with:\n      action", "    step: contain\n    when: trigger.params.ticket == \"T-1\"\n    with:\n      action", 1))
		s := run(t, guarded, ticket("T-7"), engine.Stubs{"confirm": {failed}})
		if got := stepIDs(s, true); !slices.Equal(got, []string{"undo"}) {
			t.Fatalf("compensated %v", got)
		}
	})
}

// TestBranchGuardFailsClosed: a guard that cannot be evaluated takes no
// branch; the run stops and compensates what ran, reporting the node.
//
// Covers: F678
func TestBranchGuardFailsClosed(t *testing.T) {
	d := parsed(t, fixture(t, "v2_route.yaml"))
	tr := trigger()
	tr.Params = map[string]autodomain.Value{}
	s := run(t, d, tr, nil)
	if s.State != autodomain.ExecFailed || s.Reason != engine.ReasonGuard {
		t.Fatalf("%s %s", s.State, s.Reason)
	}
	if !slices.Equal(s.Unevaluable, []string{"route"}) || len(s.Attempts) != 0 {
		t.Fatalf("unevaluable %v attempts %v", s.Unevaluable, s.Attempts)
	}
}

// TestHR530_V1RunsByIndex: a v1 definition runs as it did: no node pointer,
// no path, attempts in step order.
//
// Covers: F678
func TestHR530_V1RunsByIndex(t *testing.T) {
	s := simulate(t, def(t, "", ""), engine.Stubs{"launch": {changed}, "wait": {ended}, "effect": {confirmed}})
	if s.State != autodomain.ExecSucceeded || len(s.Path) != 0 {
		t.Fatalf("%s %v", s.State, s.Path)
	}
	if got := stepIDs(s, false); !slices.Equal(got, []string{"launch", "wait", "effect"}) {
		t.Fatalf("steps %v", got)
	}
	for i, a := range s.Attempts {
		if a.Index != i || a.NodeID != a.StepID {
			t.Errorf("attempt %d = %+v", i, a)
		}
	}
}

// TestT231_V2AttemptsNameTheirNodes: every attempt carries its node, entered
// once.
//
// Covers: F678
func TestT231_V2AttemptsNameTheirNodes(t *testing.T) {
	s := run(t, parsed(t, fixture(t, "v2_refund.yaml")), ticket("T-7"), engine.Stubs{"confirm": {confirmed}})
	if len(s.Attempts) != 2 {
		t.Fatalf("attempts %+v", s.Attempts)
	}
	for _, a := range s.Attempts {
		if a.NodeID != a.StepID || a.Visit != 1 {
			t.Errorf("attempt %+v", a)
		}
	}
}
