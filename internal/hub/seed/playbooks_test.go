// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package seed_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// The response playbook library (G0 M27 D508, N14): six automations in hub/
// whose contain steps act only on CONFIRMED alerts, on the trigger's run or
// grant (D514).

// confirmedOnly is the step condition every library contain step carries: the
// basis was observed or matched by a rule. The engine also skips a contain step
// whose trigger isn't a CONFIRMED alert; this keeps the playbook's own intent
// readable in the draft.
const confirmedOnly = `"basis" in trigger.params && trigger.params.basis in ["OBSERVED", "RULE_MATCH"]`

var playbookNames = []string{
	"pc.playbook.compromised-laptop", "pc.playbook.data-flow-hold-escalation", "pc.playbook.leaked-key",
	"pc.playbook.offboarded-owner", "pc.playbook.poisoned-mcp-server", "pc.playbook.rogue-sub-agent",
}

type playbook struct {
	item seed.Item
	def  *autodomain.Definition
}

func playbooks(t *testing.T) []playbook {
	t.Helper()
	var out []playbook
	for _, it := range ofKind(t, domain.KindAutomation) {
		if !strings.HasPrefix(it.Entry.Name, "pc.playbook.") {
			continue
		}
		body, err := it.Item.DecodeBody()
		if err != nil {
			t.Fatal(err)
		}
		def, err := autodomain.Parse([]byte(body.(domain.AutomationBody).Definition))
		if err != nil {
			t.Fatalf("%s: %v", it.Entry.Name, err)
		}
		out = append(out, playbook{it, def})
	}
	return out
}

func containSteps(d *autodomain.Definition) []autodomain.StepSpec {
	all := slices.Clone(d.Do)
	if d.IfFails != nil {
		all = append(all, d.IfFails.Compensate...)
	}
	return slices.DeleteFunc(all, func(s autodomain.StepSpec) bool { return s.Step != autodomain.KindContain })
}

// TestPlaybooks_TheLibrary: the six playbooks D508 names, each an automation
// item a Hub install turns into a draft (HR-561).
//
// Covers: F942
func TestPlaybooks_TheLibrary(t *testing.T) {
	var names []string
	for _, p := range playbooks(t) {
		names = append(names, p.item.Entry.Name)
		if !p.def.ReviewBy.IsZero() {
			t.Errorf("%s names a review date", p.item.Entry.Name)
		}
	}
	if !slices.Equal(names, playbookNames) {
		t.Fatalf("playbooks %v, want %v", names, playbookNames)
	}
}

// TestHR653_PlaybooksContainOnlyOnConfirmedAlerts: a library contain step
// suspends or revokes only the trigger's run or grant, starts only from a
// raised alert or an opened incident, never from alert.inferred, carries the
// confirmed-basis condition, and the playbook revokes nothing beyond its
// execution. A playbook that cannot contain says so in its summary.
//
// Covers: F943
func TestHR653_PlaybooksContainOnlyOnConfirmedAlerts(t *testing.T) {
	containing := 0
	for _, p := range playbooks(t) {
		name := p.item.Entry.Name
		steps := containSteps(p.def)
		if p.def.When.Event == nil && len(steps) > 0 {
			t.Errorf("%s: a contain step without a signal trigger", name)
		}
		for _, s := range steps {
			containing++
			w, err := s.DecodeWith()
			if err != nil {
				t.Fatal(err)
			}
			c := w.(*autodomain.ContainWith)
			if c.Subject != autodomain.SubjectTriggerRun && c.Subject != autodomain.SubjectTriggerGrant {
				t.Errorf("%s/%s: subject %s", name, s.ID, c.Subject)
			}
			if s.When != confirmedOnly {
				t.Errorf("%s/%s: when %q, want %q", name, s.ID, s.When, confirmedOnly)
			}
			if on := p.def.When.Event.On; on != "alert.raised" && on != "incident.opened" {
				t.Errorf("%s: a contain step starts from %s", name, on)
			}
			if !strings.Contains(p.item.Entry.Summary, "contain step needs Business") {
				t.Errorf("%s: the summary does not say the contain step needs Business", name)
			}
		}
		for _, s := range p.def.Do {
			if s.Step == autodomain.KindRevokeGrant {
				t.Errorf("%s/%s: a library playbook revokes grants", name, s.ID)
			}
		}
		// The validator refuses the same playbook started from an inferred
		// alert (D500).
		if len(steps) > 0 {
			inf := *p.def
			ev := *p.def.When.Event
			ev.On = autodomain.EventAlertInferred
			inf.When.Event = &ev
			if !slices.ContainsFunc(autodomain.Validate(context.Background(), &inf, automationEnv{now: time.Now(), business: true}),
				func(f autodomain.Finding) bool { return f.Code == autodomain.CodeContainOnInferred }) {
				t.Errorf("%s: started from %s, no %s", name, autodomain.EventAlertInferred, autodomain.CodeContainOnInferred)
			}
		}
	}
	if containing != 4 {
		t.Errorf("%d contain steps, want 4 (leaked key, poisoned MCP server, compromised laptop, rogue sub-agent)", containing)
	}
}

// TestT278_AnUnconfirmedSignalContainsNothing runs each containing playbook on
// the engine's simulator with every basis: only OBSERVED and RULE_MATCH reach
// the contain step; INFERRED, HYPOTHESIS, an unknown basis and none at all skip
// it, and the case still opens so a person hears of the signal.
//
// Covers: F943
func TestT278_AnUnconfirmedSignalContainsNothing(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for _, p := range playbooks(t) {
		if len(containSteps(p.def)) == 0 {
			continue
		}
		for _, basis := range []string{"OBSERVED", "RULE_MATCH", "INFERRED", "HYPOTHESIS", ""} {
			params := "{signal: 0192f942-0000-7000-8000-0000000009f1}"
			if basis != "" {
				params = "{signal: 0192f942-0000-7000-8000-0000000009f1, basis: " + basis + "}"
			}
			raw := fmt.Sprintf(`- name: basis
  kind: CUSTOM
  trigger:
    params: %s
    subjects: [{type: run, id: 0192f942-0000-7000-8000-0000000009f2}]
  stubs:
    contain: [{state: DONE, effect: CHANGED, refs: [response_action]}]
    case: [{state: DONE, effect: CHANGED, refs: [case]}]
  expect:
    state: SUCCEEDED
`, params)
			tests, err := templates.ParseTests(p.item.Entry.Name, p.def, []byte(raw))
			if err != nil {
				t.Fatalf("%s %q: %v", p.item.Entry.Name, basis, err)
			}
			clk := clock.NewFake(start)
			sim, err := engine.Simulate(ctx, p.def, tests[0].Trigger.Ref(ids.New[ids.Org](), ids.NewV7(), ids.NewV7(), clk.Now()), engine.Stubs(tests[0].Stubs), clk)
			if err != nil {
				t.Fatalf("%s %q: %v", p.item.Entry.Name, basis, err)
			}
			last := map[string]autodomain.StepState{}
			for _, a := range sim.Attempts {
				last[a.StepID] = a.State
			}
			wantContain := autodomain.StepSkipped
			if basis == "OBSERVED" || basis == "RULE_MATCH" {
				wantContain = autodomain.StepDone
			}
			if last["contain"] != wantContain || last["case"] != autodomain.StepDone {
				t.Errorf("%s on basis %q: contain %s, case %s; want contain %s, case DONE", p.item.Entry.Name, basis, last["contain"], last["case"], wantContain)
			}
		}
	}
}
