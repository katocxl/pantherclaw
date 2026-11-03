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
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	detengine "github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// The response playbook library (G0 M27 D508, N14): six automations in hub/.
// A contain step acts only on a CONFIRMED alert (D514) and only on a subject
// the trigger carries (D539): rogue-sub-agent revokes the grant a refused
// delegation names, compromised-laptop suspends the run an incident names.
// The case opens first, so it opens on every path.

// confirmedOnly is the start of every library contain step's condition: the
// basis was observed or matched by a rule. The engine also skips a contain step
// whose trigger isn't a CONFIRMED alert; this keeps the playbook's own intent
// readable in the draft. The condition goes on to require the step's subject.
const confirmedOnly = `"basis" in trigger.params && trigger.params.basis in ["OBSERVED", "RULE_MATCH"]`

// subjectParam is the parameter that carries a contain subject, read from the
// trigger's subjects.
var subjectParam = map[string]string{autodomain.SubjectTriggerRun: "run", autodomain.SubjectTriggerGrant: "grant"}

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

func book(t *testing.T, name string) playbook {
	t.Helper()
	for _, p := range playbooks(t) {
		if p.item.Entry.Name == name {
			return p
		}
	}
	t.Fatalf("no playbook %s", name)
	return playbook{}
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
		if !p.def.ReviewBy.IsZero() || p.def.Authority.Revocable != nil {
			t.Errorf("%s names a review date or a revocable scope", p.item.Entry.Name)
		}
	}
	if !slices.Equal(names, playbookNames) {
		t.Fatalf("playbooks %v, want %v", names, playbookNames)
	}
}

// TestHR653_PlaybooksContainOnlyOnConfirmedAlerts: a library contain step
// starts only from a raised alert or an opened incident, never from
// alert.inferred, comes after the case, escalates when it fails, and runs only
// on a confirmed basis and when the trigger carries its subject, read from
// the trigger's subjects. Only rogue-sub-agent and compromised-laptop contain;
// they say they need Business and don't run on Team, and the other four say
// they run on Team.
//
// Covers: F943
func TestHR653_PlaybooksContainOnlyOnConfirmedAlerts(t *testing.T) {
	var containing []string
	for _, p := range playbooks(t) {
		name := p.item.Entry.Name
		steps := containSteps(p.def)
		if len(steps) == 0 {
			if !strings.Contains(p.item.Entry.Summary, "Runs on Team.") {
				t.Errorf("%s: the summary does not say it runs on Team", name)
			}
			continue
		}
		containing = append(containing, name)
		if !strings.Contains(p.item.Entry.Summary, "needs Business; on Team it does not run") {
			t.Errorf("%s: the summary does not say it needs Business and does not run on Team", name)
		}
		if p.def.When.Event == nil {
			t.Fatalf("%s: a contain step without a signal trigger", name)
		}
		if on := p.def.When.Event.On; on != "alert.raised" && on != "incident.opened" {
			t.Errorf("%s: a contain step starts from %s", name, on)
		}
		caseAt := slices.IndexFunc(p.def.Do, func(s autodomain.StepSpec) bool { return s.Step == autodomain.KindOpenCase })
		for _, s := range steps {
			w, err := s.DecodeWith()
			if err != nil {
				t.Fatal(err)
			}
			c := w.(*autodomain.ContainWith)
			param, ok := subjectParam[c.Subject]
			if !ok {
				t.Fatalf("%s/%s: subject %s", name, s.ID, c.Subject)
			}
			if want := confirmedOnly + ` && "` + param + `" in trigger.params`; s.When != want {
				t.Errorf("%s/%s: when %q, want %q", name, s.ID, s.When, want)
			}
			spec, ok := p.def.When.Event.Params[param]
			if !ok || spec.From != "subjects."+param || spec.IsRequired() {
				t.Errorf("%s: parameter %s is %+v, want an optional read of subjects.%s", name, param, spec, param)
			}
			if at := slices.IndexFunc(p.def.Do, func(x autodomain.StepSpec) bool { return x.ID == s.ID }); caseAt < 0 || at < caseAt {
				t.Errorf("%s/%s: the case does not open before the contain step", name, s.ID)
			}
			if s.OnFailure != autodomain.OnFailureEscalate {
				t.Errorf("%s/%s: on_failure %q", name, s.ID, s.OnFailure)
			}
		}
		for _, s := range p.def.Do {
			if s.Step == autodomain.KindRevokeGrant {
				t.Errorf("%s/%s: a library playbook uses revoke_grant", name, s.ID)
			}
		}
		// The validator refuses the same playbook started from an inferred
		// alert (D500).
		inf := *p.def
		ev := *p.def.When.Event
		ev.On = autodomain.EventAlertInferred
		inf.When.Event = &ev
		if !slices.ContainsFunc(autodomain.Validate(context.Background(), &inf, automationEnv{now: time.Now(), business: true}),
			func(f autodomain.Finding) bool { return f.Code == autodomain.CodeContainOnInferred }) {
			t.Errorf("%s: started from %s, no %s", name, autodomain.EventAlertInferred, autodomain.CodeContainOnInferred)
		}
	}
	if want := []string{"pc.playbook.compromised-laptop", "pc.playbook.rogue-sub-agent"}; !slices.Equal(containing, want) {
		t.Errorf("containing playbooks %v, want %v", containing, want)
	}
}

// produced is the feed event of an audit entry exactly as audit.Record writes
// it for ev: the body the ledger holds, read by the feed's own normalizer.
func produced(t *testing.T, name string, actor evdomain.Actor, outcome, reason string, object *[2]string, details map[string]string) feed.Event {
	t.Helper()
	type obj struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	}
	var o *obj
	if object != nil {
		o = &obj{object[0], object[1]}
	}
	body, err := evdomain.CanonicalBody(struct {
		Name       string            `json:"name"`
		Outcome    string            `json:"outcome"`
		ReasonCode string            `json:"reason_code,omitempty"`
		Object     *obj              `json:"object,omitempty"`
		Details    map[string]string `json:"details,omitempty"`
	}{name, outcome, reason, o, details})
	if err != nil {
		t.Fatal(err)
	}
	e, err := feed.Normalize("audit."+name, actor.Type, actor.ID, time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC), body)
	if err != nil {
		t.Fatal(err)
	}
	e.ID, e.Org = ids.NewV7(), ids.New[ids.Org]()
	return e
}

// detect runs every rule of the built-in pack, and extra, on e with the
// engine's own evaluation, and returns the signals that fired.
func detect(t *testing.T, e feed.Event, extra ...*detengine.Compiled) []reflexdomain.Signal {
	t.Helper()
	env, err := detengine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	var out []reflexdomain.Signal
	for _, c := range append(slices.Clone(p.Rules), extra...) {
		res, err := detengine.Evaluate(context.Background(), detengine.NewMemory(), c, e)
		if err != nil {
			t.Fatal(err)
		}
		if res.Fired != nil {
			out = append(out, detengine.Signal(c, e, *res.Fired))
		}
	}
	return out
}

// customIncidentRule stands in for a customer's own rule that opens an
// incident naming a run: none of the built-in rules does.
func customIncidentRule(t *testing.T) *detengine.Compiled {
	t.Helper()
	env, err := detengine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rules.Parse([]byte(customIncidentYAML))
	if err != nil {
		t.Fatal(err)
	}
	c, err := detengine.Compile(env, r, "custom", "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const customIncidentYAML = `id: org.playbooks.delegated_incident
version: "1"
title: Delegation under watch
description: A customer's rule that opens an incident on every delegation, naming the child run.
edition: business
severity: HIGH
attention: INCIDENT
basis: OBSERVED
on: [audit.grant.delegated]
group: run
tests:
  - name: a delegation
    fires: true
    events:
      - kind: audit.grant.delegated
        actor_type: instance
        actor_id: 01930000-0000-7000-8000-0000000000i1
        outcome: success
        subjects: {grant: 01930000-0000-7000-8000-0000000000g2, run: 01930000-0000-7000-8000-0000000000r2}
`

// signalEvent is the feed event Reflex writes for a raised alert (kind
// reflex.alert) or an opened incident (reflex.incident): the signal's
// subjects and basis, as reflexEntry reads them.
func signalEvent(kind string, s reflexdomain.Signal) feed.Event {
	return feed.Event{
		Kind: kind, OccurredAt: s.OccurredAt, Outcome: "OPEN", Subjects: s.Subjects,
		Attrs: map[string]string{
			"id": ids.NewV7().String(), "rule": s.RuleID, "severity": string(s.Severity),
			"attention": string(s.Attention), "basis": string(s.Basis),
		},
	}
}

// eventField reads a parameter source as the trigger service does
// (triggers.eventField): subjects.<type> is the first id of that type,
// attrs.<key> an attribute.
func eventField(e feed.Event) func(string) (string, bool) {
	return func(path string) (string, bool) {
		if typ, ok := strings.CutPrefix(path, "subjects."); ok {
			return e.Subject(reflexdomain.SubjectType(typ))
		}
		if k, ok := strings.CutPrefix(path, "attrs."); ok {
			v, ok := e.Attrs[k]
			return v, ok
		}
		return "", false
	}
}

// simulate starts p from e as the trigger service would (its event, where
// clause and parameters) and runs it on the engine's simulator with every
// effectful step done.
func simulate(t *testing.T, p playbook, e feed.Event) map[string]autodomain.StepState {
	t.Helper()
	ctx := context.Background()
	w := p.def.When.Event
	if !triggers.Means(w.On, e, triggers.Facts{}) {
		t.Fatalf("%s: the event is not %s", p.item.Entry.Name, w.On)
	}
	if ok, err := triggers.MatchEvent(ctx, w.Where, e); err != nil || !ok {
		t.Fatalf("%s: the where clause does not match: %v", p.item.Entry.Name, err)
	}
	vals, err := triggers.ExtractFields(w.Params, eventField(e))
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]string{}
	for k, v := range vals {
		params[k] = v.Text()
	}
	var subjects []string
	for _, s := range e.Subjects {
		subjects = append(subjects, fmt.Sprintf("{type: %s, id: %s}", s.Type, s.ID))
	}
	var ps []string
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range params {
			if !yield(k) {
				return
			}
		}
	}) {
		ps = append(ps, k+": "+params[k])
	}
	raw := fmt.Sprintf(`- name: produced
  kind: CUSTOM
  trigger:
    params: {%s}
    subjects: [%s]
  stubs:
    contain: [{state: DONE, effect: CHANGED, refs: [response_action]}]
    case: [{state: DONE, effect: CHANGED, refs: [case]}]
  expect:
    state: SUCCEEDED
`, strings.Join(ps, ", "), strings.Join(subjects, ", "))
	tests, err := templates.ParseTests(p.item.Entry.Name, p.def, []byte(raw))
	if err != nil {
		t.Fatalf("%s: %v\n%s", p.item.Entry.Name, err, raw)
	}
	clk := clock.NewFake(time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC))
	sim, err := engine.Simulate(ctx, p.def, tests[0].Trigger.Ref(ids.New[ids.Org](), ids.NewV7(), ids.NewV7(), clk.Now()), engine.Stubs(tests[0].Stubs), clk)
	if err != nil {
		t.Fatal(err)
	}
	last := map[string]autodomain.StepState{}
	for _, a := range sim.Attempts {
		last[a.StepID] = a.State
	}
	return last
}

// The audit entries the producing code writes (grants/app delegate.go
// refuseDelegation, service.go refuse and grantEvent, pgauthority
// store.go tampered).
var (
	agentID  = "0192f942-0000-7000-8000-0000000009a1"
	parentID = "0192f942-0000-7000-8000-0000000009b1"
	childID  = "0192f942-0000-7000-8000-0000000009b2"
	runID    = "0192f942-0000-7000-8000-0000000009c1"
	txnID    = "0192f942-0000-7000-8000-0000000009d1"
	instance = evdomain.Actor{Type: "instance", ID: "0192f942-0000-7000-8000-0000000009e1"}
	sa       = evdomain.Actor{Type: "service_account", ID: "0192f942-0000-7000-8000-0000000009e2"}
)

func delegateRefused(t *testing.T) feed.Event {
	return produced(t, "grant.delegate_refused", instance, "denied", "DELEGATION_EXCEEDS_PARENT", &[2]string{"grant", parentID},
		map[string]string{"agent": agentID, "parent": parentID, "attempted": "grant.delegate"})
}

func issueRefused(t *testing.T) feed.Event {
	return produced(t, "grant.issue_refused", sa, "denied", "HUMAN_ONLY", nil,
		map[string]string{"attempted": "grant.issue", "agent": agentID})
}

func delegated(t *testing.T) feed.Event {
	return produced(t, "grant.delegated", instance, "success", "", &[2]string{"grant", childID},
		map[string]string{"parent": parentID, "parent_revision": "1", "child_run": runID})
}

func tampered(t *testing.T) feed.Event {
	return produced(t, "security.action_tampered", evdomain.Actor{Type: "gateway", ID: "gw-1"}, "denied", "ACTION_TAMPERED",
		&[2]string{"transaction", txnID}, nil)
}

// one is the single signal of rule among sigs.
func one(t *testing.T, sigs []reflexdomain.Signal, rule string) reflexdomain.Signal {
	t.Helper()
	for _, s := range sigs {
		if s.RuleID == rule {
			return s
		}
	}
	t.Fatalf("%s did not fire: %+v", rule, sigs)
	return reflexdomain.Signal{}
}

// TestT278_AnUnconfirmedSignalContainsNothing drives each containing playbook
// from the audit entry the producing code writes, through the detection
// engine's own rules, to the trigger's parameters and the engine's simulator.
// A refused delegation names the grant it exceeded, and on a confirmed basis
// that grant is revoked; a refused issue names none, and only the case opens.
// An incident that names a run suspends it; one that names a transaction
// does not. Every basis other than OBSERVED and RULE_MATCH, and none at all,
// contains nothing; the case opens on every path.
//
// Covers: F943
func TestT278_AnUnconfirmedSignalContainsNothing(t *testing.T) {
	rogue, laptop := book(t, "pc.playbook.rogue-sub-agent"), book(t, "pc.playbook.compromised-laptop")
	cases := []struct {
		name, kind string
		p          playbook
		sig        reflexdomain.Signal
		contained  bool
	}{
		{"a refused delegation", reflexdomain.KindAlert, rogue, one(t, detect(t, delegateRefused(t)), "pc.authority.self_issue"), true},
		{"a refused issue", reflexdomain.KindAlert, rogue, one(t, detect(t, issueRefused(t)), "pc.authority.self_issue"), false},
		{"an incident on a run", reflexdomain.KindIncident, laptop, one(t, detect(t, delegated(t), customIncidentRule(t)), "org.playbooks.delegated_incident"), true},
		{"an incident on a transaction", reflexdomain.KindIncident, laptop, one(t, detect(t, tampered(t)), "pc.integrity.action_tampered"), false},
	}
	for _, c := range cases {
		if c.sig.Basis != reflexdomain.BasisObserved {
			t.Fatalf("%s: basis %s", c.name, c.sig.Basis)
		}
		for _, basis := range []reflexdomain.Basis{reflexdomain.BasisObserved, "RULE_MATCH", "INFERRED", "HYPOTHESIS", ""} {
			e := signalEvent(c.kind, c.sig)
			e.Attrs["basis"] = string(basis)
			if basis == "" {
				delete(e.Attrs, "basis")
			}
			last := simulate(t, c.p, e)
			want := autodomain.StepSkipped
			if c.contained && basis.Confirmed() {
				want = autodomain.StepDone
			}
			if last["contain"] != want || last["case"] != autodomain.StepDone {
				t.Errorf("%s on basis %q: contain %s, case %s; want contain %s, case DONE", c.name, basis, last["contain"], last["case"], want)
			}
		}
	}
}
