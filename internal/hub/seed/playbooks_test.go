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

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	detengine "github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// The response playbook library (G0 M27 D508, N14): six automations in hub/.
// None contains (D539, D550): a playbook may contain only a subject its real
// alerts carry, on a confirmed basis, and no real alert does that today.
// Leaked-key's and poisoned-mcp-server's alerts name a key or a connection;
// no confirmed incident names a run; and the rogue sub-agent alert covers a
// refused revision, whose grant the caller chose, alike with a refused
// delegation, with nothing in the trigger to tell them apart. Each opens a
// case for a person, and all six run on Team.

// containingGraph is a v2 definition whose only step node contains: what a
// containing node in a graph playbook looks like to Definition.Contains.
const containingGraph = `apiVersion: automations.pantherclaw.dev/v2
kind: Automation
purpose: A graph that contains.
work_kind: SECURITY_WORK
when:
  event:
    on: alert.raised
authority:
  principal: self
nodes:
  - id: hold
    step: contain
    with: {action: SUSPEND_RUN, subject: TRIGGER_RUN}
    next: done
  - id: done
    outcome: SUCCEEDED
`

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

// TestHR653_NoLibraryPlaybookContains: no library playbook contains or
// revokes beyond its own execution, since no real alert names a subject it
// could act on safely (D539, D550). What counts as containing is the
// automations domain's own answer (Definition.Contains, which a v2 graph's
// step nodes reach through Parse), and no step is of a kind the catalog marks
// as revoking beyond the execution. Every playbook validates on Team and
// says so, every signal-started one opens its case as its first step and says
// it contains nothing, and none names a revocable scope.
//
// Covers: F943
func TestHR653_NoLibraryPlaybookContains(t *testing.T) {
	graph, err := autodomain.Parse([]byte(containingGraph))
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Contains() {
		t.Fatal("Contains misses a containing node of a v2 graph")
	}
	for _, p := range playbooks(t) {
		name := p.item.Entry.Name
		if p.def.Contains() {
			t.Errorf("%s contains", name)
		}
		all := slices.Clone(p.def.Do)
		if p.def.IfFails != nil {
			all = append(all, p.def.IfFails.Compensate...)
		}
		for _, n := range p.def.Nodes {
			if n.Step != "" {
				all = append(all, autodomain.StepSpec{ID: n.ID, Step: n.Step})
			}
		}
		for _, s := range all {
			if autodomain.Catalog[s.Step].ConfirmRevocable {
				t.Errorf("%s/%s: a library playbook uses %s, which can revoke beyond its execution", name, s.ID, s.Step)
			}
		}
		if p.def.Authority.Revocable != nil {
			t.Errorf("%s names a revocable scope", name)
		}
		if !strings.Contains(p.item.Entry.Summary, "Runs on Team.") {
			t.Errorf("%s: the summary does not say it runs on Team", name)
		}
		def := *p.def
		def.ReviewBy = autodomain.NewDate(time.Now().AddDate(0, 0, 30))
		if f := autodomain.Validate(context.Background(), &def, automationEnv{now: time.Now()}); len(f) != 0 {
			t.Errorf("%s does not validate on Team: %+v", name, f)
		}
		if p.def.When.Event == nil || !strings.HasPrefix(p.def.When.Event.On, "alert.") && !strings.HasPrefix(p.def.When.Event.On, "incident.") {
			continue
		}
		if p.def.Do[0].Step != autodomain.KindOpenCase {
			t.Errorf("%s: the first step is %s, not the case", name, p.def.Do[0].Step)
		}
		if !strings.Contains(p.item.Entry.Summary, "contains nothing") {
			t.Errorf("%s: the summary does not say it contains nothing", name)
		}
	}
}

// produced is the feed event of the audit entry audit.Record writes for ev
// (audit.Entry: the kind and body the ledger holds), read by the feed's own
// normalizer. ev comes from the producer's own builder.
func produced(t *testing.T, ev audit.Event) feed.Event {
	t.Helper()
	kind, body, err := audit.Entry(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	e, err := feed.Normalize(kind, ev.Actor.Type, ev.Actor.ID, time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC), body)
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
// incident naming a run: none of the built-in rules does. It declares
// OBSERVED, as an older publication could; the engine raises it as
// INFERRED all the same (D526 P6).
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
// subjects and basis. The ledger body is Reflex's own (the Raiser's alert
// entry, or the incident entry the grouping hook writes), read back the way
// the feed reads every entry.
func signalEvent(t *testing.T, kind string, s reflexdomain.Signal) feed.Event {
	t.Helper()
	var body []byte
	switch kind {
	case reflexdomain.KindAlert:
		body = alerts.EntryBody(s, ids.NewV7(), alerts.StateOpen)
	case reflexdomain.KindIncident:
		var err error
		body, err = reflexapp.IncidentEntryBody(dbq.PcIncident{
			ID: ids.NewV7(), Title: s.Title, Severity: string(s.Severity), State: "OPEN", GroupKey: s.GroupKey,
		}, s.Subjects, s.Basis)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("signalEvent: kind %q", kind)
	}
	e, err := feed.Normalize(kind, alerts.Actor.Type, alerts.Actor.ID, s.OccurredAt, body)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// simulate starts p from e as the trigger service would (its event, where
// clause and parameters) and runs it on the engine's simulator, the case
// opening.
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
	vals, err := triggers.ExtractFields(w.Params, func(p string) (string, bool) { return triggers.EventField(e, p) })
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
// The audit events the producers write, from their own builders (grants/app
// DelegateRefusedEvent, IssueRefusedEvent and DelegatedEvent, pgauthority
// TamperedEvent): a change to a producer changes these.
var (
	agentID  = mustUUID("0192f942-0000-7000-8000-0000000009a1")
	parentID = mustUUID("0192f942-0000-7000-8000-0000000009b1")
	childID  = mustUUID("0192f942-0000-7000-8000-0000000009b2")
	runID    = mustUUID("0192f942-0000-7000-8000-0000000009c1")
	txnID    = mustUUID("0192f942-0000-7000-8000-0000000009d1")
	otherID  = mustUUID("0192f942-0000-7000-8000-0000000009f1") // another agent's grant
	instance = mustUUID("0192f942-0000-7000-8000-0000000009e1")
	sa       = evdomain.Actor{Type: "service_account", ID: "0192f942-0000-7000-8000-0000000009e2"}
)

// reviseRefused is a refused revision of a grant the caller chose, here
// another agent's.
func reviseRefused(t *testing.T) feed.Event {
	return produced(t, grantsapp.IssueRefusedEvent(sa, "grant.revise", ids.UUID{}, otherID))
}

func delegateRefused(t *testing.T) feed.Event {
	return produced(t, grantsapp.DelegateRefusedEvent(instance, parentID, agentID))
}

func issueRefused(t *testing.T) feed.Event {
	return produced(t, grantsapp.IssueRefusedEvent(sa, "grant.issue", agentID, ids.UUID{}))
}

func delegated(t *testing.T) feed.Event {
	return produced(t, grantsapp.DelegatedEvent(instance, childID, parentID, 1, runID))
}

func tampered(t *testing.T) feed.Event {
	return produced(t, pgauthority.TamperedEvent("gw-1", txnID, false))
}

func mustUUID(s string) ids.UUID {
	u, err := ids.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
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

// TestT278_NoSignalContainsAnything drives each signal playbook from the
// audit entry the producing code writes, through the detection engine's own
// rules, to the trigger's parameters and the engine's simulator, on every
// basis the producer can raise and every weaker one. A refused delegation, a
// refused issue and a refused revision of another agent's grant all raise
// pc.authority.self_issue, which the trigger can't tell apart, so
// rogue-sub-agent revokes none of them; a confirmed incident naming a
// transaction and a customer's incident naming a run (raised INFERRED, D526
// P6) suspend nothing. Only the case opens, on every path (D550).
//
// Covers: F943
func TestT278_NoSignalContainsAnything(t *testing.T) {
	rogue, laptop := book(t, "pc.playbook.rogue-sub-agent"), book(t, "pc.playbook.compromised-laptop")
	cases := []struct {
		name, kind string
		p          playbook
		sig        reflexdomain.Signal
		basis      reflexdomain.Basis // what the engine raised
	}{
		{"a refused delegation", reflexdomain.KindAlert, rogue, one(t, detect(t, delegateRefused(t)), "pc.authority.self_issue"), reflexdomain.BasisObserved},
		{"a refused issue", reflexdomain.KindAlert, rogue, one(t, detect(t, issueRefused(t)), "pc.authority.self_issue"), reflexdomain.BasisObserved},
		{"a refused revision of another agent's grant", reflexdomain.KindAlert, rogue, one(t, detect(t, reviseRefused(t)), "pc.authority.self_issue"), reflexdomain.BasisObserved},
		{"a customer's incident on a run", reflexdomain.KindIncident, laptop, one(t, detect(t, delegated(t), customIncidentRule(t)), "org.playbooks.delegated_incident"), reflexdomain.BasisInferred},
		{"an incident on a transaction", reflexdomain.KindIncident, laptop, one(t, detect(t, tampered(t)), "pc.integrity.action_tampered"), reflexdomain.BasisObserved},
	}
	for _, c := range cases {
		if c.sig.Basis != c.basis {
			t.Fatalf("%s: basis %s, want %s", c.name, c.sig.Basis, c.basis)
		}
		if c.name == "a refused revision of another agent's grant" {
			if g, ok := signalEvent(t, c.kind, c.sig).Subject(reflexdomain.SubjectGrant); !ok || g != otherID.String() {
				t.Fatalf("%s: the alert names grant %q, want the other agent's %s", c.name, g, otherID)
			}
		}
		for _, basis := range []reflexdomain.Basis{reflexdomain.BasisObserved, "RULE_MATCH", "INFERRED", "HYPOTHESIS", ""} {
			if basis.Confirmed() && !c.basis.Confirmed() {
				continue // no producer raises this signal confirmed
			}
			e := signalEvent(t, c.kind, c.sig)
			e.Attrs["basis"] = string(basis)
			if basis == "" {
				delete(e.Attrs, "basis")
			}
			last := simulate(t, c.p, e)
			if last["case"] != autodomain.StepDone || len(last) != 1 {
				t.Errorf("%s on basis %q: steps %v, want only the case, DONE", c.name, basis, last)
			}
		}
	}
}
