// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package seed_test

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	connapp "github.com/katocxl/pantherclaw/internal/connections/app"
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
// None contains (D539, D550): leaked-key's and poisoned-mcp-server's alerts
// name a key or a connection; no confirmed incident names a run; and the
// rogue sub-agent alert covers a refused revision, whose grant the caller
// chose, alike with a refused delegation. Each opens a case for a person,
// and all six run on Team.
//
// Containment lives only in two separate containment playbooks (HR-665,
// Business): alerts keep the kind of the event that raised them, and a
// refused delegation and a drift found during a call name their run, so each
// containment playbook pins one event kind that always carries a run,
// requires the run subject, and suspends only that run, on CONFIRMED alerts.

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

// containNames are the containment playbooks (HR-665), each with the event
// kind its trigger pins.
var containNames = map[string]string{
	"pc.playbook.poisoned-mcp-server-contain": "audit.package.transitioned",
	"pc.playbook.rogue-sub-agent-contain":     "audit.grant.delegate_refused",
}

// containing reports a containment playbook (HR-665).
func containing(name string) bool {
	_, ok := containNames[name]
	return ok
}

// responseBooks are the six response playbooks; containBooks the containment ones.
func responseBooks(t *testing.T) []playbook {
	t.Helper()
	return slices.DeleteFunc(playbooks(t), func(p playbook) bool { return containing(p.item.Entry.Name) })
}

func containBooks(t *testing.T) []playbook {
	t.Helper()
	return slices.DeleteFunc(playbooks(t), func(p playbook) bool { return !containing(p.item.Entry.Name) })
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

// TestPlaybooks_TheLibrary: the six playbooks D508 names and, listed apart,
// the two containment playbooks (HR-665), each an automation item a Hub
// install turns into a draft (HR-561).
//
// Covers: F942
func TestPlaybooks_TheLibrary(t *testing.T) {
	var names, contain []string
	for _, p := range playbooks(t) {
		if containing(p.item.Entry.Name) {
			contain = append(contain, p.item.Entry.Name)
		} else {
			names = append(names, p.item.Entry.Name)
		}
		if !p.def.ReviewBy.IsZero() || p.def.Authority.Revocable != nil {
			t.Errorf("%s names a review date or a revocable scope", p.item.Entry.Name)
		}
	}
	if !slices.Equal(names, playbookNames) {
		t.Fatalf("playbooks %v, want %v", names, playbookNames)
	}
	if want := slices.Sorted(maps.Keys(containNames)); !slices.Equal(contain, want) {
		t.Fatalf("containment playbooks %v, want %v", contain, want)
	}
}

// TestHR653_LibraryContainsOnlyInContainmentPlaybooks: no response playbook
// contains or revokes beyond its own execution (HR-653, D539, D550), and a
// library playbook contains only as a containment playbook (HR-665). What
// counts as containing is the automations domain's own answer
// (Definition.Contains, which a v2 graph's step nodes reach through Parse),
// and no step is of a kind the catalog marks as revoking beyond the
// execution. Every response playbook validates on Team and says so, every
// signal-started one opens its case as its first step and says it contains
// nothing, and none names a revocable scope. Every containment playbook
// starts on alert.raised, has exactly one step, SUSPEND_RUN on TRIGGER_RUN,
// fails validation on Team only for the edition and validates on Business,
// and its trigger, through triggers.MatchEvent, matches the alert its
// producer's event raises with the run, and no alert without a run subject
// or of another event kind.
//
// Covers: F943
func TestHR653_LibraryContainsOnlyInContainmentPlaybooks(t *testing.T) {
	graph, err := autodomain.Parse([]byte(containingGraph))
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Contains() {
		t.Fatal("Contains misses a containing node of a v2 graph")
	}
	for _, p := range containBooks(t) {
		checkContainment(t, p)
	}
	if n := len(containBooks(t)); n != len(containNames) {
		t.Fatalf("%d containment playbooks, want %d", n, len(containNames))
	}
	for _, p := range responseBooks(t) {
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

// checkContainment: p starts on alert.raised, has exactly one step,
// SUSPEND_RUN on TRIGGER_RUN, revokes nothing beyond its execution, says it
// needs Business, fails validation on Team only for the edition and
// validates on Business (HR-284, HR-665).
func checkContainment(t *testing.T, p playbook) {
	t.Helper()
	name := p.item.Entry.Name
	if p.def.When.Event == nil || p.def.When.Event.On != "alert.raised" {
		t.Errorf("%s does not start on alert.raised", name)
	}
	if len(p.def.Do) != 1 || p.def.IfFails != nil || len(p.def.Nodes) != 0 || !p.def.Contains() {
		t.Fatalf("%s: steps %+v, want exactly one contain step", name, p.def.Do)
	}
	w, err := p.def.Do[0].DecodeWith()
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := w.(*autodomain.ContainWith); !ok || c.Action != autodomain.ContainSuspendRun || c.Subject != autodomain.SubjectTriggerRun {
		t.Errorf("%s: the step is %+v, want SUSPEND_RUN on TRIGGER_RUN", name, w)
	}
	if revokesBeyond(p.def) || p.def.Authority.Revocable != nil {
		t.Errorf("%s can revoke beyond its execution", name)
	}
	if !strings.Contains(p.item.Entry.Summary, "Needs Business.") {
		t.Errorf("%s: the summary does not say it needs Business", name)
	}
	def := *p.def
	def.ReviewBy = autodomain.NewDate(time.Now().AddDate(0, 0, 30))
	team := autodomain.Validate(context.Background(), &def, automationEnv{now: time.Now()})
	if !slices.ContainsFunc(team, func(f autodomain.Finding) bool {
		return f.Severity == autodomain.SeverityError && f.Code == autodomain.CodeUnsupportedCapability && strings.Contains(f.Message, "business")
	}) {
		t.Errorf("%s validates on Team: %+v", name, team)
	}
	for _, f := range team {
		if f.Severity == autodomain.SeverityError && (f.Code != autodomain.CodeUnsupportedCapability || !strings.Contains(f.Message, "business")) {
			t.Errorf("%s on Team: %s %s: %s", name, f.Code, f.Path, f.Message)
		}
	}
	for _, f := range autodomain.Validate(context.Background(), &def, automationEnv{now: time.Now(), business: true}) {
		if f.Severity == autodomain.SeverityError {
			t.Errorf("%s on Business: %s %s: %s", name, f.Code, f.Path, f.Message)
		}
	}
}

// TestHR665_ContainmentTriggers drives each containment playbook's trigger
// from the audit event the producing code writes, through the detection
// engine's built-in rules and Reflex's own alert entry, to
// triggers.MatchEvent. It matches the alert of its pinned event kind that
// names the run; it does not match that alert without its run subject, nor
// with another event kind, nor the alerts of a refused issue or a periodic
// drift check (no run), nor the other playbook's alert. Every signal the
// pinned event raises is CONFIRMED, and every rule a containment playbook
// names is a built-in rule with a CONFIRMED basis whose `on` lists the
// pinned event kind.
//
// Covers: F943
func TestHR665_ContainmentTriggers(t *testing.T) {
	ctx := context.Background()
	rogue, poisoned := book(t, "pc.playbook.rogue-sub-agent-contain"), book(t, "pc.playbook.poisoned-mcp-server-contain")
	env, err := detengine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := pack.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	builtin := map[string]*rules.Rule{}
	for _, c := range pk.Rules {
		builtin[c.Rule.ID] = c.Rule
	}
	ruleNames := regexp.MustCompile(`"((?:pc|org)\.[A-Za-z0-9_.-]+)"`)
	for _, p := range containBooks(t) {
		kind := containNames[p.item.Entry.Name]
		named := ruleNames.FindAllStringSubmatch(p.def.When.Event.Where, -1)
		if len(named) == 0 {
			t.Errorf("%s names no rule", p.item.Entry.Name)
		}
		for _, m := range named {
			r, ok := builtin[m[1]]
			switch {
			case !ok || !r.Builtin():
				t.Errorf("%s names %s, not a built-in rule", p.item.Entry.Name, m[1])
			case !r.Basis.Confirmed():
				t.Errorf("%s names %s, whose basis %s is not CONFIRMED", p.item.Entry.Name, m[1], r.Basis)
			case !slices.Contains(r.On, kind):
				t.Errorf("%s names %s, which does not raise on %s", p.item.Entry.Name, m[1], kind)
			}
		}
	}
	alert := func(e feed.Event, rule string) feed.Event {
		t.Helper()
		s := one(t, detect(t, e), rule)
		for _, sig := range detect(t, e) {
			if !sig.Basis.Confirmed() {
				t.Errorf("%s on %s raises %s, not CONFIRMED", sig.RuleID, e.Kind, sig.Basis)
			}
		}
		return signalEvent(t, reflexdomain.KindAlert, s)
	}
	delegation := alert(delegateRefused(t), "pc.authority.self_issue")
	drift := alert(driftDuringCall(t, runID), "pc.tools.drift")
	match := func(p playbook, e feed.Event) bool {
		t.Helper()
		if !triggers.Means(p.def.When.Event.On, e, triggers.Facts{}) {
			return false
		}
		ok, err := triggers.MatchEvent(ctx, p.def.When.Event.Where, e)
		if err != nil {
			t.Fatalf("%s: %v", p.item.Entry.Name, err)
		}
		return ok
	}
	withoutRun := func(e feed.Event) feed.Event {
		e.Subjects = slices.DeleteFunc(slices.Clone(e.Subjects), func(s reflexdomain.Subject) bool { return s.Type == reflexdomain.SubjectRun })
		return e
	}
	otherKind := func(e feed.Event, kind string) feed.Event {
		e.Attrs = maps.Clone(e.Attrs)
		e.Attrs["event_kind"] = kind
		return e
	}
	for _, c := range []struct {
		name string
		p    playbook
		e    feed.Event
		want bool
	}{
		{"a refused delegation naming its run", rogue, delegation, true},
		{"a refused delegation without its run", rogue, withoutRun(delegation), false},
		{"a refused delegation's alert with another event kind", rogue, otherKind(delegation, "audit.grant.issue_refused"), false},
		{"a refused issue", rogue, alert(issueRefused(t), "pc.authority.self_issue"), false},
		{"a refused revision of another agent's grant", rogue, alert(reviseRefused(t), "pc.authority.self_issue"), false},
		{"a drift alert", rogue, drift, false},
		{"a drift found during a call", poisoned, drift, true},
		{"a drift without its run", poisoned, withoutRun(drift), false},
		{"a drift alert with another event kind", poisoned, otherKind(drift, "audit.connection.drift_reported"), false},
		{"a drift found by the periodic check", poisoned, alert(driftDuringCall(t, ids.UUID{}), "pc.tools.drift"), false},
		{"a refused delegation's alert", poisoned, delegation, false},
	} {
		if got := match(c.p, c.e); got != c.want {
			t.Errorf("%s: %s matches %v, want %v", c.p.item.Entry.Name, c.name, got, c.want)
		}
		if c.want {
			if _, ok := c.e.Subject(reflexdomain.SubjectRun); !ok {
				t.Errorf("%s: the alert names no run", c.name)
			}
			if c.e.Attrs["event_kind"] != containNames[c.p.item.Entry.Name] {
				t.Errorf("%s: event kind %q", c.name, c.e.Attrs["event_kind"])
			}
		}
	}
	if r, _ := delegation.Subject(reflexdomain.SubjectRun); r != runID.String() {
		t.Errorf("the delegation alert names run %q, want the delegating run %s", r, runID)
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
	connID   = mustUUID("0192f942-0000-7000-8000-0000000009f3")
	instance = mustUUID("0192f942-0000-7000-8000-0000000009e1")
	sa       = evdomain.Actor{Type: "service_account", ID: "0192f942-0000-7000-8000-0000000009e2"}
)

// reviseRefused is a refused revision of a grant the caller chose, here
// another agent's.
func reviseRefused(t *testing.T) feed.Event {
	return produced(t, grantsapp.IssueRefusedEvent(sa, "grant.revise", ids.UUID{}, otherID))
}

func delegateRefused(t *testing.T) feed.Event {
	return produced(t, grantsapp.DelegateRefusedEvent(instance, parentID, agentID, runID))
}

func issueRefused(t *testing.T) feed.Event {
	return produced(t, grantsapp.IssueRefusedEvent(sa, "grant.issue", agentID, ids.UUID{}))
}

func delegated(t *testing.T) feed.Event {
	return produced(t, grantsapp.DelegatedEvent(instance, childID, parentID, 1, runID))
}

// driftDuringCall is the quarantine entry of a drift the server resolved to
// run (zero: a periodic check, or a transaction it has no row of).
func driftDuringCall(t *testing.T, run ids.UUID) feed.Event {
	return produced(t, connapp.DriftQuarantinedEvent(evdomain.Actor{Type: "gateway", ID: instance.String()}, connID,
		"acme/refunds", "1.0.0", "ACTIVE", "get_refund", "sha256:aa", "sha256:bb", "clean", run))
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
