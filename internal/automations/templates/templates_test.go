// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package templates_test

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// d32 are the templates of D32.
var d32 = []string{
	"approval_routing", "approved_business_workflow", "audit_digest", "bounded_task_launch", "coverage_recovery",
	"grant_lifecycle", "least_privilege_review", "new_agent_intake", "scoped_incident_containment",
}

// variants are parameter changes over each template's example that cover
// its options ("" removes a parameter).
var variants = map[string][]map[string]string{
	"bounded_task_launch": {
		{},
		{"trigger": "schedule", "source": "", "budget_per_run": "", "budget_per_day": ""},
		{"operations": "payments.refund,tickets.update", "confirm_operation": "payments.refund"},
		{"trigger": "schedule", "operations": "payments.*", "confirm_operation": "payments.refund", "timezone": "Europe/Berlin"},
	},
	"approved_business_workflow": {
		{},
		{"gate": "false"},
		{"operation": "tickets.update", "budget_per_run": "", "budget_per_day": ""},
	},
	"grant_lifecycle": {
		{},
		{"trigger": "run.ended"},
		{"trigger": "case.closed"},
		{"hours_left": "24"},
	},
	"approval_routing":       {{}, {"remind_after": "24h", "resolution_timeout": "1h"}},
	"new_agent_intake":       {{}, {"baseline_from": "TEMPLATE", "claim_timeout": "6d"}},
	"coverage_recovery":      {{}, {"assign_to": "OWNER", "min_state": "PARTIAL", "coverage_timeout": "6d"}},
	"least_privilege_review": {{}, {"unused_days": "90", "simulate_days": "30", "cron": "30 6 1 * *"}},
	"scoped_incident_containment": {
		{},
		{"event": "incident.opened", "contain": "REVOKE_GRANT", "contain_at": "HIGH"},
	},
	"audit_digest": {
		{},
		{"trigger": "case.closed", "sections": "decisions,open_items"},
	},
}

// irreversible are the operations the test organization defines as
// irreversible (they also spend money).
var irreversible = []string{"payments.refund"}

type rendered struct {
	name   string
	params map[string]string
	doc    []byte
	def    *autodomain.Definition
	tests  []templates.TestCase
}

// renderAll renders every variant of every template.
func renderAll(t *testing.T) map[string][]rendered {
	t.Helper()
	out := map[string][]rendered{}
	for _, tm := range templates.List() {
		vs, ok := variants[tm.ID]
		if !ok {
			t.Fatalf("no variants for %s", tm.ID)
		}
		for i, v := range vs {
			params := tm.Example()
			for k, x := range v {
				if x == "" {
					delete(params, k)
				} else {
					params[k] = x
				}
			}
			doc, tests, err := templates.Render(tm.ID, params)
			if err != nil {
				t.Fatalf("%s variant %d: %v", tm.ID, i, err)
			}
			def, err := autodomain.Parse(doc)
			if err != nil {
				t.Fatalf("%s variant %d: %v\n%s", tm.ID, i, err, doc)
			}
			identify(def)
			out[tm.ID] = append(out[tm.ID], rendered{name: tm.ID + "/" + string(rune('a'+i)), params: params, doc: doc, def: def, tests: tests})
		}
	}
	return out
}

var owner = autodomain.RefID(ids.NewV7())

// identify supplies what the caller puts on the automation, not the
// template (D68): until core moves name and owner out of the document,
// they are set on the parsed definition.
func identify(d *autodomain.Definition) {
	d.Name, d.Owner = "from-template", owner
}

func TestListHasTheD32Templates(t *testing.T) {
	var got []string
	for _, tm := range templates.List() {
		got = append(got, tm.ID)
		if tm.Title == "" || tm.Summary == "" || len(tm.Params) == 0 {
			t.Errorf("%s: title, summary and params are required", tm.ID)
		}
		g, ok := templates.Get(tm.ID)
		if !ok || g.ID != tm.ID {
			t.Errorf("Get(%s) = %v, %v", tm.ID, g.ID, ok)
		}
		// The returned description is a copy.
		g.Params[0].Name = "changed"
		if again, _ := templates.Get(tm.ID); again.Params[0].Name == "changed" {
			t.Errorf("%s: Get returns the library's own params", tm.ID)
		}
	}
	if !slices.Equal(got, d32) {
		t.Fatalf("templates = %v, want %v", got, d32)
	}
	if _, ok := templates.Get("nope"); ok {
		t.Error("Get(nope) found a template")
	}
	if _, _, err := templates.Render("nope", nil); !errors.Is(err, templates.ErrUnknown) {
		t.Errorf("Render(nope) = %v", err)
	}
}

// TestRenderedDocumentsHaveNoIdentity: name and owner are the caller's
// (D68), never the template's.
func TestRenderedDocumentsHaveNoIdentity(t *testing.T) {
	for id, rs := range renderAll(t) {
		for _, r := range rs {
			def, err := autodomain.Parse(r.doc)
			if err != nil {
				t.Fatal(err)
			}
			if def.Name != "" || !def.Owner.IsZero() {
				t.Errorf("%s: rendered name %q owner %s", id, def.Name, def.Owner)
			}
		}
	}
}

// TestEditionIsTheStepsEdition: a template's edition is the least edition
// its steps need.
func TestEditionIsTheStepsEdition(t *testing.T) {
	for id, rs := range renderAll(t) {
		tm, _ := templates.Get(id)
		for _, r := range rs {
			want := autodomain.EditionTeam
			for _, k := range kinds(r.def) {
				if autodomain.Catalog[k].Edition == autodomain.EditionBusiness {
					want = autodomain.EditionBusiness
				}
			}
			if tm.Edition != want {
				t.Errorf("%s: edition %s, steps need %s", r.name, tm.Edition, want)
			}
		}
	}
}

// TestGuardsAndWhereCompile: step guards compile in the engine's guard
// environment and trigger filters in the triggers' environment.
func TestGuardsAndWhereCompile(t *testing.T) {
	for _, rs := range renderAll(t) {
		for _, r := range rs {
			for _, s := range r.def.Do {
				if s.When != "" {
					if err := engine.CompileGuard(s.When); err != nil {
						t.Errorf("%s step %s: %v", r.name, s.ID, err)
					}
				}
			}
			w := r.def.When
			switch {
			case w.Condition != nil && w.Condition.Where != "":
				if err := triggers.CompileCheck("subject", w.Condition.Where); err != nil {
					t.Errorf("%s: %v", r.name, err)
				}
			case w.Event != nil && w.Event.Where != "":
				if err := triggers.CompileCheck("event", w.Event.Where); err != nil {
					t.Errorf("%s: %v", r.name, err)
				}
			}
		}
	}
}

// TestBaselineTestsPassUnderSimulate runs every baseline test of every
// variant through the engine's pure simulator (D34).
func TestBaselineTestsPassUnderSimulate(t *testing.T) {
	ctx := context.Background()
	org := ids.New[ids.Org]()
	start := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	for _, rs := range renderAll(t) {
		for _, r := range rs {
			automation, version := ids.NewV7(), ids.NewV7()
			for _, tc := range r.tests {
				clk := clock.NewFake(start)
				trig := tc.Trigger.Ref(org, automation, version, clk.Now())
				sim, err := engine.Simulate(ctx, r.def, trig, engine.Stubs(tc.Stubs), clk)
				if err != nil {
					t.Errorf("%s %q: %v", r.name, tc.Name, err)
					continue
				}
				if sim.State != tc.Expect.State || sim.Reason != tc.Expect.Reason {
					t.Errorf("%s %q: %s %q, want %s %q", r.name, tc.Name, sim.State, sim.Reason, tc.Expect.State, tc.Expect.Reason)
				}
				last := map[string]autodomain.StepState{}
				for _, a := range sim.Attempts {
					last[a.StepID] = a.State
				}
				for step, want := range tc.Expect.Steps {
					if last[step] != want {
						t.Errorf("%s %q: step %s %q, want %s", r.name, tc.Name, step, last[step], want)
					}
				}
				if tc.Kind == templates.TestDuplicate {
					again := tc.Trigger.Ref(org, automation, version, clk.Now())
					if k1, k2 := dedupeKey(r.def, trig, start), dedupeKey(r.def, again, start); k1 == "" || k1 != k2 {
						t.Errorf("%s %q: the duplicate's keys %q and %q differ", r.name, tc.Name, k1, k2)
					}
				}
			}
		}
	}
}

// dedupeKey is the key that makes a second submission of the trigger start
// no execution: the declared key, or a schedule occurrence's key.
func dedupeKey(def *autodomain.Definition, t autodomain.TriggerRef, fireAt time.Time) string {
	if def.When.Schedule != nil {
		return triggers.ScheduleKey(t.Automation, fireAt)
	}
	return triggers.DedupeKey(def, t)
}

// TestHR287_BaselineKinds: every rendering ships NORMAL, DENIED, TIMEOUT
// and DUPLICATE tests, plus PARTIAL or UNKNOWN when its ceiling has an
// irreversible operation.
func TestHR287_BaselineKinds(t *testing.T) {
	for _, rs := range renderAll(t) {
		for _, r := range rs {
			have := map[string]bool{}
			for _, tc := range r.tests {
				have[tc.Kind] = true
			}
			for _, k := range []string{templates.TestNormal, templates.TestDenied, templates.TestTimeout, templates.TestDuplicate} {
				if !have[k] {
					t.Errorf("%s: no %s test", r.name, k)
				}
			}
			c := r.def.Authority.Ceiling
			if c != nil && c.Bounds.Operations != nil && slices.ContainsFunc(irreversible, c.Bounds.Operations.Matches) &&
				!have[templates.TestPartial] && !have[templates.TestUnknown] {
				t.Errorf("%s: an irreversible ceiling operation needs a PARTIAL or UNKNOWN test", r.name)
			}
		}
	}
}

func TestRenderRefusesBadParams(t *testing.T) {
	tm, _ := templates.Get("bounded_task_launch")
	base := tm.Example()
	for name, change := range map[string]map[string]string{
		"unknown":          {"flavor": "red"},
		"missing":          {"agent": ""},
		"not a uuid":       {"agent": "alice"},
		"bad date":         {"review_by": "2026-13-45"},
		"bad zone":         {"trigger": "schedule", "timezone": "Mars/Olympus"},
		"bad enum":         {"grant_ttl": "forever"},
		"out of range":     {"runs_per_day": "100000"},
		"too many items":   {"operations": "a.b,a.c,a.d,a.e,a.f,a.g,a.h,a.i,a.j,a.k,a.l"},
		"duplicate items":  {"operations": "a.b,a.b"},
		"requires":         {"budget_per_day": ""},
		"option needs it":  {"source": ""},
		"empty list items": {"operations": "a.b,"},
	} {
		params := maps.Clone(base)
		for k, v := range change {
			params[k] = v
			if v == "" {
				delete(params, k)
			}
		}
		if _, _, err := templates.Render(tm.ID, params); !errors.Is(err, templates.ErrParams) {
			t.Errorf("%s: %v, want ErrParams", name, err)
		}
	}
	// Every problem is listed at once.
	_, _, err := templates.Render(tm.ID, map[string]string{"flavor": "red", "agent": "alice"})
	for _, want := range []string{"flavor: unknown", "agent:", "review_by: missing"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not mention %q", err, want)
		}
	}
}

// TestT126_ParamValuesCannotAddStructureOrTemplates: a value is one scalar
// wherever it lands; YAML or template syntax in it changes nothing else.
func TestT126_ParamValuesCannotAddStructureOrTemplates(t *testing.T) {
	tm, _ := templates.Get("bounded_task_launch")
	baseDoc, _, err := templates.Render(tm.ID, tm.Example())
	if err != nil {
		t.Fatal(err)
	}
	base, _ := autodomain.Parse(baseDoc)
	for _, evil := range []string{
		"x\n  agents: [0192f000-0000-7000-8000-00000000eeee]\ndo: []",
		"x\" \nauthority:\n  principal: user:0192f000-0000-7000-8000-00000000eeee",
		"x: y\n- step: contain",
		"# comment\n&a *a !!binary",
	} {
		params := tm.Example()
		params["purpose"] = evil
		doc, _, err := templates.Render(tm.ID, params)
		if err != nil {
			t.Fatalf("%q: %v", evil, err)
		}
		def, err := autodomain.Parse(doc)
		if err != nil {
			t.Fatalf("%q: %v", evil, err)
		}
		if def.Purpose != evil {
			t.Errorf("purpose = %q, want the value verbatim", def.Purpose)
		}
		def.Purpose = base.Purpose
		d1, _ := def.Digest()
		d2, _ := base.Digest()
		if string(d1) != string(d2) {
			t.Errorf("%q changed more than the purpose:\n%s", evil, doc)
		}
	}
	// Template syntax is refused in any value, also where a pattern would
	// allow it.
	for name, v := range map[string]string{
		"purpose":    "refund {{params.ref}}",
		"event_type": "a}}b",
		"timezone":   "${agent}",
	} {
		params := tm.Example()
		params[name] = v
		if _, _, err := templates.Render(tm.ID, params); !errors.Is(err, templates.ErrParams) {
			t.Errorf("%s=%q: %v, want ErrParams", name, v, err)
		}
	}
}

// TestT126_GrantLifecycleNeverExtends: grant_lifecycle only notifies and
// revokes; it has no ceiling and no step that issues, extends or launches.
func TestT126_GrantLifecycleNeverExtends(t *testing.T) {
	for _, r := range renderAll(t)["grant_lifecycle"] {
		if r.def.Authority.Ceiling != nil {
			t.Errorf("%s: a ceiling", r.name)
		}
		for _, s := range r.def.Do {
			if s.Step != autodomain.KindNotify && s.Step != autodomain.KindRevokeGrant {
				t.Errorf("%s: step %s (%s) is neither notify nor revoke_grant", r.name, s.ID, s.Step)
			}
		}
		if r.def.IfFails != nil {
			t.Errorf("%s: compensation", r.name)
		}
		if !slices.ContainsFunc(r.def.Finish, func(f autodomain.Finish) bool { return f.Condition == autodomain.FinishGrantRevoked }) {
			t.Errorf("%s: does not finish on GRANT_REVOKED", r.name)
		}
	}
	for _, k := range autodomain.Kinds() {
		if strings.Contains(k, "extend") || strings.Contains(k, "renew") || strings.Contains(k, "issue") {
			t.Errorf("the catalog has %s", k)
		}
	}
}

// TestHR284_ContainmentOnlyOnTheTrigger: scoped_incident_containment is
// Business, contains only the triggering run or grant, guards containment
// by its criteria, escalates a failed containment, and opens a case.
func TestHR284_ContainmentOnlyOnTheTrigger(t *testing.T) {
	tm, _ := templates.Get("scoped_incident_containment")
	if tm.Edition != autodomain.EditionBusiness {
		t.Errorf("edition %s", tm.Edition)
	}
	trigger := []string{autodomain.SubjectTriggerRun, autodomain.SubjectTriggerGrant}
	for _, r := range renderAll(t)["scoped_incident_containment"] {
		for _, p := range r.def.Authority.Platform {
			if p.Step != autodomain.KindContain {
				continue
			}
			for _, sc := range p.Scopes {
				if !slices.Contains(trigger, sc) {
					t.Errorf("%s: contain scope %s", r.name, sc)
				}
			}
		}
		var contained, cased bool
		for _, s := range r.def.Do {
			switch s.Step {
			case autodomain.KindContain:
				contained = true
				w, err := s.DecodeWith()
				if err != nil {
					t.Fatal(err)
				}
				if c := w.(*autodomain.ContainWith); !slices.Contains(trigger, c.Subject) {
					t.Errorf("%s: contains %s", r.name, c.Subject)
				}
				if s.When == "" || s.OnFailure != autodomain.OnFailureEscalate {
					t.Errorf("%s: contain is unguarded or does not escalate", r.name)
				}
			case autodomain.KindOpenCase:
				cased = s.When == ""
			}
		}
		if !contained || !cased {
			t.Errorf("%s: contain %v, unconditional case %v", r.name, contained, cased)
		}
	}
	for id, rs := range renderAll(t) {
		if id == "scoped_incident_containment" {
			continue
		}
		for _, r := range rs {
			if slices.Contains(kinds(r.def), autodomain.KindContain) {
				t.Errorf("%s contains", r.name)
			}
		}
	}
}

// TestT126_NoTemplatePublishesOrPromotes: every step is a catalog kind,
// and none publishes, activates, promotes, approves or confirms (HR-279).
func TestT126_NoTemplatePublishesOrPromotes(t *testing.T) {
	for _, rs := range renderAll(t) {
		for _, r := range rs {
			for _, k := range kinds(r.def) {
				if _, ok := autodomain.Catalog[k]; !ok {
					t.Errorf("%s: %s is not a catalog kind", r.name, k)
				}
				for _, word := range strings.Split(k, "_") {
					if slices.Contains([]string{"publish", "activate", "promote", "approve", "confirm"}, word) {
						t.Errorf("%s: step kind %s", r.name, k)
					}
				}
			}
		}
	}
}

// TestHR286_ProposalsStayDrafts: intake and least-privilege templates only
// propose: no launch, no ceiling, and their drafting steps are
// proposal-only kinds.
func TestHR286_ProposalsStayDrafts(t *testing.T) {
	all := renderAll(t)
	for _, id := range []string{"new_agent_intake", "least_privilege_review"} {
		for _, r := range all[id] {
			if r.def.Authority.Ceiling != nil {
				t.Errorf("%s: a ceiling", r.name)
			}
			for _, s := range r.def.Do {
				k := autodomain.Catalog[s.Step]
				if k.Effectful && s.Step != autodomain.KindNotify {
					t.Errorf("%s: step %s (%s) changes something beyond a notice", r.name, s.ID, s.Step)
				}
			}
		}
	}
}

// kinds returns the step kinds of d's steps and compensation.
func kinds(d *autodomain.Definition) []string {
	var out []string
	for _, s := range d.Do {
		out = append(out, s.Step)
	}
	if d.IfFails != nil {
		for _, s := range d.IfFails.Compensate {
			out = append(out, s.Step)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// TestKindAndSource: a template's kind is its rendered work_kind, and its
// source is the shipped YAML with placeholders.
func TestKindAndSource(t *testing.T) {
	for id, rs := range renderAll(t) {
		tm, _ := templates.Get(id)
		for _, r := range rs {
			if string(r.def.WorkKind) != tm.Kind {
				t.Errorf("%s: kind %s, renders %s", r.name, tm.Kind, r.def.WorkKind)
			}
		}
		src, ok := templates.Source(id)
		if !ok || !strings.Contains(string(src), "id: "+id) || !strings.Contains(string(src), "${review_by}") {
			t.Errorf("%s: source %v", id, ok)
		}
		src[0] = 'x'
		if again, _ := templates.Source(id); again[0] == 'x' {
			t.Errorf("%s: Source returns the library's own bytes", id)
		}
	}
	if _, ok := templates.Source("nope"); ok {
		t.Error("Source(nope) found a template")
	}
}
