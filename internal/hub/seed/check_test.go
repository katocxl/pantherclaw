// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package seed_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	dengine "github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/rules"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polapp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
	pcpostgres "github.com/katocxl/pantherclaw/packages/pc-postgres"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
	pcslack "github.com/katocxl/pantherclaw/packages/pc-slack"
	pcstripe "github.com/katocxl/pantherclaw/packages/pc-stripe"
)

// The real validators over the seed (G0 M23 D112): `task hub:check` runs these
// tests. A seed item passes what the same content passes in the product: the
// policy publish gate with its mutation check, the detection compiler and the
// rule's own tests, the range format with the customer limits, and automation
// validation and simulation.

func items(t *testing.T) []seed.Item {
	t.Helper()
	out, err := seed.Load(os.DirFS(hubRoot))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const hubRoot = "../../../hub"

func ofKind(t *testing.T, k domain.Kind) []seed.Item {
	t.Helper()
	all := items(t)
	return slices.DeleteFunc(all, func(it seed.Item) bool { return it.Entry.Kind != k })
}

// TestHubSeed_Counts: the seed D112 names.
//
// Covers: F849
func TestHubSeed_Counts(t *testing.T) {
	count := map[domain.Kind]int{}
	for _, it := range items(t) {
		count[it.Entry.Kind]++
	}
	want := map[domain.Kind]int{domain.KindPolicyTemplate: 6, domain.KindDetectionRule: 8, domain.KindRangeScenario: 5, domain.KindAutomation: 3}
	if !maps.Equal(count, want) {
		t.Fatalf("seed %v, want %v", count, want)
	}
	var names []string
	for _, it := range ofKind(t, domain.KindPolicyTemplate) {
		names = append(names, it.Entry.Name)
	}
	if want := []string{
		"pc.coding.deploy-needs-approval", "pc.coding.merge-needs-review", "pc.coding.no-secrets-outbound", "pc.coding.read-only-agent",
		"pc.data.pii-read-then-disclose", "pc.support.refund-limit",
	}; !slices.Equal(names, want) {
		t.Fatalf("policy templates %v, want %v", names, want)
	}
}

// TestHubSeed_IndexEntries: every item is an entry an index may list, with a
// size of its own bytes. The index check is the one a signed index gets.
//
// Covers: F840, F849
func TestHubSeed_IndexEntries(t *testing.T) {
	x := domain.Index{Spec: domain.IndexSpec, Version: 1, IssuedAt: "2026-10-31T00:00:00Z", ExpiresAt: "2026-12-31T00:00:00Z"}
	for _, it := range items(t) {
		x.Items = append(x.Items, it.Entry)
		if int64(len(it.Raw)) != it.Entry.Size {
			t.Errorf("%s: size %d, %d bytes", it.Entry.Name, it.Entry.Size, len(it.Raw))
		}
		if !bytes.Contains(it.Raw, []byte(domain.ItemSpec)) {
			t.Errorf("%s: no spec", it.Entry.Name)
		}
		if it.Entry.Summary == "" {
			t.Errorf("%s: no summary", it.Entry.Name)
		}
	}
	if _, err := x.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestHubSeed_LoadRefuses: the loader refuses what must not reach an index.
//
// Covers: F848
func TestHubSeed_LoadRefuses(t *testing.T) {
	const good = "name: pc.a.b\nversion: 1.0.0\nkind: detection_rule\ntitle: T\nsummary: S\nbody:\n  content: x\n"
	test := &fstest.MapFile{Data: []byte("tests: []\n")}
	base := func() fstest.MapFS {
		return fstest.MapFS{"items/detection_rule/a/item.yaml": {Data: []byte(good)}, "items/detection_rule/a/tests/events.yaml": test}
	}
	if got, err := seed.Load(base()); err != nil || len(got) != 1 {
		t.Fatalf("a good item: %v %v", got, err)
	}
	cases := map[string]func(fstest.MapFS){
		"no tests": func(m fstest.MapFS) { delete(m, "items/detection_rule/a/tests/events.yaml") },
		"unknown member": func(m fstest.MapFS) {
			m["items/detection_rule/a/item.yaml"] = &fstest.MapFile{Data: []byte(good + "script: x\n")}
		},
		"unknown member in the body": func(m fstest.MapFS) {
			m["items/detection_rule/a/item.yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(good, "content: x", "content: x\n  run: y", 1))}
		},
		"another kind's directory": func(m fstest.MapFS) {
			m["items/automation/a/item.yaml"] = &fstest.MapFile{Data: []byte(good)}
			m["items/automation/a/tests/x"] = test
		},
		"not a kind": func(m fstest.MapFS) {
			m["items/scripts/a/item.yaml"] = &fstest.MapFile{Data: []byte(good)}
		},
		"name repeated": func(m fstest.MapFS) {
			m["items/detection_rule/b/item.yaml"] = &fstest.MapFile{Data: []byte(good)}
			m["items/detection_rule/b/tests/x"] = test
		},
		"a bad name": func(m fstest.MapFS) {
			m["items/detection_rule/a/item.yaml"] = &fstest.MapFile{Data: []byte(strings.Replace(good, "pc.a.b", "Other.a", 1))}
		},
	}
	for name, change := range cases {
		m := base()
		change(m)
		if _, err := seed.Load(m); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// world is the read side of the policy gate: the packages an item names.
type world struct {
	ds   []*defs.Definition
	pkgs []*defs.Package
}

func (w world) ActivePackages(context.Context, ids.OrgID) ([]*defs.Package, error) {
	return w.pkgs, nil
}

func (w world) ActiveDefinitions(context.Context, ids.OrgID) ([]*defs.Definition, error) {
	return w.ds, nil
}

func (world) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return map[string]fdomain.Type{
		"github.pull.head": fdomain.TypeObject, "github.pull.people": fdomain.TypeObject, "github.pull.reviews": fdomain.TypeObject,
		"github.pull.checks": fdomain.TypeObject, "github.branch.rules": fdomain.TypeObject, "github.repo.deploy_triggers": fdomain.TypeObject,
		"github.branch.deploy_triggers": fdomain.TypeObject, "stripe.payment.refundable": fdomain.TypeObject, "slack.channel.external": fdomain.TypeObject,
	}, nil
}

var packages = map[string][]byte{
	"mock-payments": mockpayments.Package, "pc-github": pcgithub.Package, "pc-postgres": pcpostgres.Package, "pc-shell": pcshell.Package,
	"pc-slack": pcslack.Package, "pc-stripe": pcstripe.Package,
}

func worldOf(t *testing.T, names []string) world {
	t.Helper()
	var w world
	for _, n := range names {
		raw, ok := packages[n]
		if !ok {
			t.Fatalf("package %q", n)
		}
		p, err := manifest.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		w.pkgs = append(w.pkgs, p)
		for i := range p.Definitions {
			w.ds = append(w.ds, &p.Definitions[i])
		}
	}
	return w
}

// policyValues is a policy template's tests/values.yaml.
type policyValues struct {
	Repos       []string `json:"repos,omitzero"`
	Agent       string   `json:"agent,omitzero"`
	Environment string   `json:"environment,omitzero"`
	Packages    []string `json:"packages"`
}

// TestHubSeed_PolicyTemplatesPassTheGate: each template, rendered with the
// product renderer, passes the publish gate's runner: every scenario test
// decided by the real pipeline as it expects, every mutant killed.
//
// Covers: F849
func TestHubSeed_PolicyTemplatesPassTheGate(t *testing.T) {
	org := ids.MustParse[ids.Org]("01890000-0000-7000-8000-000000000001")
	for _, it := range ofKind(t, domain.KindPolicyTemplate) {
		t.Run(it.Entry.Name, func(t *testing.T) {
			body, err := it.Item.DecodeBody()
			if err != nil {
				t.Fatal(err)
			}
			b := body.(domain.PolicyTemplateBody)
			if len(b.Tests) == 0 {
				t.Fatal("a policy template carries its tests")
			}
			doc, err := rtdomain.ToJSON(it.Tests["values.yaml"])
			if err != nil {
				t.Fatal(err)
			}
			var v policyValues
			if err := json.Unmarshal(doc, &v, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			spec := map[string]render.Spec{}
			for k, p := range b.Placeholders {
				spec[k] = render.Spec{Kind: p.Kind, Pattern: p.Pattern}
			}
			o := render.Options{Name: it.Entry.Name, Repos: v.Repos, Agent: v.Agent, Environment: v.Environment, Defaults: map[string]string{}}
			for _, r := range v.Repos {
				o.Defaults[r] = "main"
			}
			data, err := render.RenderItems(o, spec, b.Rules, b.Tests)
			if err != nil {
				t.Fatal(err)
			}
			if len(data.Skipped) != 0 {
				t.Fatalf("rules left out: %v", data.Skipped)
			}
			raw, err := json.Marshal(map[string]any{"id": "org-policy", "version": 1, "rules": data.Rules, "tests": data.Tests})
			if err != nil {
				t.Fatal(err)
			}
			var bundle pdomain.Bundle
			if err := json.Unmarshal(raw, &bundle, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			w := worldOf(t, v.Packages)
			res, err := scenario.New(w, w, celenv.DefaultLimits, polapp.DefaultBudget).Run(context.Background(), org, &bundle)
			if err != nil {
				t.Fatal(err)
			}
			if res.Error == scenario.ErrBundleInvalid {
				_, err := (&polapp.Engine{Limits: celenv.DefaultLimits}).Compile(&bundle, w.ds)
				t.Fatalf("the rules do not compile: %v", err)
			}
			for _, c := range res.Cases {
				if !c.Passed {
					t.Errorf("case %s: %s", c.ID, c.Detail)
				}
			}
			for _, m := range res.Surviving {
				t.Errorf("mutant survives: %s %s", m.Rule, m.Mutation)
			}
			for _, m := range res.Uncompilable {
				t.Errorf("mutant does not compile: %s %s", m.Rule, m.Mutation)
			}
			if !res.Passed || res.Error != "" {
				t.Errorf("gate: passed %v, error %q, %d mutants", res.Passed, res.Error, res.Mutants)
			}
			t.Logf("%d cases, %d mutants", len(res.Cases), res.Mutants)
		})
	}
}

// TestHubSeed_DetectionRulesAreAlertOnly: each rule is a custom rule, alert
// only, compiles, has a firing and a quiet test, and passes them, and the
// cases in its tests/ directory, on the engine (HR-241).
//
// Covers: F849
func TestHubSeed_DetectionRulesAreAlertOnly(t *testing.T) {
	env, err := dengine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range ofKind(t, domain.KindDetectionRule) {
		t.Run(it.Entry.Name, func(t *testing.T) {
			body, err := it.Item.DecodeBody()
			if err != nil {
				t.Fatal(err)
			}
			content := body.(domain.DetectionRuleBody).Content
			r, err := rules.Parse([]byte(content))
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case r.Builtin():
				t.Error("a Hub rule is a custom rule: its id starts with org.")
			case r.Attention != reflexdomain.AttentionAlert:
				t.Errorf("attention %s: a Hub rule is alert-only", r.Attention)
			case !r.HasFiringAndQuiet():
				t.Error("a rule needs a firing and a quiet test to publish")
			}
			c, err := dengine.Compile(env, r, rules.Digest([]byte(content)), "")
			if err != nil {
				t.Fatal(err)
			}
			if res := dengine.RunTests(context.Background(), c); !dengine.AllPass(res) {
				t.Errorf("the rule's tests: %+v", res)
			}
			doc, err := rtdomain.ToJSON(it.Tests["events.yaml"])
			if err != nil {
				t.Fatal(err)
			}
			var more struct {
				Tests []rules.Test `json:"tests"`
			}
			if err := json.Unmarshal(doc, &more, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			if len(more.Tests) == 0 {
				t.Fatal("no cases in tests/events.yaml")
			}
			r.Tests = more.Tests
			if err := r.Validate(); err != nil {
				t.Fatal(err)
			}
			c, err = dengine.Compile(env, r, rules.Digest([]byte(content)), "")
			if err != nil {
				t.Fatal(err)
			}
			for _, res := range dengine.RunTests(context.Background(), c) {
				if !res.Passed {
					t.Errorf("tests/events.yaml: %+v", res)
				}
			}
		})
	}
}

// expect is a range scenario's tests/expect.yaml.
type expect struct {
	Verdict string   `json:"verdict"`
	Steps   []string `json:"steps"`
}

// TestHubSeed_RangeScenariosAreCustomerAuthored: each scenario parses and
// validates unchanged, under the customer limits: CX id, business tier, only
// live-driver steps. None has the library's id (HR-564).
//
// Covers: F849
func TestHubSeed_RangeScenariosAreCustomerAuthored(t *testing.T) {
	for _, it := range ofKind(t, domain.KindRangeScenario) {
		t.Run(it.Entry.Name, func(t *testing.T) {
			body, err := it.Item.DecodeBody()
			if err != nil {
				t.Fatal(err)
			}
			b := body.(domain.RangeScenarioBody)
			s, err := rtdomain.Parse([]byte(b.Scenario))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.CheckFileName(b.FileName); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(s.ID, "CX-9") || len(s.ID) != len("CX-90001") {
				t.Errorf("id %s, want CX-90001…", s.ID)
			}
			if o := rtdomain.OriginOf(s.ID); o != rtdomain.OriginCustomer {
				t.Errorf("origin %s", o)
			}
			if _, ok := library.Lookup(s.ID); ok {
				t.Error("a customer scenario is in the library")
			}
			doc, err := rtdomain.ToJSON(it.Tests["expect.yaml"])
			if err != nil {
				t.Fatal(err)
			}
			var e expect
			if err := json.Unmarshal(doc, &e, json.RejectUnknownMembers(true)); err != nil {
				t.Fatal(err)
			}
			var steps []string
			for _, st := range s.Steps {
				steps = append(steps, st.ID)
			}
			if !slices.Equal(steps, e.Steps) || e.Verdict != string(rtdomain.VerdictPass) {
				t.Errorf("steps %v, tests/expect.yaml %+v", steps, e)
			}
		})
	}
}

// automationEnv is an organization where every lookup holds and nothing is
// irreversible: the checks that are org-specific run when a person enables
// the draft.
type automationEnv struct{ now time.Time }

var automationOwner = ids.NewV7()

func (e automationEnv) Now() time.Time { return e.now }

func (automationEnv) Owner() ids.UUID { return automationOwner }

func (automationEnv) OwnerActivePerson(context.Context, ids.UUID) (bool, error) { return true, nil }

func (automationEnv) AgentGrantable(context.Context, ids.UUID) (bool, error) { return true, nil }

func (automationEnv) Operation(context.Context, string) (autodomain.OperationInfo, error) {
	return autodomain.OperationInfo{Known: true}, nil
}

func (automationEnv) DestinationActive(context.Context, ids.UUID, string) (bool, error) {
	return true, nil
}

func (automationEnv) EligibleApprovers(context.Context, autodomain.GateWith, ids.UUID, ids.UUID) (int, error) {
	return 2, nil
}

func (automationEnv) Edition(x autodomain.Edition) bool { return x == autodomain.EditionTeam }

// TestHubSeed_Automations: each definition parses as a draft does, carries no
// review date to go stale, validates with no error on the Team edition once a
// person sets one, starts with nothing that acts on its own, and runs its
// baseline tests on the engine's simulator (HR-287).
//
// Covers: F849
func TestHubSeed_Automations(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	for _, it := range ofKind(t, domain.KindAutomation) {
		t.Run(it.Entry.Name, func(t *testing.T) {
			body, err := it.Item.DecodeBody()
			if err != nil {
				t.Fatal(err)
			}
			b := body.(domain.AutomationBody)
			if !autodomain.NamePattern.MatchString(b.AutomationName) || !autodomain.WorkKind(b.WorkKind).Valid() {
				t.Fatalf("name %q, work kind %q", b.AutomationName, b.WorkKind)
			}
			def, err := autodomain.Parse([]byte(b.Definition))
			if err != nil {
				t.Fatal(err)
			}
			if !def.ReviewBy.IsZero() {
				t.Error("an item names no review date: it would go stale in the index")
			}
			if def.Purpose != b.Purpose || string(def.WorkKind) != b.WorkKind {
				t.Errorf("the definition says %q, %s", def.Purpose, def.WorkKind)
			}
			if !slices.ContainsFunc(autodomain.Validate(ctx, def, automationEnv{start}), func(f autodomain.Finding) bool {
				return f.Code == autodomain.CodeReviewDate
			}) {
				t.Error("a draft without a review date validated: a person must set one")
			}
			if err := json.Unmarshal([]byte(`"`+start.AddDate(0, 0, 30).Format(time.DateOnly)+`"`), &def.ReviewBy); err != nil {
				t.Fatal(err)
			}
			for _, f := range autodomain.Validate(ctx, def, automationEnv{start}) {
				if f.Severity == autodomain.SeverityError {
					t.Errorf("%s %s: %s", f.Code, f.Path, f.Message)
				}
			}
			tests, err := templates.ParseTests(it.Entry.Name, def, it.Tests["baseline.yaml"])
			if err != nil {
				t.Fatal(err)
			}
			kinds := map[string]bool{}
			org := ids.New[ids.Org]()
			for _, tc := range tests {
				kinds[tc.Kind] = true
				clk := clock.NewFake(start)
				trig := tc.Trigger.Ref(org, ids.NewV7(), ids.NewV7(), clk.Now())
				sim, err := engine.Simulate(ctx, def, trig, engine.Stubs(tc.Stubs), clk)
				if err != nil {
					t.Errorf("%q: %v", tc.Name, err)
					continue
				}
				if sim.State != tc.Expect.State || sim.Reason != tc.Expect.Reason {
					t.Errorf("%q: %s %q, want %s %q", tc.Name, sim.State, sim.Reason, tc.Expect.State, tc.Expect.Reason)
				}
				last := map[string]autodomain.StepState{}
				for _, a := range sim.Attempts {
					last[a.StepID] = a.State
				}
				for step, want := range tc.Expect.Steps {
					if last[step] != want {
						t.Errorf("%q: step %s %q, want %s", tc.Name, step, last[step], want)
					}
				}
			}
			for _, k := range []string{templates.TestNormal, templates.TestDenied, templates.TestTimeout, templates.TestDuplicate} {
				if !kinds[k] {
					t.Errorf("no %s test (HR-287)", k)
				}
			}
		})
	}
}

// TestHubSeed_NoCode: no file of the tree is a script or a program, and no
// published item holds a member the format does not define (HR-563).
//
// Covers: F848
func TestHubSeed_NoCode(t *testing.T) {
	err := filepath.WalkDir(hubRoot, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch filepath.Ext(p) {
		case ".yaml", ".md", "":
			return nil
		}
		t.Errorf("%s: the Hub holds YAML and its documents", p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items(t) {
		if _, err := domain.DecodeItem(it.Raw); err != nil {
			t.Errorf("%s: %v", it.Entry.Name, err)
		}
	}
}
