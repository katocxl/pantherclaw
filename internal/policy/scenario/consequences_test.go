// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scenario

import (
	"context"
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// packageWorld also serves the active packages, as the definitions store
// does, so consequences are decided.
type packageWorld struct {
	world
	pkgs []*defs.Package
}

func (w *packageWorld) ActivePackages(_ context.Context, org ids.OrgID) ([]*defs.Package, error) {
	w.reads = append(w.reads, "packages:"+org.String())
	return w.pkgs, nil
}

func githubWorld(t *testing.T) *packageWorld {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "packages", "pc-github", "package.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	w := &packageWorld{world: world{catalog: map[string]fdomain.Type{}}, pkgs: []*defs.Package{pkg}}
	for i := range pkg.Definitions {
		w.defs = append(w.defs, &pkg.Definitions[i])
	}
	return w
}

const headSHA = "0123456789abcdef0123456789abcdef01234567"

// mergeCase merges acme/payments#7 at headSHA with the deploy triggers
// given; the pull request's own prerequisites are present and fresh, and
// no provider declares any of them (the catalog is empty).
func mergeCase(id, triggers string, expect pdomain.TestExpect) pdomain.TestCase {
	obj := func(v string) pdomain.TestFact {
		return pdomain.TestFact{Value: jsontext.Value(`{"object":` + v + `}`), AgeSeconds: 5}
	}
	return pdomain.TestCase{
		ID: id, Summary: "merge with triggers " + triggers,
		Action: pdomain.TestAction{
			Operation: "github.pull.merge", Target: &actionir.Target{Type: "github.pull_request", ID: "acme/payments#7"},
			Params: jsontext.Value(`{"sha":"` + headSHA + `","merge_method":"squash"}`),
		},
		Given: &pdomain.TestGiven{Facts: map[string]pdomain.TestFact{
			"github.pull.head":            obj(`{"sha":"` + headSHA + `"}`),
			"github.pull.people":          obj(`{"complete":true,"author":1,"pushers":[1]}`),
			"github.pull.reviews":         obj(`{"approved":1}`),
			"github.pull.checks":          obj(`{"passed":true}`),
			"github.branch.rules":         obj(`{"protected":true}`),
			"github.repo.deploy_triggers": obj(triggers),
		}},
		Expect: expect,
	}
}

func noProduction() pdomain.Rule {
	return pdomain.Rule{
		ID: "no-production", Kind: pdomain.Forbid, Summary: "no deployments to production",
		Operations: []string{"github.deployment.trigger"}, When: `consequence.environments.exists(e, e == "production")`,
		Reason: "PRODUCTION_DEPLOY",
	}
}

// TestScenarioConsequencesAreDecided is D28: a merge decides the deployment
// it triggers, with the environments the deploy-triggers fact names, as the
// Authority does; unknown triggers are held. The mutation gate covers the
// rule that only ever decides through the consequence.
func TestScenarioConsequencesAreDecided(t *testing.T) {
	w := githubWorld(t)
	r := newRunner(&w.world, papp.DefaultBudget)
	r.pkgs = w
	rules := []pdomain.Rule{noProduction(), approveDeploys()}
	deny := mergeCase("production", `{"state":"triggered","environments":["production"]}`,
		pdomain.TestExpect{Decision: "DENY", Reason: "PRODUCTION_DEPLOY", Rule: "no-production"})
	staging := mergeCase("staging", `{"state":"triggered","environments":["staging"]}`,
		pdomain.TestExpect{Decision: "REQUIRE_APPROVAL", Reason: "DEPLOY_APPROVAL", Rule: "approve-deploys"})
	unknown := mergeCase("unknown", `{"state":"none","unknown":"the pull request changes a workflow"}`,
		pdomain.TestExpect{Decision: "REQUIRE_APPROVAL", Reason: consequences.ReasonUnknown})
	res := runOK(t, r, bundle(rules, deny, staging, unknown))
	for _, c := range res.Cases {
		if !c.Passed {
			t.Errorf("case %s: %s", c.ID, c.Detail)
		}
	}
	if !res.Passed || res.Mutants != 3 || res.Survivors != 0 {
		t.Fatalf("gate: %+v", res)
	}
	// Only the staging case: the rule's removal and its == flip are not
	// both noticed, so the gate refuses.
	weak := runOK(t, r, bundle(rules, staging))
	if weak.Passed || !slices.ContainsFunc(weak.Surviving, func(m pdomain.MutantResult) bool { return m.Mutation == RemoveRule }) {
		t.Fatalf("staging only: %+v", weak)
	}
	// With no requirement on the deployment, nothing can release an unknown
	// one: CANNOT_AUTHORIZE, as the Authority answers.
	unreleasable := unknown
	unreleasable.Expect.Decision = "CANNOT_AUTHORIZE"
	if res := runOK(t, r, bundle([]pdomain.Rule{noProduction()}, unreleasable)); !res.Cases[0].Passed {
		t.Fatalf("unknown without a requirement: %+v", res.Cases[0])
	}
	// Without the packages there are no consequence rules: the merge alone
	// is allowed, so the production case fails, as it should.
	plain := newRunner(&w.world, papp.DefaultBudget)
	if res := runOK(t, plain, bundle([]pdomain.Rule{noProduction()}, deny)); res.Cases[0].Passed {
		t.Fatalf("no packages: %+v", res)
	}
	if !slices.Contains(w.reads, "packages:"+testOrg.String()) {
		t.Fatalf("packages not read: %v", w.reads)
	}
	// The head binding (HR-205) reads the prerequisite's value.
	moved := mergeCase("moved", `{"state":"none","environments":[]}`, pdomain.TestExpect{Decision: "CANNOT_AUTHORIZE", Reason: "HEAD_MOVED"})
	moved.Given.Facts["github.pull.head"] = pdomain.TestFact{Value: jsontext.Value(`{"object":{"sha":"` + strings.Repeat("f", 40) + `"}}`), AgeSeconds: 5}
	if res := runOK(t, r, bundle([]pdomain.Rule{noProduction()}, moved)); !res.Cases[0].Passed {
		t.Fatalf("moved head: %+v", res.Cases[0])
	}
}

// TestScenarioNewUsesThePackagesOfTheDefinitionsReader: New picks up
// ActivePackages from the definitions reader, as the server's definitions
// store has it.
func TestScenarioNewUsesThePackagesOfTheDefinitionsReader(t *testing.T) {
	w := githubWorld(t)
	if r := New(w, w, celenv.DefaultLimits, 1); r.pkgs == nil {
		t.Fatal("ActivePackages not used")
	}
	if r := New(&w.world, w, celenv.DefaultLimits, 1); r.pkgs != nil {
		t.Fatal("a reader without ActivePackages has packages")
	}
}

func approveDeploys() pdomain.Rule {
	return pdomain.Rule{
		ID: "approve-deploys", Kind: pdomain.RequireApproval, Summary: "deployments need an approver",
		Operations: []string{"github.deployment.trigger"}, When: "true", Reason: "DEPLOY_APPROVAL",
		Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
}
