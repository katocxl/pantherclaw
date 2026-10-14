// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package consequences_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

var now = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

// merge is pc.github's merge with its consequence rule.
func merge(t *testing.T) (*defs.Definition, []consequences.Rule) {
	t.Helper()
	p, err := manifest.Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	on, ok := p.Definition("github.pull.merge")
	if !ok {
		t.Fatal("no github.pull.merge")
	}
	var rules []consequences.Rule
	for _, r := range p.Consequences {
		if r.Operation == on.Operation {
			d, _ := p.Definition(r.Consequence.Operation)
			rules = append(rules, consequences.Rule{ConsequenceRule: r, Definition: d})
		}
	}
	if len(rules) != 1 {
		t.Fatalf("%d merge rules", len(rules))
	}
	return on, rules
}

// triggers is a github.repo.deploy_triggers fact observed ago before now.
func triggers(members map[string]any, ago time.Duration) map[string]fdomain.Fact {
	return map[string]fdomain.Fact{"github.repo.deploy_triggers": {
		Name: "github.repo.deploy_triggers", SubjectType: "github.pull_request", SubjectID: "acme/payments#7",
		Value: fdomain.Value{Type: fdomain.TypeObject, Object: members}, ObservedAt: now.Add(-ago),
	}}
}

func evaluate(t *testing.T, facts map[string]fdomain.Fact, ages map[string]time.Duration) consequences.Consequence {
	t.Helper()
	on, rules := merge(t)
	out := consequences.NewEvaluator(celenv.DefaultLimits).Evaluate(context.Background(), rules, consequences.Input{
		On: on, TargetID: "acme/payments#7", Facts: facts, Ages: ages, Now: now,
	})
	if len(out) != 1 {
		t.Fatalf("%d consequences", len(out))
	}
	return out[0]
}

// TestHR206_APredictedDeploymentNamesItsRepositoryAndEnvironments: a merge
// into a branch a workflow deploys on push predicts github.deployment.trigger
// on the repository, with the environments the fact names; with no
// trigger, the consequence is ruled out on the same current fact.
func TestHR206_APredictedDeploymentNamesItsRepositoryAndEnvironments(t *testing.T) {
	c := evaluate(t, triggers(map[string]any{
		"state": "triggered", "environments": []any{"production", "staging", "production"},
		"workflows": []any{map[string]any{"path": ".github/workflows/deploy.yml", "environments": []any{"production"}}},
	}, 5*time.Second), nil)
	if c.Err != nil || c.State != consequences.Predicted || c.Operation != "github.deployment.trigger" ||
		c.Target.Type != "github.repository" || c.Target.ID != "acme/payments" || !slices.Equal(c.Environments, []string{"production", "staging"}) ||
		len(c.Used) != 1 || !strings.HasPrefix(c.FactsDigest, "sha256:") {
		t.Fatalf("predicted: %+v", c)
	}
	c = evaluate(t, triggers(map[string]any{"state": "none", "environments": []any{}}, 5*time.Second), nil)
	if c.Err != nil || c.State != consequences.NotTriggered || len(c.Environments) != 0 {
		t.Fatalf("not triggered: %+v", c)
	}
}

// TestHR206_AFactThatCannotBeUsedMakesTheConsequenceUnknown: a missing
// fact, one older than its maximum age (30 seconds, or younger when the
// definition or policy asks) and one the provider marked unknown (a
// workflow change, an expression it cannot evaluate) leave the consequence
// UNKNOWN with the reason, never ruled out.
func TestHR206_AFactThatCannotBeUsedMakesTheConsequenceUnknown(t *testing.T) {
	triggered := map[string]any{"state": "triggered", "environments": []any{"production"}}
	for name, tc := range map[string]struct {
		facts map[string]fdomain.Fact
		ages  map[string]time.Duration
		why   string
	}{
		"missing": {nil, nil, "is not known"},
		"stale":   {triggers(triggered, 31*time.Second), nil, "at most 30s"},
		"stale for the definition": {
			triggers(triggered, 11*time.Second), map[string]time.Duration{"github.repo.deploy_triggers": 10 * time.Second}, "at most 10s",
		},
		"unknown member": {
			triggers(map[string]any{"state": "none", "unknown": "the pull request changes .github/workflows/deploy.yml\x07"}, time.Second), nil,
			"unknown: the pull request changes .github/workflows/deploy.yml ",
		},
		// The gateway could not read it (Q11): never ruled out.
		"unread": {triggers(map[string]any{"unread": "no read token"}, time.Second), nil, "could not be read: no read token"},
	} {
		c := evaluate(t, tc.facts, tc.ages)
		if c.Err != nil || c.State != consequences.Unknown || len(c.Unknown) != 1 || !strings.Contains(c.Unknown[0], tc.why) ||
			c.Target.ID != "acme/payments" {
			t.Errorf("%s: %+v", name, c)
		}
	}
	// An older age than 30 seconds asked elsewhere does not widen it.
	if c := evaluate(t, triggers(triggered, 31*time.Second), map[string]time.Duration{"github.repo.deploy_triggers": time.Hour}); c.State != consequences.Unknown {
		t.Errorf("a wider age widened it: %+v", c)
	}
}

// TestHR206_ARuleThatCannotBeEvaluatedIsAnError: a condition or an
// environments expression that fails at runtime, a consequence operation
// the package does not define and a target the template cannot form are
// errors (CANNOT_AUTHORIZE, HR-040), never "not triggered".
func TestHR206_ARuleThatCannotBeEvaluatedIsAnError(t *testing.T) {
	on, rules := merge(t)
	ev := consequences.NewEvaluator(celenv.DefaultLimits)
	run := func(r consequences.Rule, facts map[string]fdomain.Fact, target string) consequences.Consequence {
		t.Helper()
		return ev.Evaluate(context.Background(), []consequences.Rule{r}, consequences.Input{On: on, TargetID: target, Facts: facts, Now: now})[0]
	}
	ok := triggers(map[string]any{"state": "triggered", "environments": []any{"production"}}, time.Second)
	for name, tc := range map[string]struct {
		mutate func(*consequences.Rule)
		facts  map[string]fdomain.Fact
		target string
	}{
		"no state member": {func(*consequences.Rule) {}, triggers(map[string]any{"environments": []any{}}, time.Second), "acme/payments#7"},
		"not a condition": {func(r *consequences.Rule) { r.When = "facts.github_repo_deploy_triggers.state" }, ok, "acme/payments#7"},
		"environments not a list": {
			func(r *consequences.Rule) { r.Consequence.Environments = "facts.github_repo_deploy_triggers.state" }, ok, "acme/payments#7",
		},
		"an empty environment": {
			func(*consequences.Rule) {}, triggers(map[string]any{"state": "triggered", "environments": []any{""}}, time.Second), "acme/payments#7",
		},
		"no consequence definition": {func(r *consequences.Rule) { r.Definition = nil }, ok, "acme/payments#7"},
		"a target it cannot form":   {func(*consequences.Rule) {}, ok, "Acme/payments#7"},
	} {
		r := rules[0]
		tc.mutate(&r)
		if c := run(r, tc.facts, tc.target); !errors.Is(c.Err, consequences.ErrRule) || c.State == consequences.NotTriggered {
			t.Errorf("%s: %+v", name, c)
		}
	}
}
