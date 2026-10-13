// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// TestConsequenceTargetsAndEnvironments (G0 M8, HR-206): a consequence
// names its target as a template over the action's target id, from
// target.id and the named groups of its pattern, and the environments it
// reaches as a CEL expression over its facts. A template that names
// another group or carries other text is refused.
func TestConsequenceTargetsAndEnvironments(t *testing.T) {
	merge := minimal(map[string]domain.ParamSpec{})
	merge.Operation, merge.Access = "x.pull.merge", domain.AccessWrite
	merge.Target = domain.TargetSpec{Type: "x.pull_request", IDPattern: prPattern, Account: domain.PresenceNone}
	merge.Approval = &domain.ApprovalTemplate{Title: "Merge {target.id}", Fields: []string{"target.id"}}
	trigger := minimal(map[string]domain.ParamSpec{})
	trigger.Operation, trigger.Access, trigger.Mappings = "x.deployment.trigger", domain.AccessWrite, nil
	trigger.Approval = &domain.ApprovalTemplate{Title: "Deploy {target.id}", Fields: []string{"target.id"}}
	rule := domain.ConsequenceRule{
		ID: "merge-deploys", Operation: "x.pull.merge", When: "facts.x_deploy.state != 'none'", RequiresFacts: []string{"x.deploy"},
		ValidUntil: "2027-01-01",
		Consequence: domain.Consequence{
			Operation: "x.deployment.trigger", Effect: "deployment.trigger", Description: "Deploys",
			Target: "{target.id.owner}/{target.id.repo}", Environments: "facts.x_deploy.environments",
		},
	}
	pkg := func(r domain.ConsequenceRule) *domain.Package {
		return &domain.Package{
			Format: 1, Name: "pc.test", Version: "1.0.0", Publisher: "pantherclaw", Summary: "s",
			Definitions: []domain.Definition{*merge, *trigger}, Consequences: []domain.ConsequenceRule{r},
		}
	}
	if err := pkg(rule).Validate(); err != nil {
		t.Fatal(err)
	}
	if id, ok := rule.TargetID(merge.Target, "acme/payments#7"); !ok || id != "acme/payments" {
		t.Fatalf("target %q %v", id, ok)
	}
	if id, ok := rule.TargetID(merge.Target, "Acme/payments#7"); ok {
		t.Fatalf("a target the pattern does not match: %q", id)
	}
	own := rule
	own.Consequence.Target = ""
	if id, ok := own.TargetID(merge.Target, "acme/payments#7"); !ok || id != "acme/payments#7" {
		t.Fatalf("without a template: %q %v", id, ok)
	}
	for name, target := range map[string]string{
		"another group":   "{target.id.branch}",
		"a param":         "{params.sha}",
		"no reference":    "acme/payments",
		"other text":      "{target.id.owner} {target.id.repo}",
		"a stray brace":   "{target.id.owner}/{target.id.repo",
		"a long template": strings.Repeat("{target.id}", 30),
	} {
		r := rule
		r.Consequence.Target = target
		if err := pkg(r).Validate(); !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "target") {
			t.Errorf("%s: %v", name, err)
		}
	}
	r := rule
	r.Consequence.Environments = strings.Repeat("x", 5000)
	if err := pkg(r).Validate(); !errors.Is(err, domain.ErrInvalid) {
		t.Errorf("a long environments expression: %v", err)
	}
}

// TestHR206_AConsequenceOperationIsDefinedInItsPackage: the pipeline
// decides a consequence by its definition in the same package version, so
// a rule whose consequence operation the package does not define is
// refused at import, not left to fail when an action needs it.
func TestHR206_AConsequenceOperationIsDefinedInItsPackage(t *testing.T) {
	merge := minimal(map[string]domain.ParamSpec{})
	merge.Operation, merge.Access = "x.pull.merge", domain.AccessWrite
	merge.Approval = &domain.ApprovalTemplate{Title: "Merge {target.id}", Fields: []string{"target.id"}}
	trigger := minimal(map[string]domain.ParamSpec{})
	trigger.Operation, trigger.Access, trigger.Mappings = "x.deployment.trigger", domain.AccessWrite, nil
	trigger.Approval = &domain.ApprovalTemplate{Title: "Deploy {target.id}", Fields: []string{"target.id"}}
	pkg := func(consequence string, ds ...domain.Definition) *domain.Package {
		return &domain.Package{
			Format: 1, Name: "pc.test", Version: "1.0.0", Publisher: "pantherclaw", Summary: "s", Definitions: ds,
			Consequences: []domain.ConsequenceRule{{
				ID: "merge-deploys", Operation: "x.pull.merge", When: "true", RequiresFacts: []string{"x.deploy"}, ValidUntil: "2027-01-01",
				Consequence: domain.Consequence{Operation: consequence, Effect: "deployment.trigger", Description: "Deploys"},
			}},
		}
	}
	if err := pkg("x.deployment.trigger", *merge, *trigger).Validate(); err != nil {
		t.Fatalf("a virtual consequence operation of the package: %v", err)
	}
	if err := pkg("x.pull.merge", *merge).Validate(); err != nil {
		t.Fatalf("another operation of the package: %v", err)
	}
	for name, p := range map[string]*domain.Package{
		"an operation it does not define": pkg("x.deployment.start", *merge),
		"another package's operation":     pkg("y.deployment.trigger", *merge),
	} {
		if err := p.Validate(); !errors.Is(err, domain.ErrInvalid) || !strings.Contains(err.Error(), "not defined in this package") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
