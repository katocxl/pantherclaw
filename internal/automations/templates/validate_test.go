// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package templates_test

import (
	"context"
	"slices"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// env is an organization where every lookup holds: owner active, agents
// grantable, destinations active, two eligible approvers; `irreversible`
// says which operations cannot be undone, and they also spend money.
type env struct{ editions []autodomain.Edition }

func (env) Now() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }

// Owner is the automation row's owner (D68), never the template's.
func (env) Owner() ids.UUID { return owner }

var owner = ids.NewV7()

func (env) OwnerActivePerson(context.Context, ids.UUID) (bool, error) { return true, nil }

func (env) AgentGrantable(context.Context, ids.UUID) (bool, error) { return true, nil }

func (env) Operation(_ context.Context, op string) (autodomain.OperationInfo, error) {
	// A prefix is as wide as the widest operation it covers.
	covers := gdomain.Ops{op}.Matches
	return autodomain.OperationInfo{
		Known: true, Irreversible: slices.ContainsFunc(irreversible, covers), ConsumesBudget: slices.ContainsFunc(irreversible, covers),
	}, nil
}

func (env) DestinationActive(context.Context, ids.UUID, string) (bool, error) { return true, nil }

func (env) EligibleApprovers(context.Context, autodomain.GateWith, ids.UUID, ids.UUID) (int, error) {
	return 2, nil
}

func (e env) Edition(x autodomain.Edition) bool { return slices.Contains(e.editions, x) }

var business = env{editions: []autodomain.Edition{autodomain.EditionTeam, autodomain.EditionBusiness}}

// TestRenderedTemplatesValidate: every variant of every template validates
// with no ERROR finding.
func TestRenderedTemplatesValidate(t *testing.T) {
	for _, rs := range renderAll(t) {
		for _, r := range rs {
			for _, f := range autodomain.Validate(context.Background(), r.def, business) {
				if f.Severity == autodomain.SeverityError {
					t.Errorf("%s: %s %s: %s\n%s", r.name, f.Code, f.Path, f.Message, r.doc)
				}
			}
		}
	}
}

// TestHR284_ContainmentNeedsBusiness: in a Team organization the
// containment template does not validate.
func TestHR284_ContainmentNeedsBusiness(t *testing.T) {
	team := env{editions: []autodomain.Edition{autodomain.EditionTeam}}
	for _, r := range renderAll(t)["scoped_incident_containment"] {
		fs := autodomain.Validate(context.Background(), r.def, team)
		if !slices.ContainsFunc(fs, func(f autodomain.Finding) bool { return f.Code == autodomain.CodeUnsupportedCapability }) {
			t.Errorf("%s validates without the Business edition: %v", r.name, fs)
		}
	}
}

// TestIrreversibleWithoutConfirmationIsRefused: leaving out the effect
// confirmation of an irreversible operation is a validation error, so a
// caller cannot skip it.
func TestIrreversibleWithoutConfirmationIsRefused(t *testing.T) {
	r := renderAll(t)["bounded_task_launch"][0]
	r.def.Authority.Ceiling.Bounds.Operations = &gdomain.Ops{"payments.refund"}
	fs := autodomain.Validate(context.Background(), r.def, business)
	if !slices.ContainsFunc(fs, func(f autodomain.Finding) bool { return f.Code == autodomain.CodeIrreversibleUnreconciled }) {
		t.Errorf("no IRREVERSIBLE_UNRECONCILED: %v", fs)
	}
}

// TestD103_EveryTemplateValidatesWithItsExample: each of the nine
// templates, rendered with its defaults and example values, passes core's
// Validate with no ERROR finding (D103 T2).
func TestD103_EveryTemplateValidatesWithItsExample(t *testing.T) {
	list := templates.List()
	if len(list) != 9 {
		t.Fatalf("%d templates", len(list))
	}
	for _, tm := range list {
		doc, _, err := templates.Render(tm.ID, tm.Example())
		if err != nil {
			t.Fatalf("%s: %v", tm.ID, err)
		}
		def, err := autodomain.Parse(doc)
		if err != nil {
			t.Fatalf("%s: %v", tm.ID, err)
		}
		for _, f := range autodomain.Validate(context.Background(), def, business) {
			if f.Severity == autodomain.SeverityError {
				t.Errorf("%s: %s %s: %s", tm.ID, f.Code, f.Path, f.Message)
			}
		}
	}
}

// TestD103_WaitCoverageNeedsTheOperationParameter: wait_coverage reads the
// trigger's operation parameter, so a definition that does not declare it
// does not validate (D103 T6).
func TestD103_WaitCoverageNeedsTheOperationParameter(t *testing.T) {
	r := renderAll(t)["coverage_recovery"][0]
	def, err := autodomain.Parse(r.doc)
	if err != nil {
		t.Fatal(err)
	}
	params := def.When.Params()
	if _, ok := params["operation"]; !ok {
		t.Fatal("coverage_recovery does not declare operation")
	}
	delete(params, "operation")
	if !slices.ContainsFunc(autodomain.Validate(context.Background(), def, business), func(f autodomain.Finding) bool {
		return f.Code == autodomain.CodeParamUndeclared && f.Severity == autodomain.SeverityError
	}) {
		t.Fatal("wait_coverage without the operation parameter validates")
	}
}
