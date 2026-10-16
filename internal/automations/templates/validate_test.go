// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build automations_validate

// These tests need autodomain.Validate (core, feat/m11-core), which this
// branch does not have yet. Remove the build constraint once core is
// merged; until then run them with -tags automations_validate over a tree
// that has core's validate.go.

package templates_test

import (
	"context"
	"slices"
	"testing"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// env is an organization where every lookup holds: owner active, agents
// grantable, destinations active, two eligible approvers; `irreversible`
// says which operations cannot be undone, and they also spend money.
type env struct{ editions []autodomain.Edition }

func (env) Now() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) }

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

func (env) EligibleApprovers(context.Context, autodomain.GateWith, ids.UUID) (int, error) {
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
