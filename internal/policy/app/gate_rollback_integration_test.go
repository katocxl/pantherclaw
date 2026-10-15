// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/json/jsontext"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// refundCase is a scenario test of a refund of amount USD for reason.
func refundCase(id, amount, reason string, expect domain.TestExpect) domain.TestCase {
	return domain.TestCase{
		ID: id, Summary: "a refund of " + amount,
		Action: domain.TestAction{
			Operation: "payments.refund.create", Target: &actionir.Target{Type: "payments.charge", ID: "ch_1"},
			Params: jsontext.Value(`{"amount":{"value":"` + amount + `","currency":"USD"},"reason":"` + reason + `"}`),
		},
		Given: &domain.TestGiven{Facts: map[string]domain.TestFact{
			"payments.charge.refundable": {Value: jsontext.Value(`{"bool":true}`), AgeSeconds: 60},
		}},
		Expect: expect,
	}
}

// tested is a FORBID rule on refunds above 1000 USD with the two cases that
// kill its comparison and removal mutants.
func tested() (domain.Rule, []domain.TestCase) {
	r := denyAbove("deny-large", "1000.00")
	return r, []domain.TestCase{
		refundCase("large-over", "1000.01", "duplicate", domain.TestExpect{Decision: "DENY", Reason: r.Reason, Rule: r.ID}),
		refundCase("large-at", "1000.00", "duplicate", domain.TestExpect{Decision: "ALLOW", Reason: "GRANT_COVERS"}),
	}
}

// incident is an emergency rule added during a fraud incident: no refunds
// for fraud, with the cases that kill its mutants.
func incident() (domain.Rule, []domain.TestCase) {
	r := domain.Rule{
		ID: "freeze", Kind: domain.Forbid, Summary: "no fraud refunds during the incident", Operations: []string{"payments.refund.create"},
		When: `action.params.reason == "fraudulent"`, Reason: "INCIDENT_FREEZE", Emergency: true,
	}
	return r, []domain.TestCase{
		refundCase("freeze-fraud", "10.00", "fraudulent", domain.TestExpect{Decision: "DENY", Reason: r.Reason, Rule: r.ID}),
		refundCase("freeze-other", "10.00", "requested_by_customer", domain.TestExpect{Decision: "ALLOW", Reason: "GRANT_COVERS"}),
	}
}

// TestHR236_ARollbackCarryingAnEmergencyRulePassesTheRealGate (D9, D35):
// with S1a's real scenario runner, a rollback to a version written before
// an emergency rule carries the rule and the tests that decide by it, so
// the rolled-back version passes the gate, every mutant killed, and is
// published at once: it keeps every rule of the published version
// (nothing loosens), so it needs no confirmations.
func TestHR236_ARollbackCarryingAnEmergencyRulePassesTheRealGate(t *testing.T) {
	e := newEnv(t)
	e.v.Tests = scenario.New(e.v.Definitions, catalog{}, celenv.DefaultLimits, app.DefaultBudget)
	alice, _ := e.person("alice", td.RolePolicyPublisher), e.person("bob", td.RolePolicyPublisher)
	ctx := context.Background()

	large, largeTests := tested()
	v1, _, err := e.store.CreateVersion(ctx, e.org, &domain.Bundle{ID: "org-policy", Rules: []domain.Rule{large}, Tests: largeTests},
		"user:author", nil)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := e.v.Publish(alice.ctx, v1); err != nil || out.Version.State != app.StatePublished {
		t.Fatalf("v1 = %+v, %v", out, err)
	}
	freeze, freezeTests := incident()
	v2, _, err := e.store.CreateVersion(ctx, e.org, &domain.Bundle{
		ID: "org-policy", Rules: []domain.Rule{large, freeze}, Tests: append(slices.Clone(largeTests), freezeTests...),
	}, "user:author", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.v.Publish(alice.ctx, v2)
	if err != nil || out.Version.State != app.StatePublished {
		t.Fatalf("an emergency rule (tighter) = %+v, %v", out, err)
	}

	back, err := e.v.Rollback(alice.ctx, v1, nil)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if !slices.Equal(back.Carried, []string{"freeze"}) || back.ChangeRequest != nil || back.Version.State != app.StatePublished ||
		!back.Tests.Passed || back.Tests.Survivors != 0 {
		t.Fatalf("rollback = carried %v, request %v, state %s, tests %+v", back.Carried, back.ChangeRequest, back.Version.State, back.Tests)
	}
	b, err := e.store.Published(ctx, e.org)
	if err != nil || !slices.ContainsFunc(b.Rules, func(r domain.Rule) bool { return r.ID == "freeze" && r.Emergency }) ||
		!slices.ContainsFunc(b.Tests, func(c domain.TestCase) bool { return c.ID == "freeze-fraud" }) {
		t.Fatalf("published after rollback: %+v, %v", b, err)
	}
}
