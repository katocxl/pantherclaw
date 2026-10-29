// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/ranges/app"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// cx is a customer scenario declaration: any digest, a tier the server
// overrides.
func cx(id string) domain.Scenario {
	return domain.Scenario{ID: id, Digest: hexB, Tier: domain.TierCommunity, Category: "boundary", Suite: "coding-agent", Title: id, StepCount: 1}
}

// asDeveloper is a service account that runs ranges in the world's org.
func (w *world) asDeveloper() context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleDeveloper, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
	}})
}

// TestHR466_CustomerScenariosAreLabelledAndNeverAttested: the server labels
// a CX range and each of its results customer-authored from the ids, whatever
// the runner sent; a range never mixes library and customer scenarios; a
// customer range exports no assurance pack (RANGE_CUSTOMER_NOT_ATTESTED);
// and its baseline is an earlier customer range (G0 M17 D124, D126).
// Covers: PN-009.6
func TestHR466_CustomerScenariosAreLabelledAndNeverAttested(t *testing.T) {
	w := newWorld(t, billing.Business, td.RoleSecurityAdmin)
	dev := w.asDeveloper()
	r, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{cx("CX-001"), cx("CX-10042")}, RunnerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Origin != domain.OriginCustomer {
		t.Fatalf("range origin %q, want customer", r.Origin)
	}
	for _, sc := range r.Scenarios {
		if sc.Origin != domain.OriginCustomer || sc.Tier != domain.TierBusiness {
			t.Errorf("%s: origin %q tier %q, want customer business", sc.ID, sc.Origin, sc.Tier)
		}
	}
	res, err := w.svc.RecordResult(dev, app.RecordInput{Range: r.ID, Scenario: "CX-001", Digest: hexB, Verdict: domain.Pass, Steps: []domain.StepInput{step("s", allow, allow, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scenario.Origin != domain.OriginCustomer {
		t.Errorf("result origin %q, want customer", res.Scenario.Origin)
	}
	if _, err := w.svc.FinishRange(dev, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.ExportAssuranceReport(w.ctx, r.ID); !errors.Is(err, app.ErrNotAttested) {
		t.Fatalf("export of a customer range: %v, want RANGE_CUSTOMER_NOT_ATTESTED", err)
	}
	if len(w.f.exported) != 0 {
		t.Fatal("a customer range was exported")
	}

	// Never mixed, in either order.
	for _, set := range [][]domain.Scenario{
		{decl("RT-001", domain.TierCommunity, "boundary"), cx("CX-002")},
		{cx("CX-002"), decl("RT-001", domain.TierCommunity, "boundary")},
	} {
		if _, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: set, RunnerVersion: "t"}); !errors.Is(err, app.ErrMixed) {
			t.Errorf("a mixed range: %v, want RANGE_ORIGIN_MIXED", err)
		}
	}

	// The baseline of a customer range is a customer range, and the reverse.
	lib, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{decl("RT-001", domain.TierCommunity, "boundary")}, RunnerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.FinishRange(dev, lib.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{cx("CX-001")}, RunnerVersion: "t", Baseline: &lib.ID}); !errors.Is(err, app.ErrBaseline) {
		t.Errorf("a library baseline for a customer range: %v, want BASELINE_INVALID", err)
	}
	if _, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{decl("RT-001", domain.TierCommunity, "boundary")}, RunnerVersion: "t", Baseline: &r.ID}); !errors.Is(err, app.ErrBaseline) {
		t.Errorf("a customer baseline for a library range: %v, want BASELINE_INVALID", err)
	}
	if _, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{cx("CX-001")}, RunnerVersion: "t", Baseline: &r.ID}); err != nil {
		t.Errorf("a customer baseline for a customer range: %v", err)
	}
}

// TestRangeCustomScenariosNeedBusiness: customer scenarios need the
// Business edition (D126, PN-009.6).
// Covers: PN-009.6
func TestRangeCustomScenariosNeedBusiness(t *testing.T) {
	for _, tc := range []struct {
		edition billing.Edition
		allowed bool
	}{
		{billing.Community, false}, {billing.Team, false}, {billing.Business, true}, {billing.Enterprise, true},
	} {
		w := newWorld(t, tc.edition, td.RoleAgentOwner)
		_, err := w.svc.StartRange(w.ctx, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{cx("CX-001")}, RunnerVersion: "t"})
		if got := err == nil; got != tc.allowed {
			t.Errorf("%s: allowed %v (err %v), want %v", tc.edition, got, err, tc.allowed)
		} else if err != nil && !errors.Is(err, app.ErrEdition) {
			t.Errorf("%s: err = %v, want EDITION_REQUIRED", tc.edition, err)
		}
	}
}

// TestHR467_AnRTIDNeedsTheLibraryDigest: an RT scenario is accepted only
// with the digest the server's embedded library holds for that id
// (RANGE_SCENARIO_NOT_LIBRARY), and its tier is the library's, never the
// runner's (G0 M17 D125).
// Covers: PN-009.6
func TestHR467_AnRTIDNeedsTheLibraryDigest(t *testing.T) {
	w := newWorld(t, billing.Business, td.RoleAgentOwner)
	for name, sc := range map[string]domain.Scenario{
		"edited content": {ID: "RT-001", Digest: hexA, Tier: domain.TierCommunity, Category: "boundary", Suite: "coding-agent", Title: "x", StepCount: 1},
		"unknown id":     {ID: "RT-999", Digest: hexA, Tier: domain.TierCommunity, Category: "boundary", Suite: "coding-agent", Title: "x", StepCount: 1},
		"another's digest": {
			ID: "RT-002", Digest: dig("RT-001"), Tier: domain.TierCommunity, Category: "boundary", Suite: "coding-agent",
			Title: "x", StepCount: 1,
		},
	} {
		if _, err := w.svc.StartRange(w.ctx, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{sc}, RunnerVersion: "t"}); !errors.Is(err, app.ErrNotLibrary) {
			t.Errorf("%s: %v, want RANGE_SCENARIO_NOT_LIBRARY", name, err)
		}
	}
	// RT-030 is business-tier in the library: declaring it community changes
	// nothing.
	r := w.start(t, decl("RT-030", domain.TierCommunity, "boundary"))
	if r.Scenarios[0].Tier != domain.TierBusiness || r.Scenarios[0].Origin != domain.OriginLibrary {
		t.Fatalf("RT-030 recorded as %q %q, want business library", r.Scenarios[0].Tier, r.Scenarios[0].Origin)
	}
}

// TestT204_AForgedLibraryScenarioCannotInflateAssurance: a runner cannot
// pass its own scenario off as the library's to inflate an assurance
// report: an edited RT file is refused, a business-tier library scenario
// declared community still needs Business, and a CX scenario is never
// counted as the library's (T-204, HR-466, HR-467).
// Covers: PN-009.6
func TestT204_AForgedLibraryScenarioCannotInflateAssurance(t *testing.T) {
	team := newWorld(t, billing.Team, td.RoleAgentOwner)
	forged := decl("RT-009", domain.TierCommunity, "boundary")
	forged.Digest = hexA // the library scenario, edited to pass
	if _, err := team.svc.StartRange(team.ctx, app.StartInput{Agent: team.agent, Scenarios: []domain.Scenario{forged}, RunnerVersion: "t"}); !errors.Is(err, app.ErrNotLibrary) {
		t.Fatalf("a forged RT-009: %v, want RANGE_SCENARIO_NOT_LIBRARY", err)
	}
	// The real business-tier scenario remarked community.
	if _, err := team.svc.StartRange(team.ctx, app.StartInput{Agent: team.agent, Scenarios: []domain.Scenario{decl("RT-030", domain.TierCommunity, "boundary")}, RunnerVersion: "t"}); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("RT-030 remarked community on Team: %v, want EDITION_REQUIRED", err)
	}
	// A customer scenario stays customer-authored: its range has no report.
	biz := newWorld(t, billing.Business, td.RoleSecurityAdmin)
	dev := biz.asDeveloper()
	r, err := biz.svc.StartRange(dev, app.StartInput{Agent: biz.agent, Scenarios: []domain.Scenario{cx("CX-009")}, RunnerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := biz.svc.FinishRange(dev, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := biz.svc.ExportAssuranceReport(biz.ctx, r.ID); !errors.Is(err, app.ErrNotAttested) {
		t.Fatalf("export: %v, want RANGE_CUSTOMER_NOT_ATTESTED", err)
	}
}
