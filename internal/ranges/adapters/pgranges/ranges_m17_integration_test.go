// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgranges_test

import (
	"context"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/ranges/app"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR466_TheDatabaseHoldsTheOrigin (integration, migration 00213): a
// customer range and its results are stored as customer; the database
// refuses a range whose ids disagree with its origin and a result whose
// origin disagrees with its id, so a CX result can never be read back as
// the library's (G0 M17 D124).
// Covers: PN-009.6
func TestHR466_TheDatabaseHoldsTheOrigin(t *testing.T) {
	w := newWorld(t, dbtest.New(t))
	w.svc.Editions = edition(billing.Business)
	ctx := w.as(td.RoleAgentOwner)
	cx := domain.Scenario{ID: "CX-00042", Digest: hexA, Tier: domain.TierBusiness, Category: "boundary", Suite: "coding-agent", Title: "t", StepCount: 1}
	r, err := w.svc.StartRange(ctx, app.StartInput{Agent: w.rangeAgent, Scenarios: []domain.Scenario{cx}, RunnerVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.RecordResult(ctx, app.RecordInput{Range: r.ID, Scenario: "CX-00042", Digest: hexA, Verdict: domain.Skipped}); err != nil {
		t.Fatal(err)
	}
	got, err := w.svc.GetRange(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Range.Origin != domain.OriginCustomer || len(got.Results) != 1 || got.Results[0].Scenario.Origin != domain.OriginCustomer {
		t.Fatalf("stored range %q, results %+v", got.Range.Origin, got.Results)
	}
	lib := w.start(t, "RT-001")
	if lib.Origin != domain.OriginLibrary {
		t.Fatalf("library range stored as %q", lib.Origin)
	}

	exec := func(sql string, args ...any) error {
		return w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	run := `INSERT INTO pc.redteam_runs (org_id, id, range_agent_id, started_by, runner_version, scenario_set_digest, scenarios, origin)
		VALUES ($1, $2, $3, 'user:x', 'v', $4, $5::jsonb, $6)`
	for _, tc := range []struct{ id, origin string }{{"RT-001", "customer"}, {"CX-001", "library"}, {"CX-001", "other"}} {
		scenarios := `[{"id":"` + tc.id + `","digest":"` + hexA + `","tier":"business","category":"boundary","suite":"coding-agent"}]`
		if err := exec(run, w.org, ids.NewV7(), w.rangeAgent, hexA, scenarios, tc.origin); err == nil {
			t.Errorf("a %s range declaring %s was stored", tc.origin, tc.id)
		}
	}
	result := `INSERT INTO pc.redteam_results (org_id, range_id, scenario_id, scenario_digest, suite, category, tier, verdict, observed_by, origin)
		VALUES ($1, $2, $3, $4, 'coding-agent', 'boundary', 'business', 'SKIPPED', 'NONE', $5)`
	r2, err := w.svc.StartRange(ctx, app.StartInput{Agent: w.rangeAgent, Scenarios: []domain.Scenario{{ID: "CX-007", Digest: hexA, Tier: domain.TierBusiness, Category: "boundary", Suite: "coding-agent", Title: "t", StepCount: 1}}, RunnerVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := exec(result, w.org, r2.ID, "CX-007", hexA, "library"); err == nil {
		t.Error("a CX result stored as library")
	}
	if err := exec(result, w.org, r2.ID, "CX-007", hexA, "customer"); err != nil {
		t.Errorf("the CX result itself: %v", err)
	}
}
