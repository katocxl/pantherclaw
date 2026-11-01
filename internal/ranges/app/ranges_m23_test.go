// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"errors"
	"os"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/ranges/app"
	rdomain "github.com/katocxl/pantherclaw/internal/ranges/domain"
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR564_HubScenariosNeverEnterAttestedPacks: the Hub's range scenarios are
// customer-authored. A range of them is labeled so, whatever origin and tier
// the runner declares; none is in the library an attested range runs; it
// cannot be mixed into a library range; and its export is refused before any
// pack exists (G0 M23 D112).
//
// Covers: F849
func TestHR564_HubScenariosNeverEnterAttestedPacks(t *testing.T) {
	items, err := seed.Load(os.DirFS("../../../hub"))
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t, billing.Business, td.RoleSecurityAdmin)
	dev := w.asDeveloper()
	var set []rdomain.Scenario
	for _, it := range items {
		if it.Entry.Kind != domain.KindRangeScenario {
			continue
		}
		body, err := it.Item.DecodeBody()
		if err != nil {
			t.Fatal(err)
		}
		sc, err := rtdomain.Parse([]byte(body.(domain.RangeScenarioBody).Scenario))
		if err != nil {
			t.Fatal(err)
		}
		digest, err := rtdomain.Digest(sc)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := library.Lookup(sc.ID); ok {
			t.Errorf("%s is in the library", sc.ID)
		}
		set = append(set, rdomain.Scenario{
			ID: sc.ID, Digest: digest, Tier: rdomain.TierCommunity, Category: sc.Category, Suite: sc.Suite, Title: sc.Title, StepCount: len(sc.Steps),
			Origin: rdomain.OriginLibrary, // the runner's claim, which the server drops
		})
	}
	if len(set) != 5 {
		t.Fatalf("%d seed scenarios, want 5", len(set))
	}
	r, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: set, RunnerVersion: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Origin != rdomain.OriginCustomer {
		t.Fatalf("range origin %q, want customer", r.Origin)
	}
	for _, sc := range r.Scenarios {
		if sc.Origin != rdomain.OriginCustomer || sc.Tier != rdomain.TierBusiness {
			t.Errorf("%s: origin %q tier %q, want customer business", sc.ID, sc.Origin, sc.Tier)
		}
	}
	if _, err := w.svc.FinishRange(dev, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.ExportAssuranceReport(w.ctx, r.ID); !errors.Is(err, app.ErrNotAttested) {
		t.Fatalf("export of a range of Hub scenarios: %v, want RANGE_CUSTOMER_NOT_ATTESTED", err)
	}
	if len(w.f.exported) != 0 {
		t.Fatal("a range of Hub scenarios was exported")
	}
	e, ok := library.Lookup("RT-001")
	if !ok {
		t.Fatal("no RT-001")
	}
	mixed := []rdomain.Scenario{{ID: "RT-001", Digest: e.Digest, Tier: e.Tier, Category: "boundary", Suite: "coding-agent", Title: "RT-001", StepCount: 1}, set[0]}
	if _, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: mixed, RunnerVersion: "t"}); !errors.Is(err, app.ErrMixed) {
		t.Fatalf("a Hub scenario in a library range: %v, want RANGE_ORIGIN_MIXED", err)
	}
}
