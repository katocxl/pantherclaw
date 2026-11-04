// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
)

// goodThreatReport evaluates the shipped ATLAS mapping for an org with
// every edition, an agent with an enforced route, and every built-in rule
// live but one off.
func goodThreatReport(org string) domain.Report {
	at := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	f := catalog.FrameworkATLAS
	m := mapset.Evaluator(f)
	in := domain.Inputs{
		Framework: f, EvaluatedAt: at, ContentMode: "WATCHING",
		Editions: domain.Editions{
			AdvancedDetections: true, CustomDetections: true, BehaviorAnalytics: true, ContentSignals: true,
			Automations: true, AutomationPlaybooks: true,
		},
		Agents: []domain.Agent{{ID: "a1", Name: "builder", Active: true, LastRealTransaction: at.Add(-time.Hour)}},
		Routes: []domain.Route{{AgentID: "a1", ConnectionID: "c1", Operation: "repo.write", State: "ENFORCED", ExpiresAt: at.Add(time.Hour)}},
		Cursor: domain.Cursor{CaughtUp: true, AdvancedAt: at.Add(-time.Minute)},
	}
	off := false
	for id := range m.Builtins {
		r := domain.Rule{ID: id, Source: domain.SourceBuiltin, Published: true, LastInputAt: at.Add(-time.Hour)}
		if !off {
			r.Disabled, r.DisabledAt, off = true, at.Add(-20*24*time.Hour), true
		}
		in.Rules = append(in.Rules, r)
	}
	return domain.NewReport(org, domain.Evaluate(catalog.Load(f), m, in), in, m)
}

// threatMapPack builds a signed threat map pack around goodThreatReport,
// changed by edit before signing.
func threatMapPack(t *testing.T, k *packKit, edit func(*domain.Report, *pack.Manifest)) []byte {
	t.Helper()
	return k.build(false, func(m *pack.Manifest, files []pack.File) []pack.File {
		m.Scope = pack.Scope{Kind: pack.ScopeThreatMap}
		m.Statement = pack.ThreatMapStatement
		m.Include = pack.Include{}
		m.Transactions, m.EffectStates = []pack.TransactionState{}, map[string]int{}
		rep := goodThreatReport(m.Org)
		if edit != nil {
			edit(&rep, m)
		}
		data, err := pack.Canonical(rep)
		if err != nil {
			t.Fatal(err)
		}
		return []pack.File{{Path: pack.ThreatMapPath, Kind: pack.KindThreatMap, Data: data}, files[1]}
	})
}

func verifyThreatMapPack(t *testing.T, edit func(*domain.Report, *pack.Manifest)) *bundle.Report {
	t.Helper()
	k := newPackKit(t)
	return bundle.VerifyPack(threatMapPack(t, k, edit), bundle.Options{Trust: k.trust})
}

// TestHR688_VerifyReDerivesTheThreatMap: a signed threat map report
// verifies offline: signature, statement, header, and every technique and
// tactic count re-derived from its own inputs and mapping (G0 M28 D720).
// Covers: F968, HR-688
func TestHR688_VerifyReDerivesTheThreatMap(t *testing.T) {
	r := verifyThreatMapPack(t, nil)
	for _, name := range []string{"pack.signature", "pack.items", "pack.statement", "threatmap.report", "threatmap.mapping", "threatmap.lanes"} {
		if got := statusOf(r, name); got != bundle.Passed {
			t.Errorf("%s = %q, want passed:\n%+v", name, got, r.Checks)
		}
	}
	if r.Limits != bundle.Limits+" "+domain.Statement {
		t.Errorf("limits: %s", r.Limits)
	}
}

// TestHR688_AThreatMapThatSaysMoreThanItsInputsFails: each way a signed
// report can show more than its own inputs and mapping give fails, and a
// report of another MITRE catalog or PantherClaw mapping is not re-derived
// (D720, D720e).
// Covers: F968, HR-688, HR-680
func TestHR688_AThreatMapThatSaysMoreThanItsInputsFails(t *testing.T) {
	for _, tc := range []struct {
		name, check string
		want        bundle.Status
		edit        func(*domain.Report, *pack.Manifest)
	}{
		{"a technique's status", "threatmap.lanes", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) {
			r.Techniques[0].Status = flipStatus(r.Techniques[0].Status)
		}},
		{"a lane", "threatmap.lanes", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) {
			r.Techniques[1].Detect = flipLane(r.Techniques[1].Detect)
		}},
		{"a gap left out", "threatmap.lanes", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) {
			for i := range r.Techniques {
				if len(r.Techniques[i].Gaps) > 0 {
					r.Techniques[i].Gaps = []domain.Gap{}
					return
				}
			}
			t.Fatal("no technique with a gap")
		}},
		{"a tactic count", "threatmap.lanes", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) { r.Tactics[0].Counts.Evidenced++ }},
		{"an input changed under the lanes", "threatmap.lanes", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) {
			// Without its enforced route, no Prevent control is acting.
			r.Inputs.Routes = []domain.Route{}
		}},
		{"a mapping widened under the shipped digest", "threatmap.mapping", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) {
			for i := range r.Techniques {
				if r.Techniques[i].Prevent != domain.LaneNoneShipped || r.Techniques[i].Status == domain.StatusOutside {
					continue
				}
				id := r.Techniques[i].ID
				tm := r.Mapping.Techniques[id]
				if tm.Outside != nil || tm.Unaddressed != nil {
					continue
				}
				tm.Prevent = append(tm.Prevent, r.Mapping.Controls[0].ID)
				r.Mapping.Techniques[id] = tm
				return
			}
			t.Fatal("no technique without a Prevent control")
		}},
		{"another org", "threatmap.report", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) { r.Org = "0192aaaa-bbbb-7ccc-8ddd-000000000099" }},
		{"another statement", "threatmap.report", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) { r.Statement = "Every technique is handled." }},
		{"the general statement on the manifest", "pack.statement", bundle.Failed, func(_ *domain.Report, m *pack.Manifest) { m.Statement = pack.Statement }},
		{"a header that is not its inputs'", "threatmap.report", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) { r.Inputs.Scope.EnvironmentID = "e1" }},
		{"another mapping digest", "threatmap.report", bundle.Failed, func(r *domain.Report, _ *pack.Manifest) { r.MappingDigest = "00" }},
		{"built with another PantherClaw mapping", "threatmap.mapping", bundle.NotAvailable, func(r *domain.Report, _ *pack.Manifest) {
			// Consistent with itself, under a digest this build does not ship
			// (D720e).
			r.MappingDigest, r.Mapping.Digest = "00", "00"
		}},
		{"another catalog", "threatmap.lanes", bundle.NotAvailable, func(r *domain.Report, _ *pack.Manifest) { r.Catalog.Digest = "00" }},
		{"an unknown framework", "threatmap.mapping", bundle.NotAvailable, func(r *domain.Report, _ *pack.Manifest) {
			r.Framework, r.Inputs.Framework = "capec", "capec"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := verifyThreatMapPack(t, tc.edit)
			if got := statusOf(r, tc.check); got != tc.want {
				t.Errorf("%s = %q, want %q:\n%+v", tc.check, got, tc.want, r.Checks)
			}
		})
	}
}

// TestT302_AThreatMapEditedAfterSigningFails: a report changed after the
// manifest was signed no longer matches the signed digest, and a threat map
// manifest listing no report fails (D720).
// Covers: F968, HR-688, T-302
func TestT302_AThreatMapEditedAfterSigningFails(t *testing.T) {
	k := newPackKit(t)
	var org string
	raw := threatMapPack(t, k, func(_ *domain.Report, m *pack.Manifest) { org = m.Org })
	if got := statusOf(bundle.VerifyPack(raw, bundle.Options{Trust: k.trust}), "threatmap.lanes"); got != bundle.Passed {
		t.Fatalf("unedited = %q", got)
	}
	edited := goodThreatReport(org)
	edited.Techniques[0].Status = flipStatus(edited.Techniques[0].Status)
	data, err := pack.Canonical(edited)
	if err != nil {
		t.Fatal(err)
	}
	r := bundle.VerifyPack(repack(t, raw, pack.ThreatMapPath, data), bundle.Options{Trust: k.trust})
	if got := statusOf(r, "pack.item"); got != bundle.Failed {
		t.Errorf("an edited report: pack.item = %q:\n%+v", got, r.Checks)
	}
	none := k.build(false, func(m *pack.Manifest, files []pack.File) []pack.File {
		m.Scope, m.Statement = pack.Scope{Kind: pack.ScopeThreatMap}, pack.ThreatMapStatement
		return files
	})
	if got := statusOf(bundle.VerifyPack(none, bundle.Options{Trust: k.trust}), "threatmap.report"); got != bundle.Failed {
		t.Errorf("a threat map pack without its report = %q", got)
	}
}

func flipStatus(s domain.Status) domain.Status {
	if s == domain.StatusEvidenced {
		return domain.StatusGap
	}
	return domain.StatusEvidenced
}

func flipLane(s domain.LaneState) domain.LaneState {
	if s == domain.LaneEvidenced {
		return domain.LaneGap
	}
	return domain.LaneEvidenced
}
