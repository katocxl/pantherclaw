// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/adapters/pgthreatmap"
	tmapp "github.com/katocxl/pantherclaw/internal/threatmap/app"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
)

// threatMaps wires the threat map into the pack world (G0 M28 D720).
func (p *packWorld) threatMaps() {
	tm := &tmapp.Service{Pool: p.pool, Ents: p.edition, Store: pgthreatmap.Store{}}
	p.svc.WithThreatMap(tm)
	p.builder.ThreatMap = tm
}

// TestHR688_AThreatMapPackIsBuiltAndVerifiesOffline: a pack of scope
// threat_map holds the creator's threat map report with the threat map's
// own statement and nothing else, and verifies offline with every lane
// re-derived; the framework and environment are kept on the pack's row; an
// environment the org does not have is not found, and Community cannot ask
// (G0 M28 D720, D720a).
// Covers: F968, HR-688, T-305
func TestHR688_AThreatMapPackIsBuiltAndVerifiesOffline(t *testing.T) {
	w := newWorld(t)
	p := w.packs(billing.Team)
	p.threatMaps()
	auditor := p.person("auditor", td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: p.org.UUID()})

	pk := p.create(auditor, evapp.PackRequest{Kind: pack.ScopeThreatMap, ThreatFramework: "atlas"})
	var row string
	w.db.AdminQueryRow(t, "SELECT threat_framework || ' ' || coalesce(threat_environment::text, '-') FROM pc.evidence_packs WHERE id = $1",
		[]any{pk.ID}, &row)
	if row != "atlas -" {
		t.Fatalf("row: %q", row)
	}
	raw := p.download(auditor, pk.ID)
	m := manifestOf(t, raw)
	if m.Scope.Kind != pack.ScopeThreatMap || m.Statement != domain.Statement || len(m.Transactions) != 0 || m.Include != (pack.Include{}) {
		t.Fatalf("manifest: %+v", m)
	}
	r := bundle.VerifyPack(raw, bundle.Options{Trust: p.trust()})
	if r.Failed() {
		t.Fatalf("verify: %+v", r.Checks)
	}
	for _, c := range r.Checks {
		if (c.Name == "threatmap.report" || c.Name == "threatmap.lanes") && c.Status != bundle.Passed {
			t.Errorf("%s = %s: %s", c.Name, c.Status, c.Detail)
		}
	}

	_, err := p.svc.CreateEvidencePack(auditor, evapp.PackRequest{Kind: pack.ScopeThreatMap, ThreatFramework: "attack-enterprise", ThreatEnvironment: ids.NewV7()})
	if pcerr.CodeOf(err) != pcerr.NotFound {
		t.Errorf("an environment the org does not have: %v", err)
	}
	if _, err := p.svc.CreateEvidencePack(auditor, evapp.PackRequest{Kind: pack.ScopeThreatMap, ThreatFramework: "capec"}); pcerr.CodeOf(err) != pcerr.InvalidArgument {
		t.Errorf("an unknown framework: %v", err)
	}
	p.edition.ed = billing.Community
	if _, err := p.svc.CreateEvidencePack(auditor, evapp.PackRequest{Kind: pack.ScopeThreatMap, ThreatFramework: "atlas"}); pcerr.CodeOf(err) != pcerr.FailedPrecondition {
		t.Errorf("Community: %v", err)
	}
}
