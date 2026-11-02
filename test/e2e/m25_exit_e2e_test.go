// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	cdomain "github.com/katocxl/pantherclaw/internal/campaigns/domain"
	cports "github.com/katocxl/pantherclaw/internal/campaigns/ports"
	"github.com/katocxl/pantherclaw/internal/compliance/adapters/campaignresults"
	coapp "github.com/katocxl/pantherclaw/internal/compliance/app"
	"github.com/katocxl/pantherclaw/internal/compliance/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// oneCampaign is one finished campaign, standing in for the campaign store
// until the campaign exit runs one for real.
type oneCampaign struct{ id ids.UUID }

func (c oneCampaign) CampaignResults(context.Context, ids.OrgID, cports.Filter) (cports.Results, error) {
	return cports.Results{Items: []cports.Result{{
		Campaign: cdomain.Campaign{ID: c.id, State: cdomain.Finished},
		Steps: []cdomain.Step{
			{Scenario: "RT-001", ID: "merge", Outcome: cdomain.Held, Basis: cdomain.ServerRecord},
			{Scenario: "RT-006", ID: "route", Outcome: cdomain.NotRoutedReported, Basis: cdomain.EdgeReport},
		},
	}}}, nil
}

// TestE2E_M25_ComplianceReportOnSimulators is M25's exit: a range runs against
// the simulators, an auditor exports a signed OWASP report of the period, and
// `pclaw verify` re-derives it offline. The report shows its gaps, labels all
// of its activity simulated, carries its own statement, and the same period
// exported again gives the same digest (G0 M25 D300-D304, D312).
// Covers: F894, F895, F896, F899
func TestE2E_M25_ComplianceReportOnSimulators(t *testing.T) {
	from := time.Now().UTC().Add(-time.Minute)
	r := startRangeStack(t)
	s := r.d.s
	code, out, errs, _ := r.run(t, scenarioDir(t, "RT-001", "RT-006", "RT-019"))
	if code != 0 {
		t.Fatalf("the range: %d\n%s\n%s", code, out, errs)
	}
	to := time.Now().UTC().Add(time.Minute)

	p := s.proof(t)
	ctx := context.Background()
	svc := app.New(s.pool, p.origin).WithPacks(func(context.Context, db.TenantTx, ids.OrgID, ids.UUID) error { return nil }, teamEdition{})
	campaign := ids.NewV7()
	builder := &packbuild.Service{
		Pool: s.pool, Keys: p.reg, LogOrigin: p.origin, Explorer: &txapp.Explorer{Pool: s.pool}, Bundles: app.New(s.pool, p.origin),
		Log: pclog.Discard(),
		Compliance: &coapp.Service{Pool: s.pool, Ents: teamEdition{}, Campaigns: campaignresults.Reader{
			Results: oneCampaign{campaign}, Tags: campaignresults.LibraryTags,
		}},
	}
	auditor := s.boundAuditor(t, "compliance-auditor")
	export := func(name string) (string, map[string][]byte) {
		pk, err := svc.CreateEvidencePack(auditor, app.PackRequest{Kind: pack.ScopeCompliance, Framework: string(domain.OWASPASI), From: from, To: to})
		if err != nil {
			t.Fatalf("create the report: %v", err)
		}
		if err := builder.Build(ctx, s.org, pk.ID); err != nil {
			t.Fatal(err)
		}
		d, err := svc.DownloadEvidencePack(auditor, pk.ID)
		if err != nil {
			t.Fatal(err)
		}
		files, err := pack.Read(d.Content)
		if err != nil {
			t.Fatal(err)
		}
		return writeFile(t, p.dir, name, d.Content), files
	}

	file, files := export("compliance.zip")
	code, rep := p.verify(t, file)
	if code != 0 {
		t.Fatalf("pclaw verify: exit %d\n%+v", code, rep.Checks)
	}
	for _, name := range []string{"compliance.report", "compliance.inputs", "compliance.controls", "compliance.refs"} {
		if got := statuses(rep, name); len(got) == 0 || slices.Contains(got, bundle.Failed) || got[0] != bundle.Passed {
			t.Errorf("%s: %v", name, got)
		}
	}

	report, err := domain.Decode(files[pack.CompliancePath])
	if err != nil {
		t.Fatal(err)
	}
	if report.Statement != pack.ComplianceStatement {
		t.Errorf("statement: %q", report.Statement)
	}
	if report.Split.Simulated == 0 {
		t.Errorf("no simulated activity in the split: %+v", report.Split)
	}
	state := func(id string) domain.State {
		i := slices.IndexFunc(report.Controls, func(c domain.ControlResult) bool { return c.ID == id })
		if i < 0 {
			t.Fatalf("no control %s", id)
		}
		return report.Controls[i].State
	}
	for _, id := range []string{"ASI05", "ASI06"} {
		if got := state(id); got != domain.Gap {
			t.Errorf("%s = %s, want a gap", id, got)
		}
	}
	for _, c := range report.Controls {
		if c.State == domain.Evidenced && report.Split.Real == 0 {
			t.Errorf("%s is evidenced by simulators alone", c.ID)
		}
	}
	test := func(tag string, src domain.Source) domain.TestCount {
		for _, c := range report.Inputs.Tests {
			if c.Tag == tag && c.Source == src {
				return c
			}
		}
		return domain.TestCount{}
	}
	if got := test("ASI02", domain.SourceRange); got.Held == 0 {
		t.Errorf("the range's held scenario is not counted: %+v", report.Inputs.Tests)
	}
	if got := test("ASI02", domain.SourceCampaign); got.Held != 1 {
		t.Errorf("the campaign's held step: %+v", got)
	}
	if got := test("ASI03", domain.SourceCampaign); got.Reported != 1 || got.Held != 0 {
		t.Errorf("an edge report counted as more than a report: %+v", got)
	}

	// The same records under the same parameters, exported again.
	again, more := export("compliance-again.zip")
	if !bytes.Equal(files[pack.CompliancePath], more[pack.CompliancePath]) {
		t.Errorf("a re-export changed the report:\n%s\n%s", files[pack.CompliancePath], more[pack.CompliancePath])
	}
	if code, rep := p.verify(t, again); code != 0 {
		t.Fatalf("pclaw verify of the re-export: exit %d\n%+v", code, rep.Checks)
	}
}
