// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package bundle_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/compliance/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
)

const (
	periodStart = "2026-10-01T00:00:00Z"
	periodEnd   = "2026-11-01T00:00:00Z"
)

// goodReport is a report of one real receipt, derived by the real rule.
func goodReport(t *testing.T, org string) domain.Report {
	t.Helper()
	in := domain.Inputs{
		Sources: []domain.SourceCount{
			{Source: domain.SourceReceipts, Readable: true, Real: 1, Refs: []domain.Ref{{Type: domain.RefTransaction, ID: packTxn}}},
			{Source: domain.SourceApprovals, Readable: false, Refs: []domain.Ref{}},
			{Source: domain.SourceGrants, Readable: true, Real: 2, Refs: []domain.Ref{{Type: domain.RefGrant, ID: "g"}}},
			{Source: domain.SourceCoverage, Readable: true, Refs: []domain.Ref{}},
			{Source: domain.SourceRange, Readable: true, Simulated: 1, Refs: []domain.Ref{{Type: domain.RefRange, ID: "r", Simulated: true}}},
			{Source: domain.SourceCampaign, Readable: true, Refs: []domain.Ref{}},
		},
		Tests:  []domain.TestCount{{Tag: "ASI01", Source: domain.SourceRange, Held: 1, Refs: []domain.Ref{}}},
		Stated: []domain.StatedCount{},
	}
	controls, err := domain.Evaluate(domain.OWASPASI, in)
	if err != nil {
		t.Fatal(err)
	}
	return domain.Report{
		Format: domain.Format, Org: org, Framework: domain.OWASPASI, CatalogDigest: domain.CatalogDigest(domain.OWASPASI),
		PeriodStart: periodStart, PeriodEnd: periodEnd, Split: domain.SplitOf(in), Inputs: in, Controls: controls,
		Statement: pack.ComplianceStatement,
	}
}

// compliancePack builds a signed pack around goodReport, changed by edit, with
// a receipt that says simulated.
func compliancePack(t *testing.T, k *packKit, simulated string, edit func(*domain.Report, *pack.Manifest)) []byte {
	t.Helper()
	return k.build(false, func(m *pack.Manifest, files []pack.File) []pack.File {
		m.Scope = pack.Scope{Kind: pack.ScopeCompliance, From: periodStart, To: periodEnd}
		m.Statement = pack.ComplianceStatement
		m.Include = pack.Include{Receipts: true}
		rep := goodReport(t, m.Org)
		if edit != nil {
			edit(&rep, m)
		}
		data, err := pack.Canonical(rep)
		if err != nil {
			t.Fatal(err)
		}
		txn := `{"id":"` + packTxn + `","agent":"a","decisions":[{"evaluation":1,"receipt":"` + receipt("ALLOW", "OK", simulated, false) + `"}]}`
		return []pack.File{
			{Path: pack.CompliancePath, Kind: pack.KindCompliance, Data: data},
			{Path: "transactions/" + packTxn + ".json", Kind: pack.KindTransaction, Data: []byte(txn)},
			files[1],
		}
	})
}

func verifyCompliancePack(t *testing.T, simulated string, edit func(*domain.Report, *pack.Manifest)) *bundle.Report {
	t.Helper()
	k := newPackKit(t)
	return bundle.VerifyPack(compliancePack(t, k, simulated, edit), bundle.Options{Trust: k.trust})
}

// TestHR604_VerifyReDerivesTheReport: a signed report verifies offline, its
// states follow from its inputs, its cited transaction is in the pack, and
// the records a pack does not hold are listed as such.
// Covers: F895
func TestHR604_VerifyReDerivesTheReport(t *testing.T) {
	r := verifyCompliancePack(t, "", nil)
	for _, name := range []string{"pack.signature", "pack.items", "pack.statement", "compliance.report", "compliance.inputs", "compliance.controls", "compliance.refs"} {
		if got := statusOf(r, name); got != bundle.Passed {
			t.Errorf("%s = %q, want passed:\n%+v", name, got, r.Checks)
		}
	}
	if got := statusOf(r, "compliance.server_records"); got != bundle.NotAvailable {
		t.Errorf("server records = %q", got)
	}
}

// TestHR600_ACompliancePackCarriesItsOwnStatement: the manifest and the
// report each carry the fixed statement; the general one fails.
// Covers: F894
func TestHR600_ACompliancePackCarriesItsOwnStatement(t *testing.T) {
	r := verifyCompliancePack(t, "", nil)
	if r.Limits != bundle.Limits+" "+pack.ComplianceStatement {
		t.Errorf("limits: %s", r.Limits)
	}
	r = verifyCompliancePack(t, "", func(_ *domain.Report, m *pack.Manifest) { m.Statement = pack.Statement })
	if got := statusOf(r, "pack.statement"); got != bundle.Failed {
		t.Errorf("the general statement on a compliance pack = %q", got)
	}
	r = verifyCompliancePack(t, "", func(rep *domain.Report, _ *pack.Manifest) { rep.Statement = "We are in good shape." })
	if got := statusOf(r, "compliance.report"); got != bundle.Failed {
		t.Errorf("another statement in the report = %q", got)
	}
}

// TestHR604_AChangedStateFails: each way a report can say more than its
// inputs do fails offline.
// Covers: F895
func TestHR604_AChangedStateFails(t *testing.T) {
	asi05 := func(r *domain.Report) *domain.ControlResult {
		return &r.Controls[slices.IndexFunc(r.Controls, func(c domain.ControlResult) bool { return c.ID == "ASI05" })]
	}
	cases := []struct {
		name  string
		edit  func(*domain.Report, *pack.Manifest)
		check string
	}{
		{"a gap made evidenced", func(r *domain.Report, _ *pack.Manifest) { asi05(r).State = domain.Evidenced }, "compliance.controls"},
		{"a gap dropped", func(r *domain.Report, _ *pack.Manifest) { asi05(r).Gaps = []domain.ControlGap{} }, "compliance.controls"},
		{"a control dropped", func(r *domain.Report, _ *pack.Manifest) { r.Controls = r.Controls[1:] }, "compliance.controls"},
		{"counts raised over the states", func(r *domain.Report, _ *pack.Manifest) {
			r.Inputs.Sources[3].Real = 9
		}, "compliance.controls"},
		{"the split changed", func(r *domain.Report, _ *pack.Manifest) { r.Split.Simulated = 40 }, "compliance.inputs"},
		{"an unreadable source with records", func(r *domain.Report, _ *pack.Manifest) { r.Inputs.Sources[1].Real = 3 }, "compliance.inputs"},
		{"a test counted as real", func(r *domain.Report, _ *pack.Manifest) { r.Inputs.Sources[4].Real = 1 }, "compliance.inputs"},
		{"counts citing nothing", func(r *domain.Report, _ *pack.Manifest) { r.Inputs.Sources[0].Refs = []domain.Ref{} }, "compliance.inputs"},
		{"another period", func(r *domain.Report, _ *pack.Manifest) { r.PeriodEnd = "2027-01-01T00:00:00Z" }, "compliance.report"},
		{"another org", func(r *domain.Report, _ *pack.Manifest) { r.Org = "other" }, "compliance.report"},
		{"no receipts", func(_ *domain.Report, m *pack.Manifest) { m.Include.Receipts = false }, "compliance.report"},
		{"a cited transaction missing", func(r *domain.Report, _ *pack.Manifest) {
			r.Inputs.Sources[0].Refs = []domain.Ref{{Type: domain.RefTransaction, ID: "0192aaaa-bbbb-7ccc-8ddd-000000000099"}}
		}, "compliance.ref"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := verifyCompliancePack(t, "", c.edit)
			if got := statusOf(r, c.check); got != bundle.Failed {
				t.Errorf("%s = %q:\n%+v", c.check, got, r.Checks)
			}
		})
	}
}

// TestHR602_ARelabelledReceiptFailsVerify: a simulated transaction cited as
// real fails against its own receipt, and so does the reverse.
// Covers: F895
func TestHR602_ARelabelledReceiptFailsVerify(t *testing.T) {
	if got := statusOf(verifyCompliancePack(t, simTrue, nil), "compliance.ref"); got != bundle.Failed {
		t.Errorf("simulated cited as real = %q", got)
	}
	r := verifyCompliancePack(t, simFalse, func(rep *domain.Report, _ *pack.Manifest) {
		rep.Inputs.Sources[0].Refs[0].Simulated = true
	})
	if got := statusOf(r, "compliance.ref"); got != bundle.Failed {
		t.Errorf("real cited as simulated = %q", got)
	}
}

// TestT258_TamperedReportFailsVerify: compliance.json changed after signing
// fails on its digest, and a pack with no report fails.
// Covers: F895
func TestT258_TamperedReportFailsVerify(t *testing.T) {
	k := newPackKit(t)
	good := compliancePack(t, k, "", nil)
	files, err := pack.Read(good)
	if err != nil {
		t.Fatal(err)
	}
	before := files[pack.CompliancePath]
	after := bytes.Replace(before, []byte(`"state":"GAP"`), []byte(`"state":"EVIDENCED"`), 1)
	if bytes.Equal(before, after) {
		t.Fatal("the report holds no gap")
	}
	r := bundle.VerifyPack(repack(t, good, pack.CompliancePath, after), bundle.Options{Trust: k.trust})
	if got := statusOf(r, "pack.item"); got != bundle.Failed {
		t.Errorf("tampered report: pack.item = %q", got)
	}
	// The framework lives only in compliance.json, which the manifest's
	// digest covers: renaming it after signing fails the same way.
	renamed := bytes.Replace(before, []byte(`"framework":"OWASP_ASI"`), []byte(`"framework":"NIST_AI_RMF"`), 1)
	if bytes.Equal(before, renamed) {
		t.Fatal("the report names no framework")
	}
	r = bundle.VerifyPack(repack(t, good, pack.CompliancePath, renamed), bundle.Options{Trust: k.trust})
	if got := statusOf(r, "pack.item"); got != bundle.Failed {
		t.Errorf("another framework after signing: pack.item = %q", got)
	}
	// Signed under another framework's name, the table no longer matches.
	r = verifyCompliancePack(t, "", func(rep *domain.Report, _ *pack.Manifest) { rep.Framework = domain.NISTAIRMF })
	if got := statusOf(r, "compliance.controls"); got == bundle.Passed {
		t.Errorf("a report signed under another framework's name: compliance.controls = %q", got)
	}
	none := k.build(false, func(m *pack.Manifest, files []pack.File) []pack.File {
		m.Scope, m.Statement = pack.Scope{Kind: pack.ScopeCompliance, From: periodStart, To: periodEnd}, pack.ComplianceStatement
		return files
	})
	if got := statusOf(bundle.VerifyPack(none, bundle.Options{Trust: k.trust}), "compliance.report"); got != bundle.Failed {
		t.Errorf("no report = %q", got)
	}
}

// TestHR604_AnotherTableIsNotPassed: a report under a table this pclaw does
// not have says so rather than passing.
// Covers: F895
func TestHR604_AnotherTableIsNotPassed(t *testing.T) {
	r := verifyCompliancePack(t, "", func(rep *domain.Report, _ *pack.Manifest) { rep.CatalogDigest = "other" })
	if got := statusOf(r, "compliance.controls"); got != bundle.NotAvailable {
		t.Errorf("another table = %q", got)
	}
}
