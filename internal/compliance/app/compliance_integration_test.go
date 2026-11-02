// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/compliance/app"
	"github.com/katocxl/pantherclaw/internal/compliance/domain"
	"github.com/katocxl/pantherclaw/internal/compliance/ports"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

type fakeCampaigns []ports.CampaignStep

func (f fakeCampaigns) CampaignSteps(context.Context, ids.OrgID, time.Time, time.Time) ([]ports.CampaignStep, bool, error) {
	return f, false, nil
}

func as(o *exposuretest.Org, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User}, Bindings: bs,
	}})
}

func period() (time.Time, time.Time) {
	now := time.Now().UTC()
	return now.Add(-time.Hour), now.Add(time.Hour)
}

func service(o *exposuretest.Org, ed billing.Edition) *app.Service {
	return &app.Service{Pool: o.P, Ents: edition(ed)}
}

func sourceOf(t *testing.T, r domain.Report, s domain.Source) domain.SourceCount {
	t.Helper()
	i := slices.IndexFunc(r.Inputs.Sources, func(c domain.SourceCount) bool { return c.Source == s })
	if i < 0 {
		t.Fatalf("no source %s", s)
	}
	return r.Inputs.Sources[i]
}

func controlOf(t *testing.T, r domain.Report, id string) domain.ControlResult {
	t.Helper()
	i := slices.IndexFunc(r.Controls, func(c domain.ControlResult) bool { return c.ID == id })
	if i < 0 {
		t.Fatalf("no control %s", id)
	}
	return r.Controls[i]
}

// finishedRange stores a finished range with the given results, as the
// server would have (pc_app may not write a FINISHED range in one step).
func finishedRange(t *testing.T, o *exposuretest.Org, origin string, results map[string]rangeResult) ids.UUID {
	t.Helper()
	agent, id := ids.NewV7(), ids.NewV7()
	o.D.AdminExec(t, `INSERT INTO pc.agents (org_id, id, name, state, created_by, range_agent) VALUES ($1, $2, $3, 'DISCOVERED', 'test', true)`,
		o.Org, agent, "range-"+id.String()[:8])
	var scenarios []map[string]any
	for sid, r := range results {
		scenarios = append(scenarios, map[string]any{"id": sid, "digest": r.digest, "tier": "community", "category": "boundary",
			"suite": "coding-agent", "title": sid, "step_count": 1})
	}
	raw, err := json.Marshal(scenarios)
	if err != nil {
		t.Fatal(err)
	}
	o.D.AdminExec(t, `INSERT INTO pc.redteam_runs (org_id, id, range_agent_id, started_by, runner_version, scenario_set_digest, scenarios,
		origin) VALUES ($1, $2, $3, 'test', 'test', repeat('a', 64), $4, $5)`, o.Org, id, agent, raw, origin)
	for sid, r := range results {
		steps := `[{"id":"s","observed_by":"` + r.observedBy + `","expect":{"outcome":"DENY"},"observed":{"outcome":"DENY"},"matched":true}]`
		o.D.AdminExec(t, `INSERT INTO pc.redteam_results (org_id, range_id, scenario_id, scenario_digest, suite, category, tier, verdict,
			steps, observed_by) VALUES ($1, $2, $3, $4, 'coding-agent', 'boundary', 'community', $5, $6, $7)`,
			o.Org, id, sid, r.digest, r.verdict, []byte(steps), r.observedBy)
	}
	o.D.AdminExec(t, `UPDATE pc.redteam_runs SET state = 'FINISHED', finished_at = now() WHERE org_id = $1 AND id = $2`, o.Org, id)
	return id
}

type rangeResult struct{ digest, verdict, observedBy string }

func tagged(t *testing.T, id, verdict, by string) rangeResult {
	t.Helper()
	e, ok := library.Lookup(id)
	if !ok || len(e.ASI) == 0 {
		t.Fatalf("%s has no tags", id)
	}
	return rangeResult{e.Digest, verdict, by}
}

// TestIntCoverageReadsTheOrgsRecords: real receipts and grants are counted,
// a stated field reads STATED, what never happened reads as a gap, and the
// counts come from the org's own rows.
// Covers: F892, F893
func TestIntCoverageReadsTheOrgsRecords(t *testing.T) {
	o := exposuretest.New(t)
	txn := o.Dispatch(t, "payments.refund.create")
	grant := o.Grant(t, o.Agent, 0, "", "payments.refund.create")
	o.D.AdminExec(t, `UPDATE pc.agents SET ai_act_role = 'DEPLOYER' WHERE org_id = $1 AND id = $2`, o.Org, o.Agent)
	start, end := period()
	ctx := as(o, td.RoleAuditor)
	r, err := service(o, billing.Business).GetFrameworkCoverage(ctx, domain.EUAIActDeployer, start, end)
	if err != nil {
		t.Fatal(err)
	}
	rec := sourceOf(t, r, domain.SourceReceipts)
	if rec.Real != 1 || rec.Simulated != 0 || len(rec.Refs) != 1 || rec.Refs[0].ID != txn.String() {
		t.Errorf("receipts: %+v", rec)
	}
	gr := sourceOf(t, r, domain.SourceGrants)
	if gr.Real != 1 || len(gr.Refs) != 1 || gr.Refs[0].ID != grant.String() {
		t.Errorf("grants: %+v", gr)
	}
	if got := controlOf(t, r, "ART-26-6"); got.State != domain.Evidenced {
		t.Errorf("logs: %+v", got)
	}
	if got := controlOf(t, r, "ART-26-2"); got.State != domain.Gap {
		t.Errorf("no approvals: %+v", got)
	}
	if got := controlOf(t, r, "ART-3-ROLE"); got.State != domain.Stated {
		t.Errorf("a stated role: %+v", got)
	}
	if got := controlOf(t, r, "ART-6-CLASS"); got.State != domain.Gap {
		t.Errorf("no stated risk: %+v", got)
	}
	if r.Split.Real != 2 || r.Statement == "" {
		t.Errorf("header: %+v %q", r.Split, r.Statement)
	}
	// Outside the period nothing counts.
	r, err = service(o, billing.Business).GetFrameworkCoverage(ctx, domain.EUAIActDeployer, start.Add(-48*time.Hour), start.Add(-47*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := sourceOf(t, r, domain.SourceReceipts); got.Real != 0 {
		t.Errorf("another period: %+v", got)
	}
}

// TestHR603_EachSourceNeedsItsOwnPermission: Org Admin holds compliance.read
// but not approval.read, and sees that as a gap that says so, never a zero.
// Covers: F893
func TestHR603_EachSourceNeedsItsOwnPermission(t *testing.T) {
	o := exposuretest.New(t)
	start, end := period()
	r, err := service(o, billing.Team).GetFrameworkCoverage(as(o, td.RoleOrgAdmin), domain.OWASPASI, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if got := sourceOf(t, r, domain.SourceApprovals); got.Readable {
		t.Fatalf("approvals readable by Org Admin: %+v", got)
	}
	gaps := controlOf(t, r, "ASI09").Gaps
	if !slices.ContainsFunc(gaps, func(g domain.ControlGap) bool { return g.Reason == domain.ReasonOutsidePermission }) {
		t.Errorf("ASI09: %+v", gaps)
	}
	if _, err := service(o, billing.Team).GetFrameworkCoverage(as(o, td.RoleDeveloper), domain.OWASPASI, start, end); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Errorf("no compliance.read: %v", err)
	}
	if _, err := service(o, billing.Team).ListFrameworks(as(o, td.RoleDeveloper)); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Errorf("no compliance.read, list: %v", err)
	}
}

// TestT259_NarrowReaderSeesGapsNotCounts: a reader with no evidence.read at
// org scope learns nothing of the org's receipts from a report.
// Covers: F893
func TestT259_NarrowReaderSeesGapsNotCounts(t *testing.T) {
	o := exposuretest.New(t)
	o.Dispatch(t, "payments.refund.create")
	team := o.Claim(t, o.Agent)
	ctx := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User},
		Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeTeam, ID: team}}},
	}})
	start, end := period()
	r, err := service(o, billing.Team).Report(ctx, domain.OWASPASI, start, end)
	if err != nil {
		t.Fatal(err)
	}
	got := sourceOf(t, r, domain.SourceReceipts)
	if got.Readable || got.Real != 0 || len(got.Refs) != 0 {
		t.Fatalf("a team reader read the org's receipts: %+v", got)
	}
	if st := controlOf(t, r, "ASI01"); st.State != domain.Gap {
		t.Errorf("ASI01: %+v", st)
	}
}

// TestHR605_EditionGatesCoverageAndExport: the framework's edition is checked
// before anything is read; Team reads OWASP and not ISO.
// Covers: F897
func TestHR605_EditionGatesCoverageAndExport(t *testing.T) {
	o := exposuretest.New(t)
	start, end := period()
	ctx := as(o, td.RoleAuditor)
	if _, err := service(o, billing.Team).GetFrameworkCoverage(ctx, domain.OWASPASI, start, end); err != nil {
		t.Errorf("OWASP on Team: %v", err)
	}
	if _, err := service(o, billing.Team).GetFrameworkCoverage(ctx, domain.ISO42001, start, end); !errors.Is(err, app.ErrEdition) {
		t.Errorf("ISO on Team: %v", err)
	}
	if _, err := service(o, billing.Community).GetFrameworkCoverage(ctx, domain.OWASPASI, start, end); !errors.Is(err, app.ErrEdition) {
		t.Errorf("OWASP on Community: %v", err)
	}
	if _, err := service(o, billing.Enterprise).GetFrameworkCoverage(ctx, "DORA", start, end); !errors.Is(err, app.ErrUnknown) {
		t.Errorf("an unlisted framework: %v", err)
	}
	if _, err := service(o, billing.Team).GetFrameworkCoverage(ctx, domain.OWASPASI, end, start); !errors.Is(err, app.ErrBadPeriod) {
		t.Errorf("a backward period: %v", err)
	}
	list, err := service(o, billing.Team).ListFrameworks(ctx)
	if err != nil || len(list) != 5 {
		t.Fatalf("list: %v %v", list, err)
	}
	for _, f := range list {
		want := f.Framework == domain.OWASPASI || f.Framework == domain.NISTAIRMF
		if f.Available != want || f.Controls == 0 {
			t.Errorf("%+v", f)
		}
	}
}

// TestT260_ClaimsNeverBecomeTestEvidence: a PASS the server saw counts; a PASS
// the runner alone reported is a report; a customer range, and a result whose
// digest is not the library's, count for nothing.
// Covers: F893, F898
func TestT260_ClaimsNeverBecomeTestEvidence(t *testing.T) {
	o := exposuretest.New(t)
	finishedRange(t, o, "library", map[string]rangeResult{
		"RT-001": tagged(t, "RT-001", "PASS", "SERVER"),                                  // ASI02: held
		"RT-012": tagged(t, "RT-012", "PASS", "CLIENT"),                                  // ASI03: a report
		"RT-028": tagged(t, "RT-028", "FAIL", "SERVER"),                                  // ASI04: failed
		"RT-049": tagged(t, "RT-049", "SKIPPED", "CLIENT"),                               // ASI07: not exercised
		"RT-045": {"0000000000000000000000000000000000000000000000000000000000000000", "PASS", "SERVER"}, // ASI09: not the library's
	})
	start, end := period()
	s := service(o, billing.Team)
	s.Campaigns = fakeCampaigns{
		{Campaign: ids.NewV7(), Tags: []string{"ASI10"}, Outcome: ports.OutcomeHeld},
		{Campaign: ids.NewV7(), Tags: []string{"ASI01"}, Outcome: ports.OutcomeNotRoutedReported},
		{Campaign: ids.NewV7(), Tags: []string{"ASI08"}, Outcome: ports.OutcomeAllowed},
	}
	r, err := s.Report(as(o, td.RoleAuditor), domain.OWASPASI, start, end)
	if err != nil {
		t.Fatal(err)
	}
	has := func(id, reason string) bool {
		return slices.ContainsFunc(controlOf(t, r, id).Gaps, func(g domain.ControlGap) bool { return g.Reason == reason })
	}
	test := func(tag string, src domain.Source) domain.TestCount {
		i := slices.IndexFunc(r.Inputs.Tests, func(c domain.TestCount) bool { return c.Tag == tag && c.Source == src })
		if i < 0 {
			return domain.TestCount{}
		}
		return r.Inputs.Tests[i]
	}
	if got := test("ASI02", domain.SourceRange); got.Held != 1 {
		t.Errorf("ASI02: %+v", got)
	}
	if got := test("ASI03", domain.SourceRange); got.Reported != 1 || got.Held != 0 || !has("ASI03", domain.ReasonReportedOnly) {
		t.Errorf("ASI03: %+v", got)
	}
	if !has("ASI04", domain.ReasonTestFailed) {
		t.Error("ASI04 hides a failure")
	}
	if got := test("ASI07", domain.SourceRange); got.NotExercised != 1 || !has("ASI07", domain.ReasonNotExercised) {
		t.Errorf("ASI07: %+v", got)
	}
	if got := test("ASI09", domain.SourceRange); got.Held != 0 {
		t.Errorf("a digest not the library's counted: %+v", got)
	}
	if got := test("ASI10", domain.SourceCampaign); got.Held != 1 {
		t.Errorf("campaign held: %+v", got)
	}
	if !has("ASI01", domain.ReasonReportedOnly) || !has("ASI08", domain.ReasonTestFailed) {
		t.Error("a campaign's report or failure is not a gap")
	}
	// A customer range is never read, whatever it holds.
	before := sourceOf(t, r, domain.SourceRange).Refs
	cust := ids.NewV7()
	agent := ids.NewV7()
	o.D.AdminExec(t, `INSERT INTO pc.agents (org_id, id, name, state, created_by, range_agent) VALUES ($1, $2, 'cx', 'DISCOVERED', 'test', true)`, o.Org, agent)
	o.D.AdminExec(t, `INSERT INTO pc.redteam_runs (org_id, id, range_agent_id, started_by, runner_version, scenario_set_digest, scenarios,
		origin) VALUES ($1, $2, $3, 'test', 'test', repeat('a', 64), '[{"id":"CX-001"}]', 'customer')`, o.Org, cust, agent)
	o.D.AdminExec(t, `UPDATE pc.redteam_runs SET state = 'FINISHED', finished_at = now() WHERE org_id = $1 AND id = $2`, o.Org, cust)
	r, err = s.Report(as(o, td.RoleAuditor), domain.OWASPASI, start, end)
	if err != nil {
		t.Fatal(err)
	}
	if got := sourceOf(t, r, domain.SourceRange).Refs; len(got) != len(before) {
		t.Errorf("a customer range was read: %v", got)
	}
}

// TestHR606_ReportRowOutlivesItsPackAndDigestIsSetOnce: the row's digest is
// set once and pc_app can neither delete the row nor change its parameters.
// Covers: F896
func TestHR606_ReportRowOutlivesItsPackAndDigestIsSetOnce(t *testing.T) {
	o := exposuretest.New(t)
	packID, rowID := ids.NewV7(), ids.NewV7()
	start, end := period()
	o.Exec(t, `INSERT INTO pc.evidence_packs (org_id, id, created_by, scope_kind, scope, include)
		VALUES ($1, $2, $3, 'compliance', '{}', '{}')`, o.Org, packID, o.User)
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertComplianceReport(ctx, dbq.InsertComplianceReportParams{
			OrgID: o.Org, ID: rowID, PackID: packID, Framework: "OWASP_ASI", PeriodStart: start, PeriodEnd: end, CreatedBy: o.User,
		})
	})
	digest := make([]byte, 32)
	digest[0] = 1
	set := func() int64 {
		var n int64
		o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			n, err = dbq.New(tx).SetComplianceReportDigest(ctx, digest, o.Org, packID)
			return err
		})
		return n
	}
	if set() != 1 {
		t.Fatal("the digest was not set")
	}
	digest[0] = 2
	if set() != 0 {
		t.Fatal("the digest was set twice")
	}
	// pc_app has no DELETE and no UPDATE of the parameters.
	for _, sql := range []string{
		"DELETE FROM pc.compliance_reports WHERE org_id = $1",
		"UPDATE pc.compliance_reports SET framework = 'SOC2' WHERE org_id = $1",
		"UPDATE pc.compliance_reports SET period_end = now() WHERE org_id = $1",
	} {
		err := o.P.InTenantTx(context.Background(), o.Org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, o.Org)
			return err
		})
		if err == nil {
			t.Errorf("pc_app ran: %s", sql)
		}
	}
	// A pack that expires leaves the row.
	o.Exec(t, `UPDATE pc.evidence_packs SET state = 'FAILED', error_code = 'X' WHERE org_id = $1 AND id = $2`, o.Org, packID)
	p, err := service(o, billing.Team).ListReports(as(o, td.RoleAuditor), page.Request{Size: 10})
	if err != nil || len(p.Items) != 1 || p.Items[0].SHA256 == "" || p.Items[0].Framework != domain.OWASPASI {
		t.Fatalf("%+v %v", p, err)
	}
	// Another org reads nothing.
	other := exposuretest.NewIn(t, o.D, o.P)
	p, err = service(other, billing.Team).ListReports(as(other, td.RoleAuditor), page.Request{Size: 10})
	if err != nil || len(p.Items) != 0 {
		t.Fatalf("another org: %+v %v", p, err)
	}
}
