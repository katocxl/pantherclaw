// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/ranges/adapters/pgranges"
	rangeapp "github.com/katocxl/pantherclaw/internal/ranges/app"
	rdomain "github.com/katocxl/pantherclaw/internal/ranges/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// rangePacks exports a range through the pack service of the pack world,
// which queues the build the test then runs.
type rangePacks struct{ p *packWorld }

func (e rangePacks) ExportRange(ctx context.Context, rng ids.UUID) (ids.UUID, error) {
	pk, err := e.p.svc.CreateEvidencePack(ctx, evapp.PackRequest{
		Kind: pack.ScopeRange, Range: rng, Include: pack.Include{Receipts: true, Versions: true},
	})
	return pk.ID, err
}

type licence struct{ e billing.Edition }

func (l licence) Current(context.Context) (billing.Entitlements, error) {
	x := billing.CommunityEntitlements()
	x.Edition = l.e
	return x, nil
}

// TestHR224_RangePacksVerifyOffline (integration): a range runs against the
// real authority; its assurance report is exported as a pack of scope
// range, carries the range statement and the receipts of every transaction
// it names, and `pclaw verify`'s check re-derives the verdicts and the
// server-observed steps from them offline.
func TestHR224_RangePacksVerifyOffline(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	// The agent of this world is a range agent for this test.
	admin := w.db.Pool(t, w.db.Migrator)
	exec(t, admin, w.org, "UPDATE pc.agents SET range_agent = true WHERE org_id = $1 AND id = $2", w.org, w.agent)
	// Its connection is simulated too: a simulated run on a real connection is
	// denied SIMULATION_MISMATCH (HR-220).
	exec(t, admin, w.org, "UPDATE pc.connections SET simulated = true WHERE org_id = $1 AND id = $2", w.org, w.conn)

	p := w.packs(billing.Team)
	org := td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}
	owner, auditor := p.person("owner", td.RoleAgentOwner, org), p.person("auditor", td.RoleAuditor, org)
	svc := &rangeapp.Service{Store: pgranges.Store{Pool: w.pool}, Editions: licence{billing.Team}, Exporter: rangePacks{p}}

	decl := func(id string) rdomain.Scenario {
		return rdomain.Scenario{ID: id, Digest: strings.Repeat("a", 64), Tier: rdomain.TierCommunity, Category: "boundary", Suite: "coding-agent", Title: id, StepCount: 1}
	}
	rng, err := svc.StartRange(owner, rangeapp.StartInput{Agent: w.agent, Scenarios: []rdomain.Scenario{decl("RT-001"), decl("RT-002"), decl("RT-003")}, RunnerVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	// Two simulated decisions of the range agent, made after it started: one
	// denied, one allowed. (The authority sets transactions.simulated in the
	// boundary work's second part; the migrator sets it here.)
	run := w.run(w.grant("500").ID, ids.UUID{})
	exec(t, admin, w.org, "UPDATE pc.runs SET simulated = true WHERE org_id = $1 AND id = $2", w.org, run)
	denied := w.authorize(w.request(run, ids.NewV7(), "ch_1", "700.00"))
	allowed := w.authorize(w.request(run, ids.NewV7(), "ch_1", "10.00"))
	exec(t, admin, w.org, "UPDATE pc.transactions SET simulated = true WHERE org_id = $1 AND run_id = $2", w.org, run)

	step := func(id string, tx ids.UUID, outcome rdomain.Expect) rdomain.StepInput {
		return rdomain.StepInput{ID: id, Kind: "agent.call", Expect: outcome, Observed: outcome, Transaction: &tx}
	}
	observed := func(_ any, decision, code string) rdomain.Expect {
		return rdomain.TransactionRecord{Decision: decision, Reason: code}.Observe(rdomain.Expect{}).Observed
	}
	deniedWant := observed(nil, string(denied.Decision), decisive(denied))
	if _, err := svc.RecordResult(owner, rangeapp.RecordInput{
		Range: rng.ID, Scenario: "RT-001", Digest: decl("RT-001").Digest, Verdict: rdomain.Pass,
		Steps: []rdomain.StepInput{step("over-limit", denied.TransactionID, deniedWant)},
	}); err != nil {
		t.Fatal(err)
	}
	// The runner claims the allowed refund was denied: the server's record wins.
	res, err := svc.RecordResult(owner, rangeapp.RecordInput{
		Range: rng.ID, Scenario: "RT-002", Digest: decl("RT-002").Digest, Verdict: rdomain.Pass,
		Steps: []rdomain.StepInput{{ID: "small", Kind: "agent.call", Expect: deniedWant, Observed: deniedWant, Transaction: &allowed.TransactionID}},
	})
	if err != nil || res.Verdict != rdomain.Fail || !res.Steps[0].Mismatch {
		t.Fatalf("forged claim: %+v, %v", res, err)
	}
	// RT-003 is never recorded: MISSING at the finish.
	if _, err := svc.ExportAssuranceReport(auditor, rng.ID); !errors.Is(err, rangeapp.ErrNotFinished) {
		t.Fatalf("export of a running range: %v", err)
	}
	if d, err := svc.FinishRange(owner, rng.ID); err != nil || d.Counts != (rdomain.Counts{Pass: 1, Fail: 1, Missing: 1}) {
		t.Fatalf("finish: %+v, %v", d.Counts, err)
	}
	if _, err := svc.ExportAssuranceReport(owner, rng.ID); err == nil {
		t.Fatal("a caller without evidence.export exported a report")
	}
	packID, err := svc.ExportAssuranceReport(auditor, rng.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.builder.Build(context.Background(), w.org, packID); err != nil {
		t.Fatal(err)
	}
	raw := p.download(auditor, packID)
	m := manifestOf(t, raw)
	if m.Scope.Kind != pack.ScopeRange || m.Scope.Range != rng.ID.String() || m.Statement != pack.RangeStatement {
		t.Fatalf("manifest scope %+v, statement %q", m.Scope, m.Statement)
	}
	if len(m.Transactions) != 2 {
		t.Fatalf("the pack holds %d transactions, want the 2 the steps name", len(m.Transactions))
	}
	files, err := pack.Read(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := pack.DecodeAssurance(files[pack.AssurancePath])
	if err != nil {
		t.Fatal(err)
	}
	if a.Totals != (pack.AssuranceCounts{Pass: 1, Fail: 1, Missing: 1}) || len(a.Mismatches) != 1 || a.Mismatches[0].Step != "small" ||
		a.Categories["boundary"].Missing != 1 || a.Statement != pack.RangeStatement {
		t.Fatalf("assurance report: %+v", a)
	}
	r := bundle.VerifyPack(raw, bundle.Options{Trust: p.trust()})
	status := func(name string) bundle.Status {
		var out bundle.Status
		for _, c := range r.Checks {
			if c.Name == name {
				if c.Status == bundle.Failed {
					return bundle.Failed
				}
				out = c.Status
			}
		}
		return out
	}
	for _, name := range []string{"pack.signature", "pack.items", "pack.statement", "range.assurance", "range.verdicts", "range.step"} {
		if got := status(name); got != bundle.Passed {
			t.Errorf("%s = %q, want passed:\n%s", name, got, r.Text())
		}
	}
	// Every receipt must say simulated: true for the pack to verify. Until
	// the pipeline sets it from the run (boundary work part two), the
	// authority's receipts say false and the check must say so.
	if got := status("range.simulated"); got != bundle.Passed && got != bundle.Failed {
		t.Errorf("range.simulated = %q", got)
	}
	// A pack of someone else's range, or a running one, is not exported.
	other := p.person("other-auditor", td.RoleAuditor, org)
	if _, err := svc.ExportAssuranceReport(other, ids.NewV7()); !errors.Is(err, rangeapp.ErrNotFound) {
		t.Fatalf("an unknown range: %v", err)
	}
}
