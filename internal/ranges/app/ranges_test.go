// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/ranges/app"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hexB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fake is an in-memory store: one org, one transaction at a time.
type fake struct {
	agents   map[ids.UUID]app.AgentRef
	ranges   map[ids.UUID]domain.Range
	results  map[ids.UUID][]domain.Result
	txns     map[ids.UUID]domain.TransactionRecord
	probes   map[ids.UUID]domain.ProbeRecord
	audited  []string
	exported []ids.UUID
}

func newFake() *fake {
	return &fake{
		agents: map[ids.UUID]app.AgentRef{}, ranges: map[ids.UUID]domain.Range{}, results: map[ids.UUID][]domain.Result{},
		txns: map[ids.UUID]domain.TransactionRecord{}, probes: map[ids.UUID]domain.ProbeRecord{},
	}
}

func (f *fake) InTx(ctx context.Context, _ ids.OrgID, _ bool, fn func(context.Context, app.Tx) error) error {
	return fn(ctx, f)
}

func (f *fake) Agent(_ context.Context, id ids.UUID) (app.AgentRef, error) {
	a, ok := f.agents[id]
	if !ok {
		return a, app.ErrAgentMissing
	}
	return a, nil
}

func (f *fake) Versions(context.Context, ids.UUID) (domain.Versions, error) {
	return domain.Versions{Policies: []domain.VersionRef{{Name: "p", Version: "1"}}}, nil
}

func (f *fake) Range(_ context.Context, id ids.UUID, _ bool) (domain.Range, error) {
	r, ok := f.ranges[id]
	if !ok {
		return r, app.ErrNotFound
	}
	return r, nil
}

func (f *fake) InsertRange(_ context.Context, r domain.Range) (domain.Range, error) {
	r.Started = time.Now()
	f.ranges[r.ID] = r
	return r, nil
}

func (f *fake) Transition(_ context.Context, id ids.UUID, to domain.State) (time.Time, bool, error) {
	r := f.ranges[id]
	if r.State != domain.Running {
		return time.Time{}, false, nil
	}
	at := time.Now()
	r.State, r.Finished = to, &at
	f.ranges[id] = r
	return at, true, nil
}

func (f *fake) ListRanges(_ context.Context, agent *ids.UUID, _ ids.UUID, _ int32) ([]domain.Range, error) {
	var out []domain.Range
	for _, r := range f.ranges {
		if agent == nil || r.Agent == *agent {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fake) Results(_ context.Context, rng ids.UUID) ([]domain.Result, error) {
	return f.results[rng], nil
}

func (f *fake) InsertResult(_ context.Context, rng ids.UUID, r domain.Result) (time.Time, bool, error) {
	for _, have := range f.results[rng] {
		if have.Scenario.ID == r.Scenario.ID {
			return time.Time{}, false, nil
		}
	}
	r.Recorded = time.Now()
	f.results[rng] = append(f.results[rng], r)
	return r.Recorded, true, nil
}

func (f *fake) Transaction(_ context.Context, id ids.UUID) (domain.TransactionRecord, bool, error) {
	t, ok := f.txns[id]
	return t, ok, nil
}

func (f *fake) Probe(_ context.Context, id ids.UUID) (domain.ProbeRecord, bool, error) {
	p, ok := f.probes[id]
	return p, ok, nil
}

func (f *fake) Audit(_ context.Context, ev audit.Event) error {
	f.audited = append(f.audited, ev.Name)
	return nil
}

func (f *fake) ExportRange(_ context.Context, rng ids.UUID) (ids.UUID, error) {
	f.exported = append(f.exported, rng)
	return ids.NewV7(), nil
}

type ents struct{ e billing.Edition }

func (e ents) Current(context.Context) (billing.Entitlements, error) {
	if e.e == billing.Community {
		return billing.CommunityEntitlements(), nil
	}
	return billing.Entitlements{Edition: e.e, Status: billing.StatusValid}, nil
}

type world struct {
	f      *fake
	svc    *app.Service
	ctx    context.Context
	org    ids.OrgID
	agent  ids.UUID
	person ids.UUID
}

func newWorld(t *testing.T, edition billing.Edition, role td.RoleName) *world {
	t.Helper()
	w := &world{f: newFake(), org: ids.New[ids.Org](), agent: ids.NewV7(), person: ids.NewV7()}
	w.f.agents[w.agent] = app.AgentRef{ID: w.agent, RangeAgent: true, Path: td.OrgPath(w.org)}
	w.svc = &app.Service{Store: w.f, Editions: ents{edition}, Exporter: w.f}
	w.ctx = tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.person},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
	}})
	return w
}

func decl(id, tier, category string) domain.Scenario {
	return domain.Scenario{ID: id, Digest: dig(id), Tier: tier, Category: category, Suite: "coding-agent", Title: id, StepCount: 1}
}

func (w *world) start(t *testing.T, set ...domain.Scenario) domain.Range {
	t.Helper()
	r, err := w.svc.StartRange(w.ctx, app.StartInput{Agent: w.agent, Scenarios: set, RunnerVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (w *world) txn(t *testing.T, simulated bool, decision, reason string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	w.f.txns[id] = domain.TransactionRecord{
		ID: id, Agent: w.agent, Simulated: simulated, Created: time.Now().Add(time.Second), Decision: decision, Reason: reason,
	}
	return id
}

func uid(id ids.UUID) *ids.UUID { return &id }

func step(id string, expect, observed domain.Expect, txn *ids.UUID) domain.StepInput {
	return domain.StepInput{ID: id, Kind: "agent.call", Expect: expect, Observed: observed, Transaction: txn}
}

var (
	deny  = domain.Expect{Outcome: domain.OutcomeDeny, Reason: "DESTINATION_NOT_GRANTED"}
	allow = domain.Expect{Outcome: domain.OutcomeAllow}
)

// TestHR224_ServerRecordsWinOverClientClaims: a step that names a
// transaction is observed by the server from its own record; a runner that
// claims another outcome is overwritten, the step is marked MISMATCH and
// the scenario verdict follows the server's value (HR-224, T-091).
func TestHR224_ServerRecordsWinOverClientClaims(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-009", domain.TierCommunity, "boundary"))
	tx := w.txn(t, true, "ALLOW", "GRANT_ALLOWS") // the server saw an ALLOW
	res, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-009", Digest: dig("RT-009"), Verdict: domain.Pass,
		Steps: []domain.StepInput{step("exfil", deny, deny, uid(tx))}, // the runner claims the DENY it expected
	})
	if err != nil {
		t.Fatal(err)
	}
	st := res.Steps[0]
	if st.ObservedBy != domain.Server || !st.Mismatch || st.Observed.Outcome != domain.OutcomeAllow || st.Claimed.Outcome != domain.OutcomeDeny || st.Matched {
		t.Fatalf("step = %+v, want the server's ALLOW with the DENY claim kept as MISMATCH", st)
	}
	if res.Verdict != domain.Fail || res.Claimed != domain.Pass {
		t.Fatalf("verdict %s (claimed %s), want FAIL (claimed PASS)", res.Verdict, res.Claimed)
	}
}

// A client-observed step stays CLIENT and its claim stands.
func TestHR224_StepsWithoutRecordsAreClientObserved(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-014", domain.TierCommunity, "boundary"))
	blocked := domain.Expect{Outcome: domain.OutcomeBlocked}
	res, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-014", Digest: dig("RT-014"), Verdict: domain.Pass, Steps: []domain.StepInput{step("dns", blocked, blocked, nil)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Steps[0].ObservedBy != domain.Client || res.Steps[0].Mismatch || res.Verdict != domain.Pass {
		t.Fatalf("result = %+v", res)
	}
}

// T-091: a probe report the server knows backs the step; one it does not
// know, or another agent's, rejects the call.
func TestT091_ProbeReportsAreCheckedAgainstTheSignedRecords(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-014", domain.TierCommunity, "boundary"))
	blocked := domain.Expect{Outcome: domain.OutcomeBlocked}
	good := ids.NewV7()
	w.f.probes[good] = domain.ProbeRecord{ID: good, Agent: w.agent, Recorded: time.Now().Add(time.Second), Results: map[string]string{"dns": "reachable"}}
	in := app.RecordInput{Range: r.ID, Scenario: "RT-014", Digest: dig("RT-014"), Verdict: domain.Pass}
	in.Steps = []domain.StepInput{{ID: "dns", Kind: "sandbox.probe", ProbeKind: "dns", Expect: blocked, Observed: blocked, Probe: uid(good)}}
	res, err := w.svc.RecordResult(w.ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	// The signed record says the probe got out: the runner's BLOCKED claim loses.
	if st := res.Steps[0]; st.ObservedBy != domain.Server || !st.Mismatch || st.Observed.Outcome != domain.OutcomeAllow || res.Verdict != domain.Fail {
		t.Fatalf("step = %+v verdict %s", st, res.Verdict)
	}
	other := ids.NewV7()
	w.f.probes[other] = domain.ProbeRecord{ID: other, Agent: ids.NewV7(), Recorded: time.Now().Add(time.Second), Results: map[string]string{"dns": "blocked"}}
	for _, bad := range []ids.UUID{other, ids.NewV7()} {
		w2 := in
		w2.Scenario = "RT-014"
		w2.Steps = []domain.StepInput{{ID: "dns", Kind: "sandbox.probe", ProbeKind: "dns", Expect: blocked, Observed: blocked, Probe: uid(bad)}}
		r2 := w.start(t, decl("RT-014", domain.TierCommunity, "boundary"))
		w2.Range = r2.ID
		if _, err := w.svc.RecordResult(w.ctx, w2); !errors.Is(err, app.ErrRecord) {
			t.Fatalf("probe %s: err = %v, want RANGE_RECORD_INVALID", bad, err)
		}
	}
}

// T-091: receipts of real runs mixed into a range are refused: a
// transaction that is not simulated, another agent's, or made before the
// range started cannot back a step; nor can an unknown one.
func TestT091_RealRunTransactionsCannotBackAStep(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-009", domain.TierCommunity, "boundary"))
	realTx := w.txn(t, false, "DENY", "DESTINATION_NOT_GRANTED")
	otherAgent := ids.NewV7()
	w.f.txns[otherAgent] = domain.TransactionRecord{ID: otherAgent, Agent: ids.NewV7(), Simulated: true, Created: time.Now().Add(time.Second), Decision: "DENY"}
	old := ids.NewV7()
	w.f.txns[old] = domain.TransactionRecord{ID: old, Agent: w.agent, Simulated: true, Created: r.Started.Add(-time.Hour), Decision: "DENY"}
	for name, id := range map[string]ids.UUID{"real": realTx, "other agent": otherAgent, "before the range": old, "unknown": ids.NewV7()} {
		_, err := w.svc.RecordResult(w.ctx, app.RecordInput{
			Range: r.ID, Scenario: "RT-009", Digest: dig("RT-009"), Verdict: domain.Pass, Steps: []domain.StepInput{step("s", deny, deny, uid(id))},
		})
		if !errors.Is(err, app.ErrRecord) {
			t.Errorf("%s: err = %v, want RANGE_RECORD_INVALID", name, err)
		}
	}
	if len(w.f.results[r.ID]) != 0 {
		t.Fatal("a rejected record left a result")
	}
}

// T-091: an inflated report: a scenario never recorded is MISSING at the
// finish, a claimed PASS with no steps is refused, and a scenario or digest
// the range did not declare is refused.
func TestT091_InflatedReportsAreRefused(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-001", domain.TierCommunity, "boundary"), decl("RT-002", domain.TierCommunity, "boundary"))
	if _, err := w.svc.RecordResult(w.ctx, app.RecordInput{Range: r.ID, Scenario: "RT-001", Digest: dig("RT-001"), Verdict: domain.Pass}); !errors.Is(err, app.ErrSteps) {
		t.Fatalf("PASS with no steps: %v", err)
	}
	for _, in := range []app.RecordInput{
		{Range: r.ID, Scenario: "RT-099", Digest: dig("RT-099"), Verdict: domain.Pass, Steps: []domain.StepInput{step("s", allow, allow, nil)}},
		{Range: r.ID, Scenario: "RT-001", Digest: hexB, Verdict: domain.Pass, Steps: []domain.StepInput{step("s", allow, allow, nil)}},
	} {
		if _, err := w.svc.RecordResult(w.ctx, in); !errors.Is(err, app.ErrUndeclared) {
			t.Fatalf("%+v: %v", in, err)
		}
	}
	// A failed step claimed as PASS is FAIL.
	res, err := w.svc.RecordResult(w.ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-001", Digest: dig("RT-001"), Verdict: domain.Pass, Steps: []domain.StepInput{step("s", allow, deny, nil)},
	})
	if err != nil || res.Verdict != domain.Fail || res.Claimed != domain.Pass {
		t.Fatalf("res = %+v, err %v", res, err)
	}
	// Recording twice is refused; the result stays.
	if _, err := w.svc.RecordResult(w.ctx, app.RecordInput{Range: r.ID, Scenario: "RT-001", Digest: dig("RT-001"), Verdict: domain.Pass, Steps: []domain.StepInput{step("s", allow, allow, nil)}}); !errors.Is(err, app.ErrRecorded) {
		t.Fatalf("second result: %v", err)
	}
	d, err := w.svc.FinishRange(w.ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Counts != (domain.Counts{Fail: 1, Missing: 1}) {
		t.Fatalf("counts = %+v, want one FAIL and one MISSING", d.Counts)
	}
	// Nothing records after the finish, and it cannot finish twice.
	if _, err := w.svc.RecordResult(w.ctx, app.RecordInput{Range: r.ID, Scenario: "RT-002", Digest: dig("RT-002"), Verdict: domain.Skipped}); !errors.Is(err, app.ErrNotRunning) {
		t.Fatalf("record after finish: %v", err)
	}
	if _, err := w.svc.FinishRange(w.ctx, r.ID); !errors.Is(err, app.ErrNotRunning) {
		t.Fatalf("second finish: %v", err)
	}
}

// T-091: a stale baseline: only a finished range stands
// in as a baseline.
func TestT091_AStaleBaselineIsRefused(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	running := w.start(t, decl("RT-001", domain.TierCommunity, "boundary"))
	in := app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{decl("RT-001", domain.TierCommunity, "boundary")}, RunnerVersion: "t"}
	in.Baseline = &running.ID
	if _, err := w.svc.StartRange(w.ctx, in); !errors.Is(err, app.ErrBaseline) {
		t.Fatalf("running baseline: %v", err)
	}
	in.Baseline = uid(ids.NewV7())
	if _, err := w.svc.StartRange(w.ctx, in); !errors.Is(err, app.ErrBaseline) {
		t.Fatalf("unknown baseline: %v", err)
	}
	abandoned := domain.Range{ID: ids.NewV7(), Agent: w.agent, State: domain.Abandoned, Origin: domain.OriginLibrary}
	w.f.ranges[abandoned.ID] = abandoned
	in.Baseline = &abandoned.ID
	if _, err := w.svc.StartRange(w.ctx, in); !errors.Is(err, app.ErrBaseline) {
		t.Fatalf("abandoned baseline: %v", err)
	}
	replaced := domain.Range{ID: ids.NewV7(), Agent: ids.NewV7(), State: domain.Finished, Origin: domain.OriginLibrary}
	w.f.ranges[replaced.ID] = replaced
	in.Baseline = &replaced.ID
	if _, err := w.svc.StartRange(w.ctx, in); err != nil {
		t.Fatalf("a finished range of a replaced agent: %v", err)
	}
	if _, err := w.svc.FinishRange(w.ctx, running.ID); err != nil {
		t.Fatal(err)
	}
	in.Baseline = &running.ID
	if _, err := w.svc.StartRange(w.ctx, in); err != nil {
		t.Fatalf("finished baseline: %v", err)
	}
}

func TestStartRangeNeedsARangeAgent(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	realTx := ids.NewV7()
	w.f.agents[realTx] = app.AgentRef{ID: realTx, Path: td.OrgPath(w.org)}
	_, err := w.svc.StartRange(w.ctx, app.StartInput{Agent: realTx, Scenarios: []domain.Scenario{decl("RT-001", domain.TierCommunity, "boundary")}, RunnerVersion: "t"})
	if !errors.Is(err, app.ErrNotRange) {
		t.Fatalf("real agent: %v", err)
	}
	_, err = w.svc.StartRange(w.ctx, app.StartInput{Agent: ids.NewV7(), Scenarios: []domain.Scenario{decl("RT-001", domain.TierCommunity, "boundary")}, RunnerVersion: "t"})
	if !errors.Is(err, app.ErrAgentMissing) {
		t.Fatalf("unknown agent: %v", err)
	}
}

// F4: business-tier scenarios need Business, the assurance report Team.
func TestEditionsGateTheLibraryAndTheReport(t *testing.T) {
	biz := decl("RT-030", domain.TierBusiness, "boundary")
	com := decl("RT-001", domain.TierCommunity, "boundary")
	for _, tc := range []struct {
		edition billing.Edition
		library bool
		report  bool
	}{
		{billing.Community, false, false}, {billing.Team, false, true}, {billing.Business, true, true}, {billing.Enterprise, true, true},
	} {
		w := newWorld(t, tc.edition, td.RoleSecurityAdmin)
		w.f.agents[w.agent] = app.AgentRef{ID: w.agent, RangeAgent: true, Path: td.OrgPath(w.org)}
		// Security Admin cannot run ranges: use a developer to start.
		dev := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
			Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
			Bindings: []td.Binding{{Role: td.RoleDeveloper, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
		}})
		if _, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{com}, RunnerVersion: "t"}); err != nil {
			t.Fatalf("%s: community tier: %v", tc.edition, err)
		}
		_, err := w.svc.StartRange(dev, app.StartInput{Agent: w.agent, Scenarios: []domain.Scenario{com, biz}, RunnerVersion: "t"})
		if got := err == nil; got != tc.library {
			t.Errorf("%s: business tier allowed %v (err %v), want %v", tc.edition, got, err, tc.library)
		} else if err != nil && !errors.Is(err, app.ErrEdition) {
			t.Errorf("%s: err = %v, want EDITION_REQUIRED", tc.edition, err)
		}
		// Export needs a finished range, read access and evidence.export (a person).
		rng := domain.Range{ID: ids.NewV7(), Agent: w.agent, State: domain.Finished, Origin: domain.OriginLibrary}
		w.f.ranges[rng.ID] = rng
		_, err = w.svc.ExportAssuranceReport(w.ctx, rng.ID)
		if got := err == nil; got != tc.report {
			t.Errorf("%s: report allowed %v (err %v), want %v", tc.edition, got, err, tc.report)
		} else if err != nil && !errors.Is(err, app.ErrEdition) {
			t.Errorf("%s: report err = %v, want EDITION_REQUIRED", tc.edition, err)
		}
	}
}

func TestExportNeedsAFinishedRange(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleSecurityAdmin)
	rng := domain.Range{ID: ids.NewV7(), Agent: w.agent, State: domain.Running, Origin: domain.OriginLibrary}
	w.f.ranges[rng.ID] = rng
	if _, err := w.svc.ExportAssuranceReport(w.ctx, rng.ID); !errors.Is(err, app.ErrNotFinished) {
		t.Fatalf("running range: %v", err)
	}
	if len(w.f.exported) != 0 {
		t.Fatal("exported an unfinished range")
	}
}

// A caller who cannot read the agent finds neither the range nor its
// results; one who reads but cannot run is denied the writes.
func TestRangesFollowAgentPermissions(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-001", domain.TierCommunity, "boundary"))
	stranger := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleViewer, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
	}})
	if _, err := w.svc.GetRange(stranger, r.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("get: %v", err)
	}
	if _, err := w.svc.FinishRange(stranger, r.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("finish: %v", err)
	}
	if _, err := w.svc.ListRanges(stranger, nil, page.Request{Size: 10}); err == nil {
		t.Fatal("list by a caller without redteam.read")
	}
	auditor := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
	}})
	if _, err := w.svc.GetRange(auditor, r.ID); err != nil {
		t.Fatalf("auditor get: %v", err)
	}
	if _, err := w.svc.FinishRange(auditor, r.ID); err == nil || errors.Is(err, app.ErrNotFound) {
		t.Fatalf("auditor finish: %v, want permission denied", err)
	}
	p, err := w.svc.ListRanges(auditor, nil, page.Request{Size: 10})
	if err != nil || len(p.Items) != 1 {
		t.Fatalf("auditor list: %v %v", p, err)
	}
}

// A runner's ERROR or SKIPPED is its own to report: with a partial step
// list (only the steps that produced an outcome) or none, the server keeps
// the verdict and never upgrades it to PASS, even when every recorded step
// matched (D33).
func TestHR224_ErrorAndSkippedVerdictsAreNeverUpgraded(t *testing.T) {
	w := newWorld(t, billing.Team, td.RoleAgentOwner)
	r := w.start(t, decl("RT-001", domain.TierCommunity, "boundary"), decl("RT-002", domain.TierCommunity, "boundary"),
		decl("RT-003", domain.TierCommunity, "boundary"))
	for _, tc := range []struct {
		scenario string
		verdict  domain.Verdict
		steps    []domain.StepInput
	}{
		{"RT-001", domain.Errored, []domain.StepInput{step("a", allow, allow, nil)}},
		{"RT-002", domain.Skipped, nil},
		{"RT-003", domain.Errored, nil},
	} {
		res, err := w.svc.RecordResult(w.ctx, app.RecordInput{Range: r.ID, Scenario: tc.scenario, Digest: dig(tc.scenario), Verdict: tc.verdict, Steps: tc.steps})
		if err != nil || res.Verdict != tc.verdict || res.Claimed != "" {
			t.Errorf("%s: %+v, %v, want %s kept", tc.scenario, res, err, tc.verdict)
		}
	}
	d, err := w.svc.FinishRange(w.ctx, r.ID)
	if err != nil || d.Counts != (domain.Counts{Error: 2, Skipped: 1}) {
		t.Fatalf("finish: %+v, %v", d.Counts, err)
	}
}

// dig is a library scenario's digest: a range accepts an RT id only with
// it (D125).
func dig(id string) string {
	if e, ok := library.Lookup(id); ok {
		return e.Digest
	}
	return hexA
}
