// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle/bundletest"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
)

const (
	rtAgent = "0192aaaa-bbbb-7ccc-8ddd-0000000000a1"
	rtRun   = "0192aaaa-bbbb-7ccc-8ddd-0000000000b1"
	rtRange = "0192aaaa-bbbb-7ccc-8ddd-0000000000c1"
)

// fakeRanges records what the CLI sends the RangeService.
type fakeRanges struct {
	pantherclawv1connect.UnimplementedRangeServiceHandler
	mu         sync.Mutex
	started    []*pantherclawv1.StartRangeRequest
	recorded   []*pantherclawv1.RecordResultRequest
	finished   int
	failRecord bool
	attempts   int
}

func (f *fakeRanges) StartRange(_ context.Context, r *pantherclawv1.StartRangeRequest) (*pantherclawv1.StartRangeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, r)
	return &pantherclawv1.StartRangeResponse{RangeId: rtRange}, nil
}

func (f *fakeRanges) RecordResult(_ context.Context, r *pantherclawv1.RecordResultRequest) (*pantherclawv1.RecordResultResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.failRecord {
		return nil, connect.NewError(connect.CodeUnavailable, "the store is down")
	}
	f.recorded = append(f.recorded, r)
	return &pantherclawv1.RecordResultResponse{}, nil
}

func (f *fakeRanges) FinishRange(context.Context, *pantherclawv1.FinishRangeRequest) (*pantherclawv1.FinishRangeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finished++
	return &pantherclawv1.FinishRangeResponse{Range: &pantherclawv1.Range{Id: rtRange, RunnerVersion: "test"}}, nil
}

// rangeEnv is a fake server, a fake gateway, an enrolled range key file and
// a scenario directory.
type rangeEnv struct {
	iss       *bundletest.Issuer
	ranges    *fakeRanges
	env       Env
	keyFile   string
	tokenFile string
	gateway   string
	scenarios string
	decision  *string // the gateway's answer to /sdk/*
	outDir    string
	runs      int
}

const rtScenario = `apiVersion: pantherclaw.range/v1
id: RT-001
title: A merge is held
category: boundary
suite: coding-agent
tier: community
attacker: A1
threats: [T-080]
rules: [HR-201]
requires: [github]
steps:
  - id: merge
    do: agent.call
    with: {face: sdk, connection: github, tool: merge_pull_request, args: {number: "7"}}
    expect: {outcome: HOLD, decisive_control: HR-201}
`

func newRangeEnv(t *testing.T) *rangeEnv {
	t.Helper()
	re := &rangeEnv{ranges: &fakeRanges{}}
	re.iss = bundletest.NewIssuer(t)
	cs := connect.NewServer()
	pantherclawv1connect.RegisterRangeServiceHandler(cs, re.ranges)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	hold := `{"decision":"hold","error_class":"held","code":"REQUIRE_APPROVAL","transaction_id":"` + rtRange + `"}`
	re.decision = &hold
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, *re.decision)
	}))
	t.Cleanup(gw.Close)
	re.gateway = gw.URL

	dir := t.TempDir()
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	kf.Identifier = "pc:org/" + re.iss.Org.String() + "/agent/" + rtAgent + "/inst/0192aaaa-bbbb-7ccc-8ddd-0000000000d1"
	kf.Server, kf.RunID = srv.URL, rtRun
	re.keyFile = filepath.Join(dir, "key.json")
	if err := workloadclient.WriteKeyFile(re.keyFile, kf, false); err != nil {
		t.Fatal(err)
	}
	re.tokenFile = writeFile(t, dir, "token", []byte("workload-token\n"))
	re.scenarios = filepath.Join(dir, "scenarios")
	if err := os.Mkdir(re.scenarios, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, re.scenarios, "RT-001-merge-held.yaml", []byte(rtScenario))
	re.outDir = filepath.Join(dir, "out")
	re.env = envOf(map[string]string{"PANTHERCLAW_SERVER": srv.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	return re
}

func (re *rangeEnv) run(t *testing.T, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{
		"redteam", "run", "--scenarios", re.scenarios, "--workload-file", re.keyFile, "--token-file", re.tokenFile,
		"--gateway", re.gateway, "--role", "github=gh-sim", "--out", filepath.Join(re.outDir, fmt.Sprint(re.runs)),
	}, extra...)
	re.runs++
	return run(t, re.env, args...)
}

// assurancePack builds a signed evidence pack holding an assurance.json with
// the given scenarios, and the trust file that pins its key.
func (re *rangeEnv) assurancePack(t *testing.T, reportOrg string, scenarios []map[string]string) (raw, trust []byte) {
	t.Helper()
	iss := re.iss
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.NewSigner("evidence-packs-test-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	var scs []pack.AssuranceScenario
	for _, s := range scenarios {
		scs = append(scs, pack.AssuranceScenario{
			ID: s["id"], Digest: s["digest"], Verdict: s["verdict"], Category: "boundary", Tier: "community", Suite: "coding-agent", Steps: []pack.AssuranceStep{},
		})
	}
	doc, err := json.Marshal(pack.Assurance{
		Format: pack.AssuranceFormat, Range: rtRange, Org: reportOrg, Agent: rtAgent,
		Started: "2026-10-14T08:00:00Z", Finished: "2026-10-14T08:05:00Z", RunnerVersion: "test", ScenarioSetDigest: strings.Repeat("c", 64),
		PolicyVersions: []pack.AssuranceVersion{}, PackageVersions: []pack.AssuranceVersion{}, Scenarios: scs,
		Categories: map[string]pack.AssuranceCounts{}, Mismatches: []pack.AssuranceMismatch{}, Statement: pack.RangeStatement,
	})
	if err != nil {
		t.Fatal(err)
	}
	b := iss.Bundle()
	files := []pack.File{
		{Path: pack.AssurancePath, Kind: pack.KindAssurance, Data: doc},
		{Path: "proofs/bundle-0001.json", Kind: pack.KindBundle, Data: bundletest.Encode(t, b)},
	}
	m := pack.Manifest{
		Format: pack.Format, Pack: "0192aaaa-bbbb-7ccc-8ddd-0000000000ff", Org: b.Org, Origin: b.Origin,
		Exporter: pack.Exporter{Type: "user", ID: "0192aaaa-bbbb-7ccc-8ddd-0000000000ee"},
		Created:  bundletest.IssuedAt.Format(time.RFC3339), Expires: bundletest.IssuedAt.Add(7 * 24 * time.Hour).Format(time.RFC3339),
		Scope:   pack.Scope{Kind: pack.ScopeTransactions, Transactions: []string{}},
		Include: pack.Include{Receipts: true}, Filters: []string{}, EffectStates: map[string]int{},
		Transactions: []pack.TransactionState{}, Retention: []pack.Retention{}, Redactions: []string{}, Gaps: []pack.Gap{},
		Statement: pack.Statement,
	}
	for _, f := range files {
		m.Items = append(m.Items, pack.ItemOf(f))
	}
	payload, err := pack.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signer.Sign(pack.JWSType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err = pack.Write(files, compact, nil, bundletest.IssuedAt); err != nil {
		t.Fatal(err)
	}
	var tr bundle.Trust
	if err := json.Unmarshal(iss.Trust(), &tr); err != nil {
		t.Fatal(err)
	}
	tr.Keys = append(tr.Keys, bundle.TrustedKey{
		KID: signer.KeyID(), Purpose: bundle.PurposeEvidencePacks, Algorithm: bundle.AlgEdDSA, PublicKey: pub,
		NotBefore: bundletest.IssuedAt.Add(-time.Hour), State: bundle.StateActive,
	})
	if trust, err = json.Marshal(tr); err != nil {
		t.Fatal(err)
	}
	return raw, trust
}

func digestOf(t *testing.T, scenario string) string {
	t.Helper()
	s, err := rtdomain.Parse([]byte(scenario))
	if err != nil {
		t.Fatal(err)
	}
	d, err := rtdomain.Digest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestRedteamRunRecordsAndWritesTheSummary(t *testing.T) {
	re := newRangeEnv(t)
	code, out, errs := re.run(t, "--fixture", "pr=7")
	if code != 0 {
		t.Fatalf("run = %d\n%s\n%s", code, out, errs)
	}
	if len(re.ranges.started) != 1 || re.ranges.finished != 1 || len(re.ranges.recorded) != 1 {
		t.Fatalf("started %d recorded %d finished %d", len(re.ranges.started), len(re.ranges.recorded), re.ranges.finished)
	}
	st := re.ranges.started[0]
	if st.GetRangeAgentId() != rtAgent || len(st.GetScenarios()) != 1 || len(st.GetScenarios()[0].GetDigest()) != 64 {
		t.Fatalf("start %v", st)
	}
	rec := re.ranges.recorded[0]
	if st.GetScenarios()[0].GetStepCount() != 1 || rec.GetSteps()[0].GetKind() != "agent.call" {
		t.Fatalf("step_count %d, kind %q", st.GetScenarios()[0].GetStepCount(), rec.GetSteps()[0].GetKind())
	}
	if rec.GetVerdict() != pantherclawv1.RangeVerdict_RANGE_VERDICT_PASS || rec.GetScenarioDigest() != st.GetScenarios()[0].GetDigest() ||
		len(rec.GetSteps()) != 1 || rec.GetSteps()[0].GetObserved().GetOutcome() != "HOLD" || rec.GetSteps()[0].GetDecisiveControl() != "HR-201" ||
		rec.GetSteps()[0].GetTransactionId() != rtRange {
		t.Fatalf("recorded %v", rec)
	}
	b, err := os.ReadFile(filepath.Join(re.outDir, "0", "summary-"+rtRange+".json"))
	if err != nil || !strings.Contains(string(b), `"unsigned":true`) || !strings.Contains(string(b), "Not a compliance certification") {
		t.Fatalf("summary %q %v", b, err)
	}
	if !strings.Contains(out, "RT-001") || !strings.Contains(out, "1 PASS, 0 FAIL") {
		t.Errorf("table:\n%s", out)
	}
}

func TestRedteamRunUsageAndInfrastructureExitTwo(t *testing.T) {
	re := newRangeEnv(t)
	for name, args := range map[string][]string{
		"no scenarios flag": {"redteam", "run", "--workload-file", re.keyFile, "--gateway", re.gateway},
		"bad suite":         {"redteam", "run", "--scenarios", re.scenarios, "--workload-file", re.keyFile, "--gateway", re.gateway, "--suite", "everything"},
		"baseline no trust": {"redteam", "run", "--scenarios", re.scenarios, "--workload-file", re.keyFile, "--gateway", re.gateway, "--baseline", "x.zip"},
		"bad role":          {"redteam", "run", "--scenarios", re.scenarios, "--workload-file", re.keyFile, "--gateway", re.gateway, "--role", "https://evil"},
		"empty suite":       {"redteam", "run", "--scenarios", re.scenarios, "--workload-file", re.keyFile, "--gateway", re.gateway, "--suite", "platform"},
	} {
		if code, _, _ := run(t, re.env, args...); code != 2 {
			t.Errorf("%s: exit %d", name, code)
		}
	}
	if len(re.ranges.started) != 0 {
		t.Error("a range was started for a usage error")
	}
}

func TestHR226_TheBaselineGateExitsOneOnARegression(t *testing.T) {
	re := newRangeEnv(t)
	dir := t.TempDir()
	d := digestOf(t, rtScenario)
	good, trust := re.assurancePack(t, re.iss.Org.String(), []map[string]string{{"id": "RT-001", "digest": d, "verdict": "PASS"}})
	goodPath := writeFile(t, dir, "baseline.zip", good)
	trustPath := writeFile(t, dir, "trust.json", trust)

	// The control holds: still PASS, no regression, exit 0.
	if code, out, errs := re.run(t, "--baseline", goodPath, "--trust", trustPath); code != 0 {
		t.Fatalf("clean run = %d\n%s\n%s", code, out, errs)
	}
	if got := re.ranges.started[0].GetBaselineRangeId(); got != rtRange {
		t.Errorf("baseline range id %q", got)
	}

	// The control is weakened: the gateway now allows the merge. The scenario
	// FAILS and the run exits 1, reporting the regression from the baseline.
	allow := `{"decision":"allow","action_id":"a1"}`
	*re.decision = allow
	code, out, errs := re.run(t, "--baseline", goodPath, "--trust", trustPath)
	if code != 1 || !strings.Contains(errs, "regressed from the baseline: RT-001 (FAIL)") || !strings.Contains(out, "Regressions from the baseline") {
		t.Fatalf("weakened run = %d\n%s\n%s", code, out, errs)
	}

	// A scenario that passed in the baseline and is gone now is a regression
	// too, with no FAIL anywhere.
	*re.decision = `{"decision":"hold","error_class":"held","code":"REQUIRE_APPROVAL"}`
	missing, trust2 := re.assurancePack(t, re.iss.Org.String(), []map[string]string{
		{"id": "RT-001", "digest": d, "verdict": "PASS"}, {"id": "RT-777", "digest": strings.Repeat("a", 64), "verdict": "PASS"},
	})
	code, _, errs = re.run(t, "--baseline", writeFile(t, dir, "missing.zip", missing), "--trust", writeFile(t, dir, "trust2.json", trust2))
	if code != 1 || !strings.Contains(errs, "RT-777 (MISSING)") {
		t.Fatalf("missing scenario = %d\n%s", code, errs)
	}

	// A baseline that does not verify is no baseline: exit 2 and no range.
	n := len(re.ranges.started)
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)/2] ^= 0xff
	code, _, errs = re.run(t, "--baseline", writeFile(t, dir, "tampered.zip", tampered), "--trust", trustPath)
	if code != 2 || len(re.ranges.started) != n {
		t.Fatalf("tampered baseline = %d (ranges %d→%d)\n%s", code, n, len(re.ranges.started), errs)
	}
	code, _, _ = re.run(t, "--baseline", goodPath, "--trust", writeFile(t, dir, "other-trust.json", []byte(`{}`)))
	if code != 2 {
		t.Fatalf("a baseline against the wrong trust file = %d", code)
	}
}

func TestRedteamRunSkipsWhatItCannotDo(t *testing.T) {
	re := newRangeEnv(t)
	probe := strings.NewReplacer("RT-001", "RT-002", "A merge is held", "A probe").Replace(rtScenario)
	head, _, _ := strings.Cut(probe, "steps:")
	probe = head + "steps:\n  - {id: probe, do: sandbox.probe, with: {probe: icmp}, expect: {outcome: BLOCKED}}\n"
	writeFile(t, re.scenarios, "RT-002-probe.yaml", []byte(probe))
	code, out, errs := re.run(t)
	if code != 0 || !strings.Contains(out, "1 PASS, 0 FAIL, 0 ERROR, 1 SKIPPED") {
		t.Fatalf("run = %d\n%s\n%s", code, out, errs)
	}
}

// fakeSetup records the creates `redteam setup` makes.
type fakeSetup struct {
	pantherclawv1connect.UnimplementedAgentServiceHandler
	pantherclawv1connect.UnimplementedConnectionServiceHandler
	pantherclawv1connect.UnimplementedGrantServiceHandler
	mu       sync.Mutex
	agents   []*pantherclawv1.CreateAgentRequest
	conns    []*pantherclawv1.CreateConnectionRequest
	grants   []*pantherclawv1.IssueGrantRequest
	existing []*pantherclawv1.Agent
}

func (f *fakeSetup) ListAgents(context.Context, *pantherclawv1.ListAgentsRequest) (*pantherclawv1.ListAgentsResponse, error) {
	return &pantherclawv1.ListAgentsResponse{Agents: f.existing}, nil
}

func (f *fakeSetup) CreateAgent(_ context.Context, r *pantherclawv1.CreateAgentRequest) (*pantherclawv1.CreateAgentResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.agents = append(f.agents, r)
	return &pantherclawv1.CreateAgentResponse{Agent: &pantherclawv1.Agent{Id: rtAgent, Name: r.GetName(), RangeAgent: true}}, nil
}

func (f *fakeSetup) ListConnections(context.Context, *pantherclawv1.ListConnectionsRequest) (*pantherclawv1.ListConnectionsResponse, error) {
	return &pantherclawv1.ListConnectionsResponse{Connections: []*pantherclawv1.Connection{{
		Id: "c1", Name: "github", Kind: pantherclawv1.ConnectionKind_CONNECTION_KIND_HTTP, GatewayId: "g1", Package: "github",
		BaseUrl: "https://api.github.com", AccessMode: pantherclawv1.AccessMode_ACCESS_MODE_PANTHERCLAW_HELD,
		CredentialHeader: "Authorization", CredentialScheme: "Bearer", State: pantherclawv1.ConnectionState_CONNECTION_STATE_ACTIVE,
	}}}, nil
}

func (f *fakeSetup) CreateConnection(_ context.Context, r *pantherclawv1.CreateConnectionRequest) (*pantherclawv1.CreateConnectionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.conns = append(f.conns, r)
	return &pantherclawv1.CreateConnectionResponse{}, nil
}

func (f *fakeSetup) GetGrant(context.Context, *pantherclawv1.GetGrantRequest) (*pantherclawv1.GetGrantResponse, error) {
	return &pantherclawv1.GetGrantResponse{Grant: &pantherclawv1.Grant{
		Id: "0192aaaa-bbbb-7ccc-8ddd-0000000000a9", Principal: &pantherclawv1.Actor{Kind: "user", Id: rtAgent},
		Bounds: []byte(`{"v":1}`), Limits: []byte(`{"counters":[]}`), MinAttestationLevel: 1,
	}}, nil
}

func (f *fakeSetup) ListGrants(context.Context, *pantherclawv1.ListGrantsRequest) (*pantherclawv1.ListGrantsResponse, error) {
	return &pantherclawv1.ListGrantsResponse{}, nil
}

func (f *fakeSetup) IssueGrant(_ context.Context, r *pantherclawv1.IssueGrantRequest) (*pantherclawv1.IssueGrantResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants = append(f.grants, r)
	return &pantherclawv1.IssueGrantResponse{}, nil
}

func TestRedteamSetupPlansFirstAndDryRunChangesNothing(t *testing.T) {
	fake := &fakeSetup{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterAgentServiceHandler(cs, fake)
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, fake)
	pantherclawv1connect.RegisterGrantServiceHandler(cs, fake)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": srv.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	id := "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	args := []string{
		"redteam", "setup", "--name", "range", "--team", id, "--env", id, "--owner", id, "--context", "ci",
		"--twin", "github=http://127.0.0.1:9100", "--like-grant", "0192aaaa-bbbb-7ccc-8ddd-0000000000a9",
	}

	code, out, errs := run(t, env, append(args, "--dry-run")...)
	if code != 0 || !strings.Contains(out, "Plan:") || !strings.Contains(out, `"github-range"`) || !strings.Contains(out, "Dry run: nothing was changed.") ||
		len(fake.agents)+len(fake.conns)+len(fake.grants) != 0 {
		t.Fatalf("dry run = %d\n%s\n%s\nagents %d conns %d grants %d", code, out, errs, len(fake.agents), len(fake.conns), len(fake.grants))
	}

	code, out, errs = run(t, env, append(args, "--yes")...)
	if code != 0 || len(fake.agents) != 1 || len(fake.conns) != 1 || len(fake.grants) != 1 {
		t.Fatalf("apply = %d\n%s\n%s", code, out, errs)
	}
	if !fake.agents[0].GetRangeAgent() || fake.agents[0].GetExecutionContext() != pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_CI {
		t.Errorf("agent %v", fake.agents[0])
	}
	cn := fake.conns[0]
	if !cn.GetSimulated() || cn.GetName() != "github-range" || cn.GetBaseUrl() != "http://127.0.0.1:9100" || cn.GetGatewayId() != "g1" ||
		cn.GetAccessMode() != pantherclawv1.AccessMode_ACCESS_MODE_PANTHERCLAW_HELD || len(cn.GetAllowedHosts()) != 0 {
		t.Errorf("twin %v", cn)
	}
	g := fake.grants[0]
	if g.GetAgentId() != rtAgent || string(g.GetBounds()) != `{"v":1}` || g.GetMinAttestationLevel() != 1 || g.GetExpireTime() == nil {
		t.Errorf("grant %v", g)
	}

	// An agent of that name that is not a range agent stops the setup.
	fake.existing = []*pantherclawv1.Agent{{Id: rtAgent, Name: "range"}}
	if code, _, _ := run(t, env, append(args, "--yes")...); code == 0 || len(fake.agents) != 1 {
		t.Errorf("a real agent named range was reused: %d", code)
	}
}

func TestRedteamRunAnErrorFailsClosed(t *testing.T) {
	re := newRangeEnv(t)
	*re.decision = `not json`
	code, out, errs := re.run(t)
	if code != 1 || !strings.Contains(out, "1 ERROR") || !strings.Contains(errs, "RT-001 (ERROR)") {
		t.Fatalf("run = %d\n%s\n%s", code, out, errs)
	}
}

func TestRedteamBaselineOfAnotherOrgIsRefused(t *testing.T) {
	re := newRangeEnv(t)
	dir := t.TempDir()
	d := digestOf(t, rtScenario)
	other, trust := re.assurancePack(t, "0192aaaa-bbbb-7ccc-8ddd-0000000000f9", []map[string]string{{"id": "RT-001", "digest": d, "verdict": "PASS"}})
	code, _, errs := re.run(t, "--baseline", writeFile(t, dir, "other.zip", other), "--trust", writeFile(t, dir, "trust.json", trust))
	if code != 2 || !strings.Contains(errs, "BASELINE_INVALID") || len(re.ranges.started) != 0 {
		t.Fatalf("another org's baseline = %d (ranges %d)\n%s", code, len(re.ranges.started), errs)
	}
	own, trust := re.assurancePack(t, re.iss.Org.String(), []map[string]string{{"id": "RT-001", "digest": d, "verdict": "PASS"}})
	code, out, errs := re.run(t, "--baseline", writeFile(t, dir, "own.zip", own), "--trust", writeFile(t, dir, "trust2.json", trust))
	if code != 0 || !strings.Contains(out, "Baseline: range "+rtRange+", finished 2026-10-14T08:05:00Z, 1 scenarios") {
		t.Fatalf("own baseline = %d\n%s\n%s", code, out, errs)
	}
}

func TestRecordRequestRecordsWhatWasObserved(t *testing.T) {
	step := func(expect rtdomain.Expect, obs rtdomain.Observation) rtdomain.StepResult {
		return rtdomain.StepResult{StepID: "s", Expect: expect, Observed: obs, Matched: true}
	}
	// The expected reason is recorded as observed only when the decision carried it.
	got := observedOf(step(rtdomain.Expect{Outcome: rtdomain.OutcomeDeny, Reason: "B"}, rtdomain.Observation{Outcome: rtdomain.OutcomeDeny, Reason: "A", Reasons: []string{"A", "B"}}))
	if got.GetOutcome() != "DENY" || got.GetReason() != "B" {
		t.Errorf("carried reason: %v", got)
	}
	got = observedOf(step(rtdomain.Expect{Reason: "B"}, rtdomain.Observation{Outcome: rtdomain.OutcomeDeny, Reason: "A", Reasons: []string{"A"}}))
	if got.GetReason() != "A" {
		t.Errorf("an expectation was recorded as an observation: %v", got)
	}
	// An outcome is the observed one, even when the step has no expectation of it.
	got = observedOf(step(rtdomain.Expect{}, rtdomain.Observation{Outcome: rtdomain.OutcomeHold, Code: "c"}))
	if got.GetOutcome() != "HOLD" || got.GetCode() != "c" {
		t.Errorf("observed: %v", got)
	}
	// A concurrent step records its non-ALLOW outcome, or ALLOW.
	each := rtdomain.Observation{Each: []rtdomain.Observation{{Outcome: rtdomain.OutcomeAllow}, {Outcome: rtdomain.OutcomeDeny}}}
	if got = observedOf(step(rtdomain.Expect{}, each)); got.GetOutcome() != "DENY" {
		t.Errorf("concurrent: %v", got)
	}
}

// pagedSetup serves agents and connections one per page.
type pagedSetup struct {
	fakeSetup
	agentPages, connPages int
}

func (f *pagedSetup) ListAgents(_ context.Context, r *pantherclawv1.ListAgentsRequest) (*pantherclawv1.ListAgentsResponse, error) {
	f.agentPages++
	if r.GetPageToken() == "" {
		return &pantherclawv1.ListAgentsResponse{Agents: []*pantherclawv1.Agent{{Id: "a1", Name: "other"}}, NextPageToken: "p2"}, nil
	}
	return &pantherclawv1.ListAgentsResponse{Agents: []*pantherclawv1.Agent{{Id: rtAgent, Name: "range", RangeAgent: true}}}, nil
}

func (f *pagedSetup) ListConnections(ctx context.Context, r *pantherclawv1.ListConnectionsRequest) (*pantherclawv1.ListConnectionsResponse, error) {
	f.connPages++
	if r.GetPageToken() == "" {
		return &pantherclawv1.ListConnectionsResponse{Connections: []*pantherclawv1.Connection{{Id: "x", Name: "unrelated", Package: "other"}}, NextPageToken: "p2"}, nil
	}
	return f.fakeSetup.ListConnections(ctx, r)
}

func TestRedteamSetupPagesThroughAgentsAndConnections(t *testing.T) {
	fake := &pagedSetup{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterAgentServiceHandler(cs, fake)
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, fake)
	pantherclawv1connect.RegisterGrantServiceHandler(cs, fake)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": srv.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	id := "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	// The only real github connection and the range agent are on page 2: both
	// must be seen.
	code, _, errs := run(t, env, "redteam", "setup", "--name", "range", "--team", id, "--env", id, "--owner", id, "--context", "ci",
		"--twin", "github=http://127.0.0.1:9100", "--dry-run")
	if fake.agentPages != 2 || fake.connPages != 2 {
		t.Fatalf("pages: agents %d connections %d", fake.agentPages, fake.connPages)
	}
	if code != 0 {
		t.Errorf("setup = %d %q", code, errs)
	}
}

func TestRedteamRunCarriesOnWhenRecordingFails(t *testing.T) {
	re := newRangeEnv(t)
	second := strings.NewReplacer("RT-001", "RT-002", "A merge is held", "A second merge is held").Replace(rtScenario)
	writeFile(t, re.scenarios, "RT-002-second.yaml", []byte(second))
	re.ranges.failRecord = true
	code, out, errs := re.run(t)
	if code != 2 || re.ranges.attempts != 2 || re.ranges.finished != 1 || !strings.Contains(errs, "recording RT-001") || !strings.Contains(errs, "recording RT-002") {
		t.Fatalf("run = %d attempts %d finished %d\n%s\n%s", code, re.ranges.attempts, re.ranges.finished, out, errs)
	}
}

func TestRecordRequestSendsOnlyStepsThatObservedSomething(t *testing.T) {
	res := rtdomain.Result{ScenarioID: "RT-001", Digest: strings.Repeat("a", 64), Verdict: rtdomain.VerdictError, Steps: []rtdomain.StepResult{
		{StepID: "done", Expect: rtdomain.Expect{Outcome: rtdomain.OutcomeHold}, Observed: rtdomain.Observation{Outcome: rtdomain.OutcomeHold}, Matched: true},
		{StepID: "broke", Expect: rtdomain.Expect{Outcome: rtdomain.OutcomeAllow}},
	}}
	req := recordRequest(rtRange, rtdomain.Scenario{Steps: []rtdomain.Step{{ID: "done", Do: "agent.call"}}}, res)
	if req.GetVerdict() != pantherclawv1.RangeVerdict_RANGE_VERDICT_ERROR || len(req.GetSteps()) != 1 || req.GetSteps()[0].GetStepId() != "done" {
		t.Fatalf("%v", req)
	}
}
