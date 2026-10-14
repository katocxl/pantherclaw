// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// rangeDriver is the harness driver of the adversarial range (D15): it runs
// one scenario's steps against a stack of its own, with the simulators of
// the roles the scenario requires. The stack is a real server, gateway and
// database; only the targets are simulators.
type rangeDriver struct {
	t   *testing.T
	sc  domain.Scenario
	s   *stack
	fix app.Fixture

	people *m2Stack
	admin  *user
	// Approvers: bob (payments) or carol and rachel (GitHub).
	reviewers []reviewer

	recs map[string]*callRec

	other *stack // the second organisation

	extra rangeExtra // sandbox, per build tag

	// asRun is the run calls are made in while a child acts; empty: the seeded run.
	asRun string
	// defaultRun is the run of a grant of the scenario.s own, when it has one.
	defaultRun string
}

type reviewer struct {
	b   *browser
	key *webauthntest.Authenticator
}

// callRec is what a call step sent and saw, for later steps that refer to it.
type callRec struct {
	act      ids.UUID
	txn      string
	obs      domain.Observation
	dispatch *rangeDispatch
	signed   *recordedRequest
}

func newRangeDriver(t *testing.T) *rangeDriver {
	return &rangeDriver{t: t, recs: map[string]*callRec{}}
}

// Capabilities are what this driver can run.
func (d *rangeDriver) Capabilities() map[app.Capability]bool {
	return map[app.Capability]bool{
		app.CapGitHub: true, app.CapPayments: true, app.CapMCP: true, app.CapPerson: true, app.CapSecondOrg: true,
		app.CapHarness: true, app.CapSandbox: d.extra.available(),
	}
}

func requires(s domain.Scenario, what string) bool { return slices.Contains(s.Requires, what) }

// Teardown has nothing of its own to do: the stack's servers and database
// stop with the test.
func (d *rangeDriver) Teardown(context.Context, domain.Scenario) error { return nil }

// Setup starts the stack the scenario needs and its fixtures.
func (d *rangeDriver) Setup(_ context.Context, sc domain.Scenario) (app.Fixture, error) {
	t := d.t
	d.sc = sc
	o := options{budget: "1000.00", shell: sc.ID == "RT-016"}
	switch sc.ID {
	case "RT-026":
		o.budget = "100.00"
	case "RT-027":
		o.maxCount = 2
	case "RT-036":
		o.access, o.actionTokens = capp.AccessTargetEnforced, true
	}
	var p idp
	if requires(sc, "person") || sc.ID == "RT-009" {
		p = inProcessIdP(t)
		o.people = &p
	}
	o.github = requires(sc, "github") || requires(sc, "sandbox")
	if sc.ID == "RT-011" {
		o.github = true
	}
	d.s = start(t, o)
	d.fix = app.Fixture{}
	if o.people != nil {
		d.people = &m2Stack{url: d.s.apiURL, cfg: d.s.serverCfg, idp: p}
	}
	if requires(sc, "person") {
		d.setupPeople()
	}
	if o.github {
		d.setupGitHub()
	}
	if requires(sc, "second_org") {
		d.other = start(t, options{budget: "1000.00"})
	}
	d.setupPayments()
	if sc.ID == "RT-009" {
		d.ownGrant(`{"operations": ["github.contents.write"], "targets": {"github.branch": {"prefixes": ["acme/payments@"]}}}`, "")
	}
	if err := d.extra.setup(d); err != nil {
		return nil, err
	}
	return d.fix, nil
}

// setupPayments makes the charges the scenarios refund refundable.
func (d *rangeDriver) setupPayments() {
	for i := 2; i <= 50; i++ {
		refundableMore(d.t, d.s, "ch_"+strconv.Itoa(i))
	}
}

// setupGitHub opens the pull request the scenarios work on: a branch with a
// fix and a pull request for it, as an agent would, and fills the fixtures.
func (d *rangeDriver) setupGitHub() {
	t, s := d.t, d.s
	gh := s.gh.sim
	main := gh.Branch(ghRepo, "main")
	steps := []struct{ method, path, body string }{
		{http.MethodPost, "/repos/" + ghRepo + "/git/refs", `{"ref":"refs/heads/fix/cve","sha":"` + main + `"}`},
		{http.MethodPut, "/repos/" + ghRepo + "/contents/src/parser.go", `{"message":"Fix the parser","content":"` +
			base64.StdEncoding.EncodeToString([]byte("package parser // fixed\n")) + `","branch":"fix/cve"}`},
		{http.MethodPost, "/repos/" + ghRepo + "/pulls", `{"title":"Fix the parser","head":"fix/cve","base":"main"}`},
	}
	for _, st := range steps {
		if code, r, raw := s.ghCall(t, st.method, st.path, st.body, ids.NewV7()); code >= 300 {
			t.Fatalf("setup %s %s: %d %+v %s", st.method, st.path, code, r, raw)
		}
	}
	pr, ok := gh.PullRequest(ghRepo, 1)
	if !ok {
		t.Fatal("setup: no pull request 1")
	}
	owner, repo, _ := strings.Cut(ghRepo, "/")
	token := "ghp_" + strings.Repeat("a1B2", 9)
	d.fix["owner"], d.fix["repo"], d.fix["other_repo"] = owner, repo, "secrets"
	d.fix["pr"], d.fix["head"], d.fix["main"] = "1", pr.HeadSHA, main
	d.fix["file_b64"] = base64.StdEncoding.EncodeToString([]byte("package notes\n"))
	d.fix["fake_github_token"] = token
	d.fix["fake_github_token_file_b64"] = base64.StdEncoding.EncodeToString([]byte("package config\n\nconst token = \"" + token + "\"\n"))
	d.fix["custody_secret"] = d.custodySecret()
}

// custodySecret is a secret the gateway holds for the GitHub connection: the
// App's private key.
func (d *rangeDriver) custodySecret() string {
	return string(pemOfGitHubKey(d.s.gh))
}

// setupPeople makes the approvers: carol and rachel for GitHub merges (as
// in the M8 exit), bob for payments.
func (d *rangeDriver) setupPeople() {
	t, s := d.t, d.s
	if requires(d.sc, "github") {
		var out, errb bytes.Buffer
		if code := runServerCmd(&out, &errb, "org", "admin-invite", "--config", s.serverCfg, "--org", s.org.String()); code != 0 {
			t.Fatalf("org admin-invite: %d %s", code, errb.String())
		}
		alice := d.people.user(t, "alice", "alice@example.test")
		alice.login(t, s.org.String(), pciToken.FindStringSubmatch(out.String())[1])
		d.admin = alice
		_, carolB, carolKey, carol := s.reviewer(t, d.people, alice, "carol", td.RoleName("code_reviewer"))
		_, rachelB, rachelKey, rachel := s.reviewer(t, d.people, alice, "rachel", td.RoleName("release_approver"))
		s.db.AdminExec(t, `UPDATE pc.webauthn_credentials SET state = 'REMOVED', state_reason = 'ADMIN_REMOVED', changed_at = now()
			WHERE org_id = $1 AND name = 'key'`, s.org)
		if code, out, errs := alice.pclaw(t, "approver-keys", "export", "--out", s.approverKeys); code != 0 || !strings.Contains(out, "2 key(s)") {
			t.Fatalf("approver-keys export: %d %s %s", code, out, errs)
		}
		s.linkGitHub(t, carol, "carol-gh")
		s.linkGitHub(t, rachel, "rachel-gh")
		d.reviewers = []reviewer{{carolB, carolKey}, {rachelB, rachelKey}}
		// A change window for production is open, so only a hold's own
		// reasons stand between the approved merge and its running.
		s.exec(t, `INSERT INTO pc.change_windows (org_id, id, environment, time_zone, one_off, freezes, revision, created_by)
			VALUES ($1, $2, 'production', 'UTC', jsonb_build_array(jsonb_build_object('start', now() - interval '1 hour', 'end', now() + interval '1 hour')),
			'[]'::jsonb, 1, 'range')`, s.org, ids.NewV7())
		return
	}
	alice, b, key := approver(t, s, d.people)
	d.admin = alice
	d.reviewers = []reviewer{{b, key}}
}

// Do runs one step.
func (d *rangeDriver) Do(ctx context.Context, sc domain.Scenario, st domain.Step, vars map[string]string) (domain.Observation, error) {
	switch st.Do {
	case "agent.call":
		return d.agentCall(ctx, st, vars)
	case "person.approve":
		return d.personApprove(st)
	case "wait":
		return d.wait(ctx, st)
	case "sim.mutate":
		return d.simMutate(st)
	case "check.receipt":
		return d.checkReceipt(st)
	case "target.replay":
		return d.targetReplay(st)
	case "agent.steal":
		return d.agentSteal(ctx, st)
	case "agent.child":
		return d.agentChild(ctx, st, vars)
	case "server.read":
		return d.serverRead(st)
	case "operator.revoke_grant":
		return d.revokeGrant()
	case "operator.kill_switch":
		return d.killSwitch()
	case "sandbox.probe":
		return d.extra.probe(d, st)
	}
	return domain.Observation{}, fmt.Errorf("the harness driver does not run %s", st.Do)
}

// callWith is the agent.call arguments the driver reads.
type callWith struct {
	Face       string         `json:"face"`
	Connection string         `json:"connection"`
	Tool       string         `json:"tool"`
	Method     string         `json:"method"`
	Path       string         `json:"path"`
	Args       jsontext.Value `json:"args"`
	Body       jsontext.Value `json:"body"`
	Instance   string         `json:"instance"`
	Concurrent int            `json:"concurrent"`
	ActionOf   string         `json:"action_of"`
	Fault      string         `json:"fault"`
	// run is the run the call is made in; empty is the seeded one.
	run string
}

func (d *rangeDriver) agentCall(ctx context.Context, st domain.Step, _ map[string]string) (domain.Observation, error) {
	var w callWith
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	if w.Concurrent > 0 {
		return d.concurrent(ctx, st, w)
	}
	obs, rec, err := d.callOnce(w, st.With, 0)
	if err != nil {
		return obs, err
	}
	d.recs[st.ID] = rec
	return obs, nil
}

func (d *rangeDriver) concurrent(_ context.Context, st domain.Step, w callWith) (domain.Observation, error) {
	each := make([]domain.Observation, w.Concurrent)
	errs := make([]error, w.Concurrent)
	var wg sync.WaitGroup
	for i := range w.Concurrent {
		wg.Go(func() {
			raw := bytes.ReplaceAll(st.With, []byte("${n}"), []byte(strconv.Itoa(i+1)))
			var one callWith
			if err := json.Unmarshal(raw, &one); err != nil {
				errs[i] = err
				return
			}
			each[i], _, errs[i] = d.callOnce(one, raw, i+1)
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return domain.Observation{}, err
	}
	return domain.Observation{Each: each}, nil
}

// callOnce sends one call over its face and returns what the gateway said.
func (d *rangeDriver) callOnce(w callWith, _ []byte, _ int) (domain.Observation, *callRec, error) {
	if w.run != "" {
		d.asRun = w.run
		defer func() { d.asRun = "" }()
	}
	act := ids.NewV7()
	if w.ActionOf != "" {
		prev, ok := d.recs[w.ActionOf]
		if !ok {
			return domain.Observation{}, nil, fmt.Errorf("action_of %s: no such call", w.ActionOf)
		}
		act = prev.act
	}
	conn := d.role(w.Connection)
	switch w.Face {
	case "http":
		return d.callHTTP(conn, w, act)
	case "mcp":
		return d.callMCP(conn, w, act)
	case "sdk":
		return d.callSDK(conn, w, act)
	case "hook":
		return d.callHook(w)
	}
	return domain.Observation{}, nil, fmt.Errorf("face %q", w.Face)
}

// role is the gateway's name of a connection role.
func (d *rangeDriver) role(r string) string {
	switch r {
	case "mcp":
		return "mcp-upstream"
	}
	return r
}

// signed is a gateway client for the seeded workload (instance "other" is
// another enrolled instance of the agent).
func (d *rangeDriver) client(instance string) *http.Client {
	key, token := d.s.key, d.s.token
	if instance == "other" {
		key, token = d.otherInstance()
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: &workloadclient.Transport{
		Key: key, Token: func() string { return token }, Base: http.DefaultTransport,
	}}
}

func (d *rangeDriver) callHTTP(conn string, w callWith, act ids.UUID) (domain.Observation, *callRec, error) {
	var body io.Reader
	if len(w.Body) > 0 {
		b := []byte(w.Body)
		if w.Body.Kind() == '"' {
			var s string
			if err := json.Unmarshal(w.Body, &s); err != nil {
				return domain.Observation{}, nil, err
			}
			b = []byte(s)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), w.Method, d.s.gateway+"/"+conn+w.Path, body)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(gateway.HeaderRunID, d.runHeader())
	req.Header.Set(gateway.HeaderActionID, act.String())
	resp, err := d.client(w.Instance).Do(req)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	obs := observeREST(resp.StatusCode, resp.Header, raw)
	return obs, &callRec{act: act, txn: obs.TransactionID, obs: obs}, nil
}

// facts is what the gateway says about a call it did not run, or ran.
type facts struct {
	ErrorClass    string   `json:"error_class"`
	Error         string   `json:"error"`
	Decision      string   `json:"decision"`
	Reasons       []string `json:"reasons"`
	TransactionID string   `json:"transaction_id"`
	Outcome       string   `json:"outcome"`
}

// observeREST reads a REST answer: the target's body with PC-* headers when
// the call ran, otherwise the typed refusal.
func observeREST(status int, h http.Header, raw []byte) domain.Observation {
	if status < 300 {
		return domain.Observation{
			Outcome: domain.OutcomeAllow, TransactionID: h.Get("PC-Transaction-Id"), Response: capBytes(raw),
			Detail: "PC-Outcome " + h.Get("PC-Outcome"),
		}
	}
	var f facts
	if err := json.Unmarshal(raw, &f, json.RejectUnknownMembers(false)); err != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: fmt.Sprintf("http_%d", status), Detail: string(raw)}
	}
	return classify(f, string(capBytes(raw)))
}

// classify turns the gateway's facts into one of the range's outcomes.
func classify(f facts, detail string) domain.Observation {
	o := domain.Observation{Reasons: f.Reasons, TransactionID: f.TransactionID, Detail: detail}
	if len(f.Reasons) > 0 {
		o.Reason = f.Reasons[0]
	}
	switch {
	case f.Outcome == "UNKNOWN":
		o.Outcome = domain.OutcomeUnknown
	case f.ErrorClass == "held":
		o.Outcome = domain.OutcomeHold
	case f.Decision == "DENY":
		o.Outcome = domain.OutcomeDeny
	case f.Decision == "REQUIRE_APPROVAL":
		o.Outcome = domain.OutcomeHold
	case f.Decision == "CANNOT_AUTHORIZE" && len(f.Reasons) > 0:
		o.Outcome = domain.OutcomeCannotAuthorize
	case f.ErrorClass == "target_refused":
		o.Outcome, o.Code = domain.OutcomeTargetRefused, f.Error
	default:
		o.Outcome, o.Code = domain.OutcomeRefused, f.Error
	}
	return o
}

func capBytes(b []byte) []byte {
	if len(b) > domain.MaxResponseBytes {
		return b[:domain.MaxResponseBytes]
	}
	return b
}

// mcpCall sends a tools/call over the MCP face and returns the status and the
// body of the answer.
func (d *rangeDriver) mcpRequest(conn, tool string, args any, instance string) (int, []byte, error) {
	params := map[string]any{
		"name": tool, "arguments": args,
		"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
	}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, d.s.gateway+"/mcp/"+conn, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", tool)
	req.Header.Set(gateway.HeaderRunID, d.runHeader())
	resp, err := d.client(instance).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if i := bytes.Index(raw, []byte("data: ")); i >= 0 {
		raw = bytes.TrimSpace(raw[i+len("data: "):])
	}
	return resp.StatusCode, raw, nil
}

// argsOf decodes a call's arguments, typing the numeric ones the scenario had
// to write as strings (substitution only yields strings).
func argsOf(v jsontext.Value) (any, error) {
	var m map[string]any
	if len(v) == 0 {
		return map[string]any{}, nil
	}
	if err := json.Unmarshal(v, &m); err != nil {
		return nil, err
	}
	if s, ok := m["pullNumber"].(string); ok {
		if n, err := strconv.Atoi(s); err == nil {
			m["pullNumber"] = n
		}
	}
	return m, nil
}

func (d *rangeDriver) callMCP(conn string, w callWith, act ids.UUID) (domain.Observation, *callRec, error) {
	args, err := argsOf(w.Args)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	status, raw, err := d.mcpRequest(strings.TrimPrefix(conn, "mcp/"), w.Tool, args, w.Instance)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	obs := observeMCP(status, raw)
	return obs, &callRec{act: act, txn: obs.TransactionID, obs: obs}, nil
}

func observeMCP(status int, raw []byte) domain.Observation {
	var out struct {
		Result struct {
			IsError bool                                 `json:"isError"`
			Meta    map[string]map[string]jsontext.Value `json:"_meta"`
		} `json:"result"`
		Error struct {
			Data map[string]string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out, json.RejectUnknownMembers(false)); err != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: fmt.Sprintf("http_%d", status), Detail: string(capBytes(raw))}
	}
	if status == http.StatusUnauthorized || out.Error.Data != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: out.Error.Data["error"], Detail: string(capBytes(raw))}
	}
	if !out.Result.IsError {
		obs := domain.Observation{Outcome: domain.OutcomeAllow, Response: capBytes(raw)}
		var ok struct {
			Structured jsontext.Value `json:"structuredContent"`
		}
		if json.Unmarshal(raw, &ok, json.RejectUnknownMembers(false)) == nil {
			var r2 struct {
				Result struct {
					Structured jsontext.Value                       `json:"structuredContent"`
					Meta       map[string]map[string]jsontext.Value `json:"_meta"`
				} `json:"result"`
			}
			if json.Unmarshal(raw, &r2, json.RejectUnknownMembers(false)) == nil {
				if len(r2.Result.Structured) > 0 {
					obs.Response = capBytes(r2.Result.Structured)
				}
				_ = json.Unmarshal(r2.Result.Meta["io.pantherclaw/result"]["transaction_id"], &obs.TransactionID)
			}
		}
		return obs
	}
	var f facts
	m := out.Result.Meta["io.pantherclaw/error"]
	str := func(n string) string {
		var s string
		_ = json.Unmarshal(m[n], &s)
		return s
	}
	f.ErrorClass, f.Error, f.Decision, f.Outcome, f.TransactionID = str("error_class"), str("error"), str("decision"), str("outcome"), str("transaction_id")
	_ = json.Unmarshal(m["reasons"], &f.Reasons)
	return classify(f, string(capBytes(raw)))
}

// stepRec is the call record of an earlier step.
func (d *rangeDriver) stepRec(id string) (*callRec, error) {
	r, ok := d.recs[id]
	if !ok {
		return nil, fmt.Errorf("step %s made no call", id)
	}
	return r, nil
}

func (d *rangeDriver) wait(ctx context.Context, st domain.Step) (domain.Observation, error) {
	var w struct {
		For, Of    string
		MaxSeconds int `json:"max_seconds"`
	}
	raw := bytes.NewReader(st.With)
	var m map[string]jsontext.Value
	if err := json.UnmarshalRead(raw, &m); err != nil {
		return domain.Observation{}, err
	}
	_ = json.Unmarshal(m["for"], &w.For)
	_ = json.Unmarshal(m["of"], &w.Of)
	_ = json.Unmarshal(m["max_seconds"], &w.MaxSeconds)
	rec, err := d.stepRec(w.Of)
	if err != nil {
		return domain.Observation{}, err
	}
	if rec.txn == "" {
		return domain.Observation{}, fmt.Errorf("step %s has no transaction to wait for", w.Of)
	}
	want := map[string]string{"effect_confirmed": "CONFIRMED", "effect_unknown": "UNKNOWN"}[w.For]
	deadline := time.Now().Add(time.Duration(w.MaxSeconds) * time.Second)
	var last string
	for {
		d.s.query(d.t, "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1", []any{rec.txn}, &last)
		if last == want {
			return domain.Observation{Outcome: domain.Outcome(want), TransactionID: rec.txn}, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return domain.Observation{Outcome: domain.OutcomeUnknown, TransactionID: rec.txn, Detail: "effect state " + last}, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ensure the ed25519 import is used by the signing helpers in range_steal_test.go.
var _ ed25519.PrivateKey
