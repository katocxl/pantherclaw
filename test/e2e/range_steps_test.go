// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"time"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/sdk"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/redteam/receipt"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type rangeDispatch = sdk.Dispatch

// pemOfGitHubKey is the PEM of the App's private key: what the gateway holds
// in custody for the github connection.
func pemOfGitHubKey(g *githubSim) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(g.key)})
}

// callSDK sends the call over the SDK face and answers as the gateway did.
func (d *rangeDriver) callSDK(conn string, w callWith, act ids.UUID) (domain.Observation, *callRec, error) {
	args, err := argsOf(w.Args)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	body, err := json.Marshal(map[string]any{
		"tool": "mcp__" + conn + "__" + w.Tool, "server": conn, "tool_use_id": "toolu_" + act.String()[:8], "input": args,
	})
	if err != nil {
		return domain.Observation{}, nil, err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, d.s.gateway+"/sdk/"+conn, bytes.NewReader(body))
	if err != nil {
		return domain.Observation{}, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(gateway.HeaderRunID, d.runHeader())
	req.Header.Set(gateway.HeaderActionID, act.String())
	resp, err := d.client(w.Instance).Do(req)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var a sdk.Answer
	if err := json.Unmarshal(raw, &a, json.RejectUnknownMembers(false)); err != nil || resp.StatusCode != http.StatusOK {
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: fmt.Sprintf("http_%d", resp.StatusCode), Detail: string(capBytes(raw))},
			&callRec{act: act}, nil
	}
	var obs domain.Observation
	switch a.Decision {
	case "allow":
		obs = domain.Observation{Outcome: domain.OutcomeAllow}
	case "hold":
		obs = domain.Observation{Outcome: domain.OutcomeHold}
	default:
		obs = classify(facts{ErrorClass: a.ErrorClass, Error: a.Code, Decision: strings.ToUpper(a.Decision), Reasons: a.Reasons}, "")
	}
	obs.Reasons, obs.TransactionID, obs.Response, obs.DecisionHash = a.Reasons, a.TransactionID, capBytes(raw), a.ActionHash
	if len(a.Reasons) > 0 {
		obs.Reason = a.Reasons[0]
	}
	return obs, &callRec{act: act, txn: a.TransactionID, obs: obs, dispatch: a.Dispatch}, nil
}

// callHook runs the Claude Code hook for a command, as the agent's host does.
func (d *rangeDriver) callHook(w callWith) (domain.Observation, *callRec, error) {
	args, err := argsOf(w.Args)
	if err != nil {
		return domain.Observation{}, nil, err
	}
	m, _ := args.(map[string]any)
	event, _ := json.Marshal(map[string]any{
		"session_id": "range", "hook_event_name": "PreToolUse", "tool_name": w.Tool, "cwd": d.t.TempDir(),
		"tool_use_id": "toolu_" + ids.NewV7().String()[:8], "tool_input": map[string]any{"command": m["command"], "description": "range"},
	})
	up := d.s.gateway
	if w.Fault == "gateway_unreachable" {
		d.s.gateway = "http://" + freeAddr(d.t) // nothing listens there
	}
	code, out, errs := d.s.hook(d.t, string(event))
	d.s.gateway = up
	obs := domain.Observation{Detail: out + errs}
	switch {
	case code == 0:
		obs.Outcome = domain.OutcomeAllow
	case code == 2:
		obs.Outcome, obs.Code = domain.OutcomeRefused, "hook_exit_2"
	default:
		obs.Outcome, obs.Code = domain.OutcomeRefused, fmt.Sprintf("hook_exit_%d", code)
	}
	return obs, &callRec{obs: obs}, nil
}

// recordedRequest is a signed request as it left the client.
type recordedRequest struct {
	method, url string
	header      http.Header
	body        []byte
}

type rangeRecorder struct {
	base http.RoundTripper
	got  *recordedRequest
}

func (r *rangeRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	r.got = &recordedRequest{method: req.Method, url: req.URL.String(), header: req.Header.Clone(), body: body}
	return r.base.RoundTrip(req)
}

// otherInstance enrols a second instance of the agent (its own key and
// token, the same run) and returns them.
func (d *rangeDriver) otherInstance() (ed25519.PrivateKey, string) {
	if d.extra.otherKey == nil {
		d.extra.otherKey, d.extra.otherToken = d.enrolOtherInstance()
	}
	return d.extra.otherKey, d.extra.otherToken
}

// agentSteal is a call made with what an attacker holding the agent's token
// would have: the token without its key, a proof replayed, a stale nonce.
func (d *rangeDriver) agentSteal(_ context.Context, st domain.Step) (domain.Observation, error) {
	var w struct {
		Mode string   `json:"mode"`
		Call callWith `json:"call"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	url, body, err := d.stealTarget(w.Call)
	if err != nil {
		return domain.Observation{}, err
	}
	switch w.Mode {
	case "token_without_key":
		_, thief, _ := ed25519.GenerateKey(rand.Reader)
		return d.rawAs(thief, d.s.token, url, body, w.Call)
	case "proof_replay":
		return d.replayProof(url, body, w.Call)
	case "stale_nonce":
		return d.staleNonce(url, body, w.Call)
	}
	return domain.Observation{}, fmt.Errorf("agent.steal mode %q", w.Mode)
}

// stealTarget is the gateway URL and body the stolen-credential call goes to.
func (d *rangeDriver) stealTarget(w callWith) (string, []byte, error) {
	conn := d.role(w.Connection)
	switch w.Face {
	case "http":
		var b []byte
		if len(w.Body) > 0 {
			b = []byte(w.Body)
		}
		return d.s.gateway + "/" + conn + w.Path, b, nil
	case "mcp":
		args, err := argsOf(w.Args)
		if err != nil {
			return "", nil, err
		}
		b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
			"name": w.Tool, "arguments": args, "_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28"},
		}})
		return d.s.gateway + "/mcp/" + conn, b, err
	}
	return "", nil, fmt.Errorf("face %q", w.Face)
}

func (d *rangeDriver) stolenRequest(url string, body []byte, w callWith) (*http.Request, error) {
	method := w.Method
	if w.Face == "mcp" {
		method = http.MethodPost
	}
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if w.Face == "mcp" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", w.Tool)
	}
	req.Header.Set(gateway.HeaderRunID, d.s.run)
	req.Header.Set(gateway.HeaderActionID, ids.NewV7().String())
	return req, nil
}

func observeAny(face string, status int, h http.Header, raw []byte) domain.Observation {
	if face == "mcp" {
		return observeMCP(status, raw)
	}
	return observeREST(status, h, raw)
}

// rawAs sends the call with a token and a key that is not the token's.
func (d *rangeDriver) rawAs(key ed25519.PrivateKey, token, url string, body []byte, w callWith) (domain.Observation, error) {
	req, err := d.stolenRequest(url, body, w)
	if err != nil {
		return domain.Observation{}, err
	}
	resp, err := stolenClient(key, token).Do(req)
	if err != nil {
		return domain.Observation{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return observeAny(w.Face, resp.StatusCode, resp.Header, raw), nil
}

// replayProof sends a call once, then sends exactly the same signed request
// again, which the gateway refuses as a replayed proof.
func (d *rangeDriver) replayProof(url string, body []byte, w callWith) (domain.Observation, error) {
	req, err := d.stolenRequest(url, body, w)
	if err != nil {
		return domain.Observation{}, err
	}
	rec := &rangeRecorder{base: http.DefaultTransport}
	if err := doRecorded(d.s, rec, req); err != nil {
		return domain.Observation{}, err
	}
	r2, err := http.NewRequestWithContext(context.Background(), rec.got.method, rec.got.url, bytes.NewReader(rec.got.body))
	if err != nil {
		return domain.Observation{}, err
	}
	r2.Header = rec.got.header.Clone()
	resp, err := http.DefaultClient.Do(r2)
	if err != nil {
		return domain.Observation{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return observeAny(w.Face, resp.StatusCode, resp.Header, raw), nil
}

// staleNonce sends a call whose proof carries a nonce the server never
// issued, as an old one would be.
func (d *rangeDriver) staleNonce(url string, body []byte, w callWith) (domain.Observation, error) {
	req, err := d.stolenRequest(url, body, w)
	if err != nil {
		return domain.Observation{}, err
	}
	stale := base64.RawURLEncoding.EncodeToString([]byte("stale-stale-stale-stale-stale-0"))
	proof, err := pap.NewProof(d.s.key, pap.ProofParams{
		Method: req.Method, URL: url, Body: body, Token: d.s.token, Nonce: stale, Now: time.Now(),
	})
	if err != nil {
		return domain.Observation{}, err
	}
	req.Header.Set("Authorization", "PAP "+d.s.token)
	req.Header.Set("PAP-Proof", proof)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return domain.Observation{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return observeAny(w.Face, resp.StatusCode, resp.Header, raw), nil
}

// personApprove has the approvers the hold needs approve it with their keys.
func (d *rangeDriver) personApprove(st domain.Step) (domain.Observation, error) {
	var w struct {
		Step string `json:"step"`
		As   string `json:"as"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	rec, err := d.stepRec(w.Step)
	if err != nil {
		return domain.Observation{}, err
	}
	if rec.txn == "" {
		return domain.Observation{}, fmt.Errorf("step %s has no held transaction", w.Step)
	}
	if w.As != "approver" {
		return d.refusedApproval(rec, w.As)
	}
	for _, r := range d.reviewers {
		if requires(d.sc, "github") {
			if code, state := d.s.approveMerge(d.t, r.b, r.key, rec.txn); code != http.StatusOK {
				return domain.Observation{Outcome: domain.OutcomeRefused, Code: state}, nil
			}
		} else {
			d.s.approve(d.t, r.b, r.key, rec.txn)
		}
	}
	return domain.Observation{Outcome: domain.OutcomeAllow, TransactionID: rec.txn}, nil
}

// simMutate changes a simulator under the scenario's feet.
func (d *rangeDriver) simMutate(st domain.Step) (domain.Observation, error) {
	var w struct {
		Sim    string         `json:"sim"`
		Change string         `json:"change"`
		Args   jsontext.Value `json:"args"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	switch {
	case w.Sim == "github" && w.Change == "push_commit":
		var a struct {
			Branch string            `json:"branch"`
			Author string            `json:"author"`
			Files  map[string]string `json:"files"`
		}
		if err := json.Unmarshal(w.Args, &a); err != nil {
			return domain.Observation{}, err
		}
		sha := d.s.gh.sim.PushAs(ghRepo, a.Branch, a.Author, a.Files)
		b, _ := json.Marshal(map[string]string{"sha": sha})
		return domain.Observation{Response: b}, nil
	case w.Sim == "payments" && w.Change == "fault":
		var a struct {
			RedirectTo       string  `json:"redirect_to"`
			LoseResponseRate float64 `json:"lose_response_rate"`
		}
		if err := json.Unmarshal(w.Args, &a); err != nil {
			return domain.Observation{}, err
		}
		f := payments.Faults{LoseRate: a.LoseResponseRate}
		if a.RedirectTo != "" {
			var hits atomic.Int64
			elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
			d.t.Cleanup(elsewhere.Close)
			f.RedirectTo = elsewhere.URL + "/v1/refunds"
		}
		d.s.sim.SetFaults(f)
		return domain.Observation{}, nil
	case w.Sim == "mcp":
		return d.extra.mutateMCP(d, w.Change, w.Args)
	case w.Sim == "slack":
		return d.slackMutate(w.Change, w.Args)
	}
	return domain.Observation{}, fmt.Errorf("sim.mutate %s %s", w.Sim, w.Change)
}

// checkReceipt reads the decision receipt of an earlier call and checks the
// explanation evidence it names.
func (d *rangeDriver) checkReceipt(st domain.Step) (domain.Observation, error) {
	var w struct {
		Of  string   `json:"of"`
		Has []string `json:"has"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	rec, err := d.stepRec(w.Of)
	if err != nil {
		return domain.Observation{}, err
	}
	var jws string
	d.s.query(d.t, "SELECT receipt_jws FROM pc.decision_receipts WHERE transaction_id = $1 ORDER BY evaluation DESC LIMIT 1", []any{rec.txn}, &jws)
	if strings.Count(jws, ".") != 2 {
		return domain.Observation{}, fmt.Errorf("no decision receipt for step %s", w.Of)
	}
	missing := receipt.Missing(jws, w.Has)
	if len(missing) > 0 {
		return domain.Observation{Outcome: rec.obs.Outcome, Reason: rec.obs.Reason, Reasons: rec.obs.Reasons, TransactionID: rec.txn, Missing: missing}, nil
	}
	return domain.Observation{Outcome: rec.obs.Outcome, Reason: rec.obs.Reason, Reasons: rec.obs.Reasons, TransactionID: rec.txn}, nil
}

// targetReplay delivers the request an SDK call was handed to the target.
func (d *rangeDriver) targetReplay(st domain.Step) (domain.Observation, error) {
	var w struct {
		Of string `json:"of"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	rec, err := d.stepRec(w.Of)
	if err != nil {
		return domain.Observation{}, err
	}
	if rec.dispatch == nil {
		return domain.Observation{}, fmt.Errorf("step %s was handed no request to deliver", w.Of)
	}
	body, err := base64.RawURLEncoding.DecodeString(rec.dispatch.Body)
	if err != nil {
		return domain.Observation{}, err
	}
	req, err := http.NewRequestWithContext(context.Background(), rec.dispatch.Method, rec.dispatch.URL, bytes.NewReader(body))
	if err != nil {
		return domain.Observation{}, err
	}
	for k, v := range rec.dispatch.Headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return domain.Observation{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 300 {
		return domain.Observation{Outcome: domain.OutcomeAllow}, nil
	}
	var e struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	_ = json.Unmarshal(raw, &e, json.RejectUnknownMembers(false))
	code := e.Error
	if code == "" {
		code = e.Code
	}
	return domain.Observation{Outcome: domain.OutcomeTargetRefused, Code: code, Detail: fmt.Sprintf("%d %s", resp.StatusCode, raw)}, nil
}

// killSwitch engages the org's kill switch and returns once the gateway has
// learned of it.
func (d *rangeDriver) killSwitch() (domain.Observation, error) {
	alice := d.s.person(d.t, "range-responder", td.RoleEmergency)
	learned := d.s.learns(d.t, time.Now(), control.ErrKillSwitch)
	if _, err := rapp.New(d.s.pool, nil, d.s.apiURL).Engage(alice.ctx, rapp.StepUp{Credential: alice.key, At: time.Now()}, "range"); err != nil {
		return domain.Observation{}, err
	}
	learned()
	return domain.Observation{}, nil
}

// serverRead tries to read an object of another organisation by id, as a
// person of this one.
func (d *rangeDriver) serverRead(st domain.Step) (domain.Observation, error) {
	var w struct {
		Object string `json:"object"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	if d.other == nil {
		return domain.Observation{}, fmt.Errorf("no second organisation")
	}
	id := d.other.objectID(d.t, w.Object)
	var n int
	table := map[string]string{"transaction": "pc.transactions", "approval": "pc.approval_requests", "run": "pc.runs"}[w.Object]
	if table == "" {
		return domain.Observation{}, fmt.Errorf("server.read object %q", w.Object)
	}
	d.s.query(d.t, "SELECT count(*)::int FROM "+table+" WHERE id = $1", []any{id}, &n)
	if n == 0 {
		return domain.Observation{Outcome: domain.OutcomeNotFound}, nil
	}
	return domain.Observation{Outcome: domain.OutcomeAllow, Detail: fmt.Sprintf("%d rows of the other organisation visible", n)}, nil
}

var _ = capp.AccessHeld
