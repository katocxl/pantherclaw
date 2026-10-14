// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package live is the range's live driver (D14): it runs a scenario's steps
// through the gateway's faces as the range agent's workload, signing every
// request with PAP/1 through the HTTP client it is given. It never executes
// a delegated allow: an allowed call on the sdk or hook face is reported
// and nothing more. Steps it cannot perform through public APIs are
// reported as app.ErrUnsupported, and the runner marks the scenario SKIPPED.
package live

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect/v2"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/mcpheader"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// maxAnswer bounds one gateway answer.
const maxAnswer = 1 << 20

// TxnState is what the server says about a transaction.
type TxnState struct {
	// Approved and Declined are set once a person has decided.
	Approved, Declined bool
	// Effect is the effect state: "CONFIRMED", "UNKNOWN" or "" (not yet).
	Effect string
	// Decision is the latest decision: ALLOW, DENY, HOLD or CANNOT_AUTHORIZE.
	Decision string
	// Receipt shows which parts a decision receipt carries: grant,
	// policy_version, package_version, facts, simulated.
	Receipt map[string]bool
}

// Transactions reads the server's record of a transaction.
type Transactions interface {
	State(ctx context.Context, id string) (TxnState, error)
}

// Operator is the person at the keyboard (pclaw redteam run --interactive).
type Operator interface {
	// Decide tells the person which held transaction to approve or decline
	// and returns when they say they have.
	Decide(ctx context.Context, txn, role string, approve bool) error
}

// Config configures a Driver.
type Config struct {
	// Gateway is the gateway's base URL.
	Gateway string
	// Client sends requests signed with the range instance's workload key
	// and token (workloadclient.Transport).
	Client *http.Client
	// Run is the range instance's run id (PAP-Run-Id).
	Run string
	// Roles maps a scenario's connection role to a gateway connection name
	// (a role not listed is used as is).
	Roles map[string]string
	// Fixture is ${fixture.<name>} per scenario.
	Fixture app.Fixture
	// Capabilities are the scenario capabilities the setup provides
	// (github, payments, mcp).
	Capabilities map[app.Capability]bool
	// Txns reads transactions for wait, check.receipt and person steps; nil
	// makes them unsupported.
	Txns Transactions
	// Operator is the person for person.* steps; nil makes them unsupported
	// (and the driver lacks the person capability).
	Operator Operator
	// Unreachable is an address nothing listens on, for the hook fault.
	Unreachable string
	// WaitPoll is the poll interval of wait steps (default 200 ms).
	WaitPoll time.Duration
	// Workload is the range instance's WorkloadService (agent.child); AgentID
	// is the range agent. Nil or empty makes agent.child unsupported.
	Workload pantherclawv1connect.WorkloadServiceClient
	// Runs ends the scenario runs at Teardown (needs run.manage; nil: they
	// expire).
	Runs    pantherclawv1connect.RunServiceClient
	AgentID string
	// Key and Token are the instance's workload key and token (agent.steal);
	// Transport sends the stolen-credential and direct requests (nil: the
	// default transport).
	Key       ed25519.PrivateKey
	Token     func() string
	Transport http.RoundTripper
	// Direct maps a connection role to its simulator's base URL (agent.direct).
	Direct map[string]string
}

// Driver is the live app.Driver.
type Driver struct {
	cfg Config

	mu          sync.Mutex
	txns        map[string]string       // step id -> transaction id
	actions     map[string]string       // step id -> action id (sdk)
	dispatches  map[string]*sdkDispatch // step id -> the request handed to the SDK
	tools       map[string]map[string][]mcpheader.Param
	scenarioRun string // the current scenario's own run
	notes       []string
}

// New returns a driver.
func New(cfg Config) *Driver {
	if cfg.WaitPoll <= 0 {
		cfg.WaitPoll = 200 * time.Millisecond
	}
	if cfg.Unreachable == "" {
		cfg.Unreachable = "http://127.0.0.1:1"
	}
	return &Driver{
		cfg: cfg, txns: map[string]string{}, actions: map[string]string{}, dispatches: map[string]*sdkDispatch{},
		tools: map[string]map[string][]mcpheader.Param{},
	}
}

// Capabilities implements app.Driver.
func (d *Driver) Capabilities() map[app.Capability]bool {
	out := map[app.Capability]bool{}
	for k, v := range d.cfg.Capabilities {
		out[k] = v
	}
	out[app.CapPerson] = d.cfg.Operator != nil
	return out
}

// ScenarioRunMinutes is the lifetime of a scenario's own run: above the 60 s
// scenario timeout, and short because the run is ended at Teardown anyway.
const ScenarioRunMinutes = 5

// Setup implements app.Driver. With a WorkloadService it starts the scenario
// in its own child run of the range instance's run (D40): holds are capped per
// run (HR-037), so a whole range on one run would hit the cap.
func (d *Driver) Setup(ctx context.Context, s domain.Scenario) (app.Fixture, error) {
	d.mu.Lock()
	d.txns, d.actions, d.dispatches = map[string]string{}, map[string]string{}, map[string]*sdkDispatch{}
	d.scenarioRun = ""
	d.mu.Unlock()
	if d.cfg.Workload != nil && d.cfg.AgentID != "" {
		res, err := d.cfg.Workload.StartChildRun(ctx, &pantherclawv1.StartChildRunRequest{
			ParentRunId: d.cfg.Run, AgentId: d.cfg.AgentID, TaskRef: "range " + s.ID, TtlMinutes: ScenarioRunMinutes,
		})
		if err != nil {
			return nil, fmt.Errorf("starting the scenario's run: %w", err)
		}
		d.mu.Lock()
		d.scenarioRun = res.GetRun().GetId()
		d.mu.Unlock()
	}
	return d.cfg.Fixture, nil
}

// runID is the run the current scenario's calls are made in.
func (d *Driver) runID() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.scenarioRun != "" {
		return d.scenarioRun
	}
	return d.cfg.Run
}

// Notes are what the driver could not do and the summary should say.
func (d *Driver) Notes() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.notes)
}

// Teardown implements app.Driver: it ends the scenario's run when the caller may
// (run.manage), best effort. Holds left pending become moot with the run.
func (d *Driver) Teardown(ctx context.Context, s domain.Scenario) error {
	d.mu.Lock()
	run := d.scenarioRun
	d.scenarioRun = ""
	d.mu.Unlock()
	if run == "" || d.cfg.Runs == nil {
		return nil
	}
	if _, err := d.cfg.Runs.EndRun(ctx, &pantherclawv1.EndRunRequest{Id: run, Reason: "range " + s.ID}); err != nil {
		note := "could not end the run of " + s.ID + ": " + err.Error()
		if connect.CodeOf(err) == connect.CodePermissionDenied {
			note = "the run of " + s.ID + " was left to expire: ending it needs run.manage"
		}
		d.mu.Lock()
		if !slices.Contains(d.notes, note) && len(d.notes) < 20 {
			d.notes = append(d.notes, note)
		}
		d.mu.Unlock()
	}
	return nil
}

// callWith is the part of agent.call's `with` the driver reads.
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
	// run overrides the run of the call (a child run).
	run string
}

// Do implements app.Driver.
func (d *Driver) Do(ctx context.Context, s domain.Scenario, st domain.Step, _ map[string]string) (domain.Observation, error) {
	switch st.Do {
	case "agent.call":
		return d.agentCall(ctx, s, st)
	case "wait":
		return d.wait(ctx, st)
	case "agent.child":
		return d.child(ctx, s, st)
	case "agent.steal":
		return d.steal(ctx, st)
	case "target.replay":
		return d.targetReplay(ctx, st)
	case "agent.direct":
		return d.direct(ctx, st)
	case "check.receipt":
		return d.checkReceipt(ctx, st)
	case "person.approve", "person.decline":
		return d.person(ctx, st)
	}
	return domain.Observation{}, fmt.Errorf("%w: %s", app.ErrUnsupported, st.Do)
}

func (d *Driver) agentCall(ctx context.Context, s domain.Scenario, st domain.Step) (domain.Observation, error) {
	var w callWith
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	if w.Instance == "other" {
		return domain.Observation{}, fmt.Errorf("%w: a second instance", app.ErrUnsupported)
	}
	if w.Concurrent == 0 {
		o, action, err := d.one(ctx, s, st.ID, 0, w)
		d.remember(st.ID, o.TransactionID, action)
		return o, err
	}
	// Concurrent: N calls at once; ${n} is 1..N in the step's strings.
	each := make([]domain.Observation, w.Concurrent)
	errs := make([]error, w.Concurrent)
	var wg sync.WaitGroup
	for i := range w.Concurrent {
		wg.Add(1)
		go func() {
			defer wg.Done()
			with, err := domain.Substitute(st.With, map[string]string{"n": strconv.Itoa(i + 1)})
			if err != nil {
				errs[i] = err
				return
			}
			var wi callWith
			if err := json.Unmarshal(with, &wi); err != nil {
				errs[i] = err
				return
			}
			each[i], _, errs[i] = d.one(ctx, s, st.ID, i+1, wi)
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return domain.Observation{}, err
	}
	return domain.Observation{Each: each}, nil
}

func (d *Driver) remember(step, txn, action string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if txn != "" {
		d.txns[step] = txn
	}
	if action != "" {
		d.actions[step] = action
	}
}

// one sends a single call on its face and returns the sdk action id, if any.
func (d *Driver) one(ctx context.Context, s domain.Scenario, step string, n int, w callWith) (domain.Observation, string, error) {
	conn := w.Connection
	if mapped, ok := d.cfg.Roles[conn]; ok {
		conn = mapped
	}
	call := fmt.Sprintf("rt-%s-%s-%d", strings.ToLower(s.ID), step, n)
	var action string
	if w.ActionOf != "" {
		d.mu.Lock()
		action = d.actions[w.ActionOf]
		d.mu.Unlock()
		if action == "" {
			return domain.Observation{}, "", fmt.Errorf("action_of %s: that step has no action id (only the sdk face reports one)", w.ActionOf)
		}
	}
	ctx = context.WithValue(ctx, runKey{}, runOr(w.run, d.runID()))
	switch w.Face {
	case "sdk":
		if w.Tool == "" {
			return domain.Observation{}, "", fmt.Errorf("%w: sdk face with method and path", app.ErrUnsupported)
		}
		return d.sdk(ctx, step, conn, call, action, w)
	case "hook":
		o, err := d.hook(ctx, conn, w)
		return o, "", err
	case "mcp":
		o, err := d.mcp(ctx, conn, w)
		return o, "", err
	case "http":
		return d.httpFace(ctx, conn, action, w)
	}
	return domain.Observation{}, "", fmt.Errorf("face %q", w.Face)
}

func (d *Driver) base() string { return strings.TrimSuffix(d.cfg.Gateway, "/") }

// post sends a JSON body and returns the status, headers and bounded answer.
func (d *Driver) post(ctx context.Context, rawURL string, header http.Header, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("PAP-Run-Id", runFrom(ctx, d.runID()))
	for k, vs := range header {
		req.Header[k] = vs
	}
	status, _, b, err := d.do(req)
	return status, b, err
}

func (d *Driver) do(req *http.Request) (int, http.Header, []byte, error) {
	res, err := d.cfg.Client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxAnswer+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(b) > maxAnswer {
		return 0, nil, nil, errors.New("the gateway's answer is too large")
	}
	return res.StatusCode, res.Header, b, nil
}

// response keeps an answer's JSON for save pointers, within the port's bound.
func response(b []byte) []byte {
	if len(b) > domain.MaxResponseBytes || !jsontext.Value(b).IsValid() {
		return nil
	}
	return b
}

// sdkAnswer is the sdk face's answer (internal/gateway/sdk.Answer).
type sdkAnswer struct {
	Decision      string       `json:"decision"`
	ErrorClass    string       `json:"error_class"`
	Code          string       `json:"code"`
	Reasons       []string     `json:"reasons"`
	ActionID      string       `json:"action_id"`
	TransactionID string       `json:"transaction_id"`
	Dispatch      *sdkDispatch `json:"dispatch"`
}

// sdkDispatch is the request the gateway hands the SDK to send to a
// target-enforced connection (internal/gateway/sdk.Dispatch).
type sdkDispatch struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func (d *Driver) sdk(ctx context.Context, step, conn, call, action string, w callWith) (domain.Observation, string, error) {
	req, err := json.Marshal(map[string]any{
		"tool": "mcp__" + conn + "__" + w.Tool, "server": conn, "input": rawOr(w.Args), "tool_use_id": call,
	})
	if err != nil {
		return domain.Observation{}, "", err
	}
	h := http.Header{}
	if action != "" {
		h.Set("PC-Action-Id", action)
	}
	status, b, err := d.post(ctx, d.base()+"/sdk/"+url.PathEscape(conn), h, req)
	if err != nil {
		return domain.Observation{}, "", err
	}
	var a sdkAnswer
	if err := json.Unmarshal(b, &a); err != nil {
		return domain.Observation{}, "", fmt.Errorf("sdk face answered HTTP %d without JSON", status)
	}
	f := facts{Class: a.ErrorClass, Code: a.Code, Reasons: a.Reasons, TransactionID: a.TransactionID, Held: a.Decision == "hold"}
	if a.Decision == "deny" && f.Class == "" {
		f.Class = "policy_denied"
	}
	if a.Dispatch != nil {
		d.mu.Lock()
		d.dispatches[step] = a.Dispatch
		d.mu.Unlock()
	}
	o := classify(f)
	o.Response = response(b)
	return o, a.ActionID, nil
}

// hookAnswer is the hook face's answer (internal/gateway/hook.Answer).
type hookAnswer struct {
	Decision      string   `json:"decision"`
	ErrorClass    string   `json:"error_class"`
	Code          string   `json:"code"`
	Reasons       []string `json:"reasons"`
	TransactionID string   `json:"transaction_id"`
	Held          bool     `json:"held"`
}

func (d *Driver) hook(ctx context.Context, conn string, w callWith) (domain.Observation, error) {
	if w.Fault == "gateway_unreachable" {
		return d.unreachable(ctx)
	}
	req, err := json.Marshal(map[string]any{"tool": w.Tool, "input": rawOr(w.Args)})
	if err != nil {
		return domain.Observation{}, err
	}
	status, b, err := d.post(ctx, d.base()+"/hook/"+url.PathEscape(conn), nil, req)
	if err != nil {
		return domain.Observation{}, err
	}
	var a hookAnswer
	if err := json.Unmarshal(b, &a); err != nil {
		return domain.Observation{}, fmt.Errorf("hook face answered HTTP %d without JSON", status)
	}
	f := facts{Class: a.ErrorClass, Code: a.Code, Reasons: a.Reasons, TransactionID: a.TransactionID, Held: a.Held}
	if a.Decision == "deny" && f.Class == "" && !a.Held {
		f.Class = "policy_denied"
	}
	o := classify(f)
	o.Response = response(b)
	return o, nil
}

// httpFace calls /{connection}{path}: the gateway's HTTP proxy.
func (d *Driver) httpFace(ctx context.Context, conn, action string, w callWith) (domain.Observation, string, error) {
	var body io.Reader
	if len(w.Body) > 0 {
		body = bytes.NewReader(w.Body)
	}
	req, err := http.NewRequestWithContext(ctx, w.Method, d.base()+"/"+url.PathEscape(conn)+w.Path, body)
	if err != nil {
		return domain.Observation{}, "", err
	}
	req.Header.Set("PAP-Run-Id", runFrom(ctx, d.runID()))
	if action == "" {
		action = ids.NewV7().String()
	}
	req.Header.Set("PC-Action-Id", action)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	status, h, b, err := d.do(req)
	if err != nil {
		return domain.Observation{}, "", err
	}
	o, err := observeREST(status, h, b)
	return o, action, err
}

// mcp calls tools/call on the 2026-07-28 stateless MCP face.
func (d *Driver) mcp(ctx context.Context, conn string, w callWith) (domain.Observation, error) {
	const version = "2026-07-28"
	meta := map[string]string{"io.modelcontextprotocol/protocolVersion": version}
	endpoint := d.base() + "/mcp/" + url.PathEscape(conn)
	rpc := func(method string, params map[string]any, name string, extra http.Header) (int, []byte, error) {
		params["_meta"] = meta
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		if err != nil {
			return 0, nil, err
		}
		h := http.Header{}
		h.Set("Accept", "application/json")
		h.Set("MCP-Protocol-Version", version)
		h.Set("Mcp-Method", method)
		if name != "" {
			h.Set("Mcp-Name", mcpheader.Encode(name))
		}
		for k, vs := range extra {
			h[k] = vs
		}
		status, b, err := d.post(ctx, endpoint, h, body)
		return status, b, err
	}
	declared, err := d.declared(conn, rpc)
	if err != nil {
		return domain.Observation{}, err
	}
	var extra http.Header
	if params := declared[w.Tool]; len(params) > 0 {
		if extra, err = mcpheader.Mirror(params, rawOr(w.Args)); err != nil {
			return domain.Observation{}, err
		}
	}
	status, b, err := rpc("tools/call", map[string]any{"name": w.Tool, "arguments": rawOr(w.Args)}, w.Tool, extra)
	if err != nil {
		return domain.Observation{}, err
	}
	return observeMCP(status, nil, b)
}

// declared returns (and caches per connection) each tool's x-mcp-header
// parameters from the gateway's tool list.
func (d *Driver) declared(conn string, rpc func(string, map[string]any, string, http.Header) (int, []byte, error)) (map[string][]mcpheader.Param, error) {
	d.mu.Lock()
	cached, ok := d.tools[conn]
	d.mu.Unlock()
	if ok {
		return cached, nil
	}
	status, b, err := rpc("tools/list", map[string]any{}, "", nil)
	if err != nil {
		return nil, err
	}
	var r struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema jsontext.Value `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if status != http.StatusOK || json.Unmarshal(b, &r) != nil {
		return nil, fmt.Errorf("mcp tools/list answered HTTP %d", status)
	}
	out := map[string][]mcpheader.Param{}
	for _, t := range r.Result.Tools {
		if params, err := mcpheader.Parse(t.InputSchema); err == nil {
			out[t.Name] = params
		}
	}
	d.mu.Lock()
	d.tools[conn] = out
	d.mu.Unlock()
	return out, nil
}

// toolJSON is the JSON a tool result carries: structured content, else the
// first text block when it is JSON.
func toolJSON(structured, content jsontext.Value) []byte {
	if len(structured) > 0 {
		return response(structured)
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) == nil && len(blocks) > 0 {
		return response([]byte(blocks[0].Text))
	}
	return nil
}

func rawOr(v jsontext.Value) jsontext.Value {
	if len(v) == 0 {
		return jsontext.Value("{}")
	}
	return v
}

// wait polls a step's transaction until its effect settles; the scenario's
// expectation (CONFIRMED or UNKNOWN) decides whether that was right.
func (d *Driver) wait(ctx context.Context, st domain.Step) (domain.Observation, error) {
	if d.cfg.Txns == nil {
		return domain.Observation{}, fmt.Errorf("%w: wait needs the server", app.ErrUnsupported)
	}
	var w struct {
		Of         string `json:"of"`
		MaxSeconds int    `json:"max_seconds"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	txn, err := d.txnOf(w.Of)
	if err != nil {
		return domain.Observation{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(w.MaxSeconds)*time.Second)
	defer cancel()
	for {
		s, err := d.cfg.Txns.State(ctx, txn)
		if err == nil && s.Effect != "" {
			return domain.Observation{Outcome: domain.Outcome(s.Effect), TransactionID: txn}, nil
		}
		select {
		case <-ctx.Done():
			return domain.Observation{}, fmt.Errorf("the effect of %s did not settle within %d s", w.Of, w.MaxSeconds)
		case <-time.After(d.cfg.WaitPoll):
		}
	}
}

func (d *Driver) txnOf(step string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if id := d.txns[step]; id != "" {
		return id, nil
	}
	return "", fmt.Errorf("step %s caused no transaction", step)
}

// checkReceipt checks the named parts of a step's decision receipt.
func (d *Driver) checkReceipt(ctx context.Context, st domain.Step) (domain.Observation, error) {
	if d.cfg.Txns == nil {
		return domain.Observation{}, fmt.Errorf("%w: check.receipt needs the server", app.ErrUnsupported)
	}
	var w struct {
		Of  string   `json:"of"`
		Has []string `json:"has"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	txn, err := d.txnOf(w.Of)
	if err != nil {
		return domain.Observation{}, err
	}
	s, err := d.cfg.Txns.State(ctx, txn)
	if err != nil {
		return domain.Observation{}, err
	}
	var missing []string
	for _, h := range w.Has {
		if !s.Receipt[h] {
			missing = append(missing, h)
		}
	}
	return domain.Observation{Outcome: domain.Outcome(s.Decision), TransactionID: txn, Missing: missing}, nil
}

// person asks the operator to approve or decline a held step's transaction
// and waits until the server shows the decision.
func (d *Driver) person(ctx context.Context, st domain.Step) (domain.Observation, error) {
	if d.cfg.Operator == nil || d.cfg.Txns == nil {
		return domain.Observation{}, fmt.Errorf("%w: a person step needs --interactive", app.ErrUnsupported)
	}
	var w struct {
		Step string `json:"step"`
		As   string `json:"as"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	txn, err := d.txnOf(w.Step)
	if err != nil {
		return domain.Observation{}, err
	}
	approve := st.Do == "person.approve"
	if err := d.cfg.Operator.Decide(ctx, txn, w.As, approve); err != nil {
		return domain.Observation{}, err
	}
	for {
		s, err := d.cfg.Txns.State(ctx, txn)
		if err == nil && ((approve && s.Approved) || (!approve && s.Declined)) {
			return domain.Observation{Outcome: domain.OutcomeAllow, TransactionID: txn}, nil
		}
		select {
		case <-ctx.Done():
			return domain.Observation{}, fmt.Errorf("transaction %s was not decided", txn)
		case <-time.After(d.cfg.WaitPoll):
		}
	}
}

// unreachable is the hook's fail-closed path: it cannot reach the gateway, so
// it exits 2 and the command does not run. It only dials the address nothing
// should listen on, sends no byte and never uses the workload-signing client,
// so no proof or token can leave for an address that is not the gateway.
func (d *Driver) unreachable(ctx context.Context) (domain.Observation, error) {
	u, err := url.Parse(d.cfg.Unreachable)
	if err != nil || u.Host == "" {
		return domain.Observation{}, fmt.Errorf("the unreachable address %q", d.cfg.Unreachable)
	}
	dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dctx, "tcp", u.Host)
	if err == nil {
		_ = conn.Close()
		return domain.Observation{}, errors.New("the address meant to be unreachable accepted a connection")
	}
	return domain.Observation{Outcome: domain.OutcomeRefused, Code: "hook_exit_2", Detail: "the gateway was unreachable"}, nil
}
