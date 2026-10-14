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
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

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
}

// Driver is the live app.Driver.
type Driver struct {
	cfg Config

	mu      sync.Mutex
	txns    map[string]string // step id -> transaction id
	actions map[string]string // step id -> action id (sdk)
	tools   map[string]map[string][]mcpheader.Param
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
		cfg: cfg, txns: map[string]string{}, actions: map[string]string{},
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

// Setup implements app.Driver.
func (d *Driver) Setup(context.Context, domain.Scenario) (app.Fixture, error) {
	d.mu.Lock()
	d.txns, d.actions = map[string]string{}, map[string]string{}
	d.mu.Unlock()
	return d.cfg.Fixture, nil
}

// Teardown implements app.Driver.
func (d *Driver) Teardown(context.Context, domain.Scenario) error { return nil }

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
}

// Do implements app.Driver.
func (d *Driver) Do(ctx context.Context, s domain.Scenario, st domain.Step, _ map[string]string) (domain.Observation, error) {
	switch st.Do {
	case "agent.call":
		return d.agentCall(ctx, s, st)
	case "wait":
		return d.wait(ctx, st)
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
	switch w.Face {
	case "sdk":
		if w.Tool == "" {
			return domain.Observation{}, "", fmt.Errorf("%w: sdk face with method and path", app.ErrUnsupported)
		}
		return d.sdk(ctx, conn, call, action, w)
	case "hook":
		o, err := d.hook(ctx, conn, w)
		return o, "", err
	case "mcp":
		o, err := d.mcp(ctx, conn, w)
		return o, "", err
	case "http":
		o, err := d.httpFace(ctx, conn, w)
		return o, "", err
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
	req.Header.Set("PAP-Run-Id", d.cfg.Run)
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
	Decision      string   `json:"decision"`
	ErrorClass    string   `json:"error_class"`
	Code          string   `json:"code"`
	Reasons       []string `json:"reasons"`
	ActionID      string   `json:"action_id"`
	TransactionID string   `json:"transaction_id"`
}

func (d *Driver) sdk(ctx context.Context, conn, call, action string, w callWith) (domain.Observation, string, error) {
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
func (d *Driver) httpFace(ctx context.Context, conn string, w callWith) (domain.Observation, error) {
	var body io.Reader
	if len(w.Body) > 0 {
		body = bytes.NewReader(w.Body)
	}
	req, err := http.NewRequestWithContext(ctx, w.Method, d.base()+"/"+url.PathEscape(conn)+w.Path, body)
	if err != nil {
		return domain.Observation{}, err
	}
	req.Header.Set("PAP-Run-Id", d.cfg.Run)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	status, h, b, err := d.do(req)
	if err != nil {
		return domain.Observation{}, err
	}
	var r struct {
		ErrorClass    string   `json:"error_class"`
		Error         string   `json:"error"`
		Decision      string   `json:"decision"`
		Reasons       []string `json:"reasons"`
		TransactionID string   `json:"transaction_id"`
	}
	f := facts{TransactionID: h.Get("PC-Transaction-Id")}
	switch {
	case h.Get("PC-Decision") == "" && json.Unmarshal(b, &r) == nil && r.ErrorClass != "":
		f = facts{Class: r.ErrorClass, Code: r.Error, Decision: r.Decision, Reasons: r.Reasons, TransactionID: r.TransactionID}
	case h.Get("PC-Decision") == "":
		return domain.Observation{}, fmt.Errorf("http face answered %d with neither a decision nor a refusal", status)
	}
	o := classify(f)
	o.Response = response(b)
	return o, nil
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
	var r struct {
		Result *struct {
			Content           jsontext.Value `json:"content"`
			StructuredContent jsontext.Value `json:"structuredContent"`
			IsError           bool           `json:"isError"`
			Meta              struct {
				Error struct {
					ErrorClass    string   `json:"error_class"`
					Error         string   `json:"error"`
					Decision      string   `json:"decision"`
					Reasons       []string `json:"reasons"`
					TransactionID string   `json:"transaction_id"`
				} `json:"io.pantherclaw/error"`
				Result struct {
					TransactionID string `json:"transaction_id"`
				} `json:"io.pantherclaw/result"`
			} `json:"_meta"`
		} `json:"result"`
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b, &r); err != nil || (r.Result == nil && r.Error == nil) {
		return domain.Observation{}, fmt.Errorf("mcp face answered HTTP %d without a JSON-RPC answer", status)
	}
	if r.Error != nil {
		return domain.Observation{Outcome: domain.OutcomeRefused, Code: "rpc_" + strconv.Itoa(r.Error.Code), Detail: r.Error.Message}, nil
	}
	var f facts
	if r.Result.IsError {
		e := r.Result.Meta.Error
		f = facts{Class: e.ErrorClass, Code: e.Error, Decision: e.Decision, Reasons: e.Reasons, TransactionID: e.TransactionID}
		if f.Class == "" {
			return domain.Observation{}, errors.New("mcp tool error without PantherClaw's error facts")
		}
	} else {
		f.TransactionID = r.Result.Meta.Result.TransactionID
	}
	o := classify(f)
	o.Response = toolJSON(r.Result.StructuredContent, r.Result.Content)
	return o, nil
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
