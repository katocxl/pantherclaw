// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// fakeGateway is a gateway with both faces whose answers each test
// scripts per path ("/mcp/<conn>" for tools/call, "/<conn>/<path>" for
// HTTP). It records every request.
type fakeGateway struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
	// answer answers one request; nil answers 404.
	answer func(w http.ResponseWriter, r *http.Request, body []byte, n int)
	// tools is the tools/list result's tools.
	tools string
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	g := &fakeGateway{tools: `[]`}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.requests, g.bodies = append(g.requests, r), append(g.bodies, string(b))
		n := len(g.requests)
		answer, tools := g.answer, g.tools
		g.mu.Unlock()
		if r.Header.Get("Mcp-Method") == "tools/list" {
			var m struct {
				ID jsontext.Value `json:"id"`
			}
			_ = json.Unmarshal(b, &m)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":{"tools":`+tools+`}}`)
			return
		}
		if answer == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		answer(w, r, b, n)
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *fakeGateway) seen() ([]*http.Request, []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]*http.Request(nil), g.requests...), append([]string(nil), g.bodies...)
}

// calls returns the requests that were not tool lists.
func (g *fakeGateway) calls() ([]*http.Request, []string) {
	rs, bs := g.seen()
	var outR []*http.Request
	var outB []string
	for i, r := range rs {
		if r.Header.Get("Mcp-Method") != "tools/list" {
			outR, outB = append(outR, r), append(outB, bs[i])
		}
	}
	return outR, outB
}

func newCallRunner(t *testing.T, g *fakeGateway) (*callRunner, string) {
	t.Helper()
	_, key, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	run := ids.NewV7().String()
	return &callRunner{
		gateway: g.URL, run: run, log: io.Discard,
		client: &http.Client{
			Transport:     &workloadclient.Transport{Key: key, Base: http.DefaultTransport, Token: func() string { return "tok" }},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, run
}

// gatewayJSON writes a JSON answer with PantherClaw headers.
func gatewayJSON(w http.ResponseWriter, status int, hdr map[string]string, body string) {
	for k, v := range hdr {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// mcpResult answers a tools/call with result, echoing the request id.
func mcpResult(w http.ResponseWriter, body []byte, result string) {
	var m struct {
		ID jsontext.Value `json:"id"`
	}
	_ = json.Unmarshal(body, &m)
	gatewayJSON(w, http.StatusOK, nil, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":`+result+`}`)
}

func httpCallTo(conn, method, path, input string) runnerCall {
	return runnerCall{Connection: conn, Face: faceHTTP, Method: method, Path: path, Input: jsontext.Value(input)}
}

func mcpCallTo(conn, tool, input string) runnerCall {
	return runnerCall{Connection: conn, Face: faceMCP, Tool: tool, Input: jsontext.Value(input)}
}

// Each HTTP call is a signed request in the launch's run with its own
// action id; the runner stops at the first denied call and sends nothing
// after it.
func TestHR285_EachCallIsSignedInTheLaunchRunAndStopsAtADenial(t *testing.T) {
	g := newFakeGateway(t)
	g.answer = func(w http.ResponseWriter, r *http.Request, _ []byte, n int) {
		switch n {
		case 1:
			gatewayJSON(w, http.StatusOK, map[string]string{"PC-Decision": "ALLOW", "PC-Transaction-Id": "tx-1"}, `{"ok":true}`)
		default:
			gatewayJSON(w, http.StatusForbidden, map[string]string{"PC-Transaction-Id": "tx-2"},
				`{"error_class":"policy_denied","error":"refund_over_limit","decision":"DENY","transaction_id":"tx-2"}`)
		}
	}
	c, run := newCallRunner(t, g)
	results, outcome := c.runCalls(t.Context(), []runnerCall{
		httpCallTo("payments", http.MethodPost, "/v1/refunds", `{"charge":"ch_1","amount":500}`),
		httpCallTo("payments", http.MethodPost, "/v1/refunds", `{"charge":"ch_2","amount":900}`),
		httpCallTo("payments", http.MethodPost, "/v1/refunds", `{"charge":"ch_3","amount":100}`),
	})
	if outcome != launchPartial {
		t.Fatalf("outcome = %s, want PARTIAL", outcome)
	}
	want := []callResult{
		{Index: 0, Status: callSucceeded, TransactionID: "tx-1"},
		{Index: 1, Status: callDenied, TransactionID: "tx-2", ErrorCode: "refund_over_limit"},
		{Index: 2, Status: callSkipped},
	}
	if !equalResults(results, want) {
		t.Fatalf("results = %+v, want %+v", results, want)
	}
	reqs, bodies := g.calls()
	if len(reqs) != 2 {
		t.Fatalf("%d requests reached the gateway, want 2 (nothing after the denial)", len(reqs))
	}
	actions := map[string]bool{}
	for i, r := range reqs {
		if r.URL.Path != "/payments/v1/refunds" || r.Method != http.MethodPost {
			t.Fatalf("request %d = %s %s", i, r.Method, r.URL.Path)
		}
		if r.Header.Get("PAP-Run-Id") != run || r.Header.Get("PAP-Proof") == "" || r.Header.Get("Authorization") != "PAP tok" {
			t.Fatalf("request %d is not a signed request in the launch's run: %v", i, r.Header)
		}
		a := r.Header.Get("PC-Action-Id")
		if _, err := ids.ParseUUID(a); err != nil || actions[a] {
			t.Fatalf("request %d action id %q is not a fresh id", i, a)
		}
		actions[a] = true
	}
	if bodies[0] != `{"charge":"ch_1","amount":500}` {
		t.Fatalf("body = %s", bodies[0])
	}
}

// A held call stops the launch; the runner never waits on or resends it.
func TestAutomationRunner_HeldCallStops(t *testing.T) {
	for _, face := range []string{faceHTTP, faceMCP} {
		t.Run(face, func(t *testing.T) {
			g := newFakeGateway(t)
			g.answer = func(w http.ResponseWriter, r *http.Request, b []byte, _ int) {
				if face == faceHTTP {
					gatewayJSON(w, http.StatusForbidden, map[string]string{"PC-Transaction-Id": "tx-h"},
						`{"error_class":"held","error":"approval_required","decision":"REQUIRE_APPROVAL","transaction_id":"tx-h"}`)
					return
				}
				mcpResult(w, b, `{"content":[],"isError":true,"_meta":{"io.pantherclaw/error":{"error_class":"held","error":"approval_required","transaction_id":"tx-h"},"io.pantherclaw/hold":{"transaction_id":"tx-h"}}}`)
			}
			c, _ := newCallRunner(t, g)
			call := httpCallTo("payments", http.MethodPost, "/v1/refunds", `{}`)
			if face == faceMCP {
				call = mcpCallTo("payments", "refund", `{}`)
			}
			results, outcome := c.runCalls(t.Context(), []runnerCall{call, call})
			want := []callResult{{Index: 0, Status: callHeld, TransactionID: "tx-h", ErrorCode: "approval_required"}, {Status: callSkipped}}
			if outcome != launchFailed || !equalResults(results, want) {
				t.Fatalf("results = %+v %s, want %+v FAILED", results, outcome, want)
			}
			if reqs, _ := g.calls(); len(reqs) != 1 {
				t.Fatalf("%d calls reached the gateway, want 1", len(reqs))
			}
		})
	}
}

// An unknown outcome is reported UNKNOWN and never sent again: the
// gateway's "uncertain" class, an answer that did not come from the
// dispatch path, and a connection that broke after the request left.
func TestHR285_UnknownOutcomesAreNeverRetried(t *testing.T) {
	cases := map[string]struct {
		face   string
		answer func(w http.ResponseWriter, r *http.Request, b []byte)
		code   string
	}{
		"http uncertain": {faceHTTP, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			gatewayJSON(w, http.StatusGatewayTimeout, map[string]string{"PC-Transaction-Id": "tx-u"},
				`{"error_class":"uncertain","error":"target_uncertain","transaction_id":"tx-u"}`)
		}, "target_uncertain"},
		"http not from the gateway": {faceHTTP, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "upstream connect error")
		}, "unrecognized_answer"},
		"http connection broke": {faceHTTP, hangUp, "gateway_unreachable"},
		"mcp uncertain": {faceMCP, func(w http.ResponseWriter, _ *http.Request, b []byte) {
			mcpResult(w, b, `{"content":[],"isError":true,"_meta":{"io.pantherclaw/error":{"error_class":"uncertain","error":"target_uncertain","transaction_id":"tx-u"}}}`)
		}, "target_uncertain"},
		"mcp no answer to the call": {faceMCP, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			gatewayJSON(w, http.StatusOK, nil, `{"jsonrpc":"2.0","id":"someone-else","result":{"content":[],"isError":false}}`)
		}, "unrecognized_answer"},
		"mcp connection broke": {faceMCP, hangUp, "gateway_unreachable"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			g := newFakeGateway(t)
			g.answer = func(w http.ResponseWriter, r *http.Request, b []byte, _ int) { tc.answer(w, r, b) }
			c, _ := newCallRunner(t, g)
			call := httpCallTo("payments", http.MethodPost, "/v1/refunds", `{"amount":1}`)
			if tc.face == faceMCP {
				call = mcpCallTo("payments", "refund", `{"amount":1}`)
			}
			results, outcome := c.runCalls(t.Context(), []runnerCall{call, call})
			if outcome != launchFailed || len(results) != 2 || results[0].Status != callUnknown || results[0].ErrorCode != tc.code || results[1].Status != callSkipped {
				t.Fatalf("results = %+v %s, want one UNKNOWN %s", results, outcome, tc.code)
			}
			if reqs, _ := g.calls(); len(reqs) != 1 {
				t.Fatalf("%d calls reached the gateway, want exactly 1 (never resent)", len(reqs))
			}
		})
	}
}

// hangUp closes the connection without an answer.
func hangUp(w http.ResponseWriter, _ *http.Request, _ []byte) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("no hijacker")
	}
	conn, _, err := hj.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// Refusals the gateway made before or instead of dispatch are FAILED with
// the gateway's code; a target's own refusal is FAILED with its status.
func TestAutomationRunner_FailuresAreReported(t *testing.T) {
	cases := map[string]struct {
		face   string
		answer func(w http.ResponseWriter, b []byte)
		want   callResult
	}{
		"http kill switch": {faceHTTP, func(w http.ResponseWriter, _ []byte) {
			gatewayJSON(w, http.StatusForbidden, nil, `{"error_class":"enforcement_failed","error":"kill_switch"}`)
		}, callResult{Status: callFailed, ErrorCode: "kill_switch"}},
		"http target refused": {faceHTTP, func(w http.ResponseWriter, _ []byte) {
			gatewayJSON(w, http.StatusUnprocessableEntity, map[string]string{"PC-Decision": "ALLOW", "PC-Transaction-Id": "tx-t"}, `{"error":"bad charge"}`)
		}, callResult{Status: callFailed, TransactionID: "tx-t", ErrorCode: "target_status_422"}},
		"http unknown route": {faceHTTP, func(w http.ResponseWriter, _ []byte) {
			gatewayJSON(w, http.StatusNotFound, nil, `{"error_class":"cannot_authorize","error":"unknown_route"}`)
		}, callResult{Status: callFailed, ErrorCode: "unknown_route"}},
		"mcp protocol error": {faceMCP, func(w http.ResponseWriter, b []byte) {
			var m struct {
				ID jsontext.Value `json:"id"`
			}
			_ = json.Unmarshal(b, &m)
			gatewayJSON(w, http.StatusOK, nil, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"error":{"code":-32602,"message":"Unknown tool: refund"}}`)
		}, callResult{Status: callFailed, ErrorCode: "mcp_-32602"}},
		"mcp tool failed": {faceMCP, func(w http.ResponseWriter, b []byte) {
			mcpResult(w, b, `{"content":[],"isError":true,"_meta":{"io.pantherclaw/error":{"error_class":"tool_failed","error":"target_refused","transaction_id":"tx-f"}}}`)
		}, callResult{Status: callFailed, TransactionID: "tx-f", ErrorCode: "target_refused"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			g := newFakeGateway(t)
			g.answer = func(w http.ResponseWriter, _ *http.Request, b []byte, _ int) { tc.answer(w, b) }
			c, _ := newCallRunner(t, g)
			call := httpCallTo("payments", http.MethodPost, "/v1/refunds", `{}`)
			if tc.face == faceMCP {
				call = mcpCallTo("payments", "refund", `{}`)
			}
			results, outcome := c.runCalls(t.Context(), []runnerCall{call})
			if outcome != launchFailed || !equalResults(results, []callResult{tc.want}) {
				t.Fatalf("results = %+v %s, want %+v", results, outcome, tc.want)
			}
		})
	}
}

// An MCP call is a 2026-07-28 tools/call to /mcp/{connection} with the
// request metadata headers and the tool's declared parameter headers,
// learned from the connection's tool list.
func TestAutomationRunner_MCPCallCarriesItsHeaders(t *testing.T) {
	g := newFakeGateway(t)
	g.tools = `[{"name":"refund","inputSchema":{"type":"object","properties":{"charge":{"type":"string","x-mcp-header":"Charge"}}}}]`
	g.answer = func(w http.ResponseWriter, r *http.Request, b []byte, _ int) {
		mcpResult(w, b, `{"content":[],"isError":false,"_meta":{"io.pantherclaw/result":{"transaction_id":"tx-m","decision":"ALLOW"}}}`)
	}
	c, run := newCallRunner(t, g)
	results, outcome := c.runCalls(t.Context(), []runnerCall{mcpCallTo("payments", "refund", `{"charge":"ch_1"}`)})
	if outcome != launchSucceeded || !equalResults(results, []callResult{{Status: callSucceeded, TransactionID: "tx-m"}}) {
		t.Fatalf("results = %+v %s", results, outcome)
	}
	reqs, bodies := g.calls()
	if len(reqs) != 1 {
		t.Fatalf("%d calls, want 1", len(reqs))
	}
	r := reqs[0]
	for k, v := range map[string]string{
		"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "refund",
		"Mcp-Param-Charge": "ch_1", "PAP-Run-Id": run,
	} {
		if got := r.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if r.URL.Path != "/mcp/payments" || r.Header.Get("PAP-Proof") == "" || r.Header.Get("PC-Action-Id") == "" {
		t.Fatalf("request = %s %v", r.URL.Path, r.Header)
	}
	var m struct {
		Method string `json:"method"`
		Params struct {
			Name      string                    `json:"name"`
			Arguments jsontext.Value            `json:"arguments"`
			Meta      map[string]jsontext.Value `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(bodies[0]), &m); err != nil {
		t.Fatal(err)
	}
	if m.Method != "tools/call" || m.Params.Name != "refund" || string(m.Params.Arguments) != `{"charge":"ch_1"}` ||
		string(m.Params.Meta["io.modelcontextprotocol/protocolVersion"]) != `"2026-07-28"` {
		t.Fatalf("body = %s", bodies[0])
	}
	if _, ok := m.Params.Meta["io.modelcontextprotocol/clientCapabilities"]; ok {
		t.Fatal("the runner declares no capabilities: a held call must never become a task it would wait on")
	}
}

// A HeaderMismatch refusal is made before anything is dispatched: the
// runner lists the tools again and sends the call once more, with the same
// action id, and never a third time.
func TestAutomationRunner_HeaderMismatchResendsOnce(t *testing.T) {
	g := newFakeGateway(t)
	g.answer = func(w http.ResponseWriter, _ *http.Request, b []byte, _ int) {
		var m struct {
			ID jsontext.Value `json:"id"`
		}
		_ = json.Unmarshal(b, &m)
		gatewayJSON(w, http.StatusBadRequest, nil, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"error":{"code":-32020,"message":"Header mismatch"}}`)
	}
	c, _ := newCallRunner(t, g)
	results, _ := c.runCalls(t.Context(), []runnerCall{mcpCallTo("payments", "refund", `{}`)})
	if !equalResults(results, []callResult{{Status: callFailed, ErrorCode: "mcp_-32020"}}) {
		t.Fatalf("results = %+v", results)
	}
	reqs, _ := g.calls()
	all, _ := g.seen()
	if len(reqs) != 2 || len(all) != 4 {
		t.Fatalf("%d calls and %d requests, want 2 calls and 2 tool lists", len(reqs), len(all)-len(reqs))
	}
	if reqs[0].Header.Get("PC-Action-Id") != reqs[1].Header.Get("PC-Action-Id") {
		t.Fatal("the resent call has a new action id")
	}
}

// A GET call's input becomes its query; scalars only.
func TestAutomationRunner_GetInputIsTheQuery(t *testing.T) {
	g := newFakeGateway(t)
	g.answer = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int) {
		gatewayJSON(w, http.StatusOK, map[string]string{"PC-Decision": "ALLOW", "PC-Transaction-Id": "tx-g"}, `{}`)
	}
	c, _ := newCallRunner(t, g)
	results, outcome := c.runCalls(t.Context(), []runnerCall{
		httpCallTo("payments", http.MethodGet, "/v1/charges", `{"customer":"cu 1","limit":5,"skip":null}`),
		httpCallTo("payments", http.MethodGet, "/v1/charges", `{"nested":{"a":1}}`),
	})
	if outcome != launchPartial || len(results) != 2 || results[1].ErrorCode != "invalid_call" {
		t.Fatalf("results = %+v %s", results, outcome)
	}
	reqs, bodies := g.calls()
	if len(reqs) != 1 || reqs[0].URL.RawQuery != "customer=cu+1&limit=5" || bodies[0] != "" {
		t.Fatalf("requests = %d %q %q", len(reqs), reqs[0].URL.RawQuery, bodies[0])
	}
}

// A launch whose declared calls do not all check runs none of them.
func TestHR285_OnlyWellFormedDeclaredCallsRun(t *testing.T) {
	ok := httpCallTo("payments", http.MethodPost, "/v1/refunds", `{}`)
	tooMany := make([]runnerCall, runnerMaxCalls+1)
	for i := range tooMany {
		tooMany[i] = ok
	}
	cases := map[string][]runnerCall{
		"dot segment":        {ok, httpCallTo("payments", http.MethodPost, "/v1/../admin", `{}`)},
		"query in path":      {ok, httpCallTo("payments", http.MethodPost, "/v1/refunds?all=1", `{}`)},
		"relative path":      {ok, httpCallTo("payments", http.MethodPost, "v1/refunds", `{}`)},
		"scheme-relative":    {ok, httpCallTo("payments", http.MethodPost, "//evil.example/x", `{}`)},
		"method":             {ok, httpCallTo("payments", "CONNECT", "/v1", `{}`)},
		"connection segment": {ok, httpCallTo("pay/ments", http.MethodPost, "/v1", `{}`)},
		"connection dots":    {ok, httpCallTo("..", http.MethodPost, "/v1", `{}`)},
		"face":               {ok, {Connection: "payments", Face: "SHELL", Tool: "x"}},
		"no tool":            {ok, mcpCallTo("payments", "", `{}`)},
		"input not object":   {ok, mcpCallTo("payments", "refund", `[1]`)},
		"too many":           tooMany,
	}
	for name, calls := range cases {
		t.Run(name, func(t *testing.T) {
			g := newFakeGateway(t)
			g.answer = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int) {
				gatewayJSON(w, http.StatusOK, map[string]string{"PC-Decision": "ALLOW"}, `{}`)
			}
			c, _ := newCallRunner(t, g)
			results, outcome := c.runCalls(t.Context(), calls)
			if outcome != launchFailed || !oneFailedRestSkipped(results, len(calls)) {
				t.Fatalf("results = %+v %s", results, outcome)
			}
			if all, _ := g.seen(); len(all) != 0 {
				t.Fatalf("%d requests reached the gateway, want none", len(all))
			}
		})
	}
}

// fakeLaunches is a launch source with scripted launches.
type fakeLaunches struct {
	mu        sync.Mutex
	launches  []*claimedLaunch
	claims    int
	failNext  int
	completed []completion
	attempts  int
}

func (f *fakeLaunches) Claim(context.Context) (*claimedLaunch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.claims++
	if len(f.launches) == 0 {
		return nil, nil
	}
	l := f.launches[0]
	f.launches = f.launches[1:]
	return l, nil
}

func (f *fakeLaunches) Complete(_ context.Context, launch string, outcome launchOutcome, results []callResult, note string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.failNext > 0 {
		f.failNext--
		return errors.New("server unavailable")
	}
	f.completed = append(f.completed, completion{launch: launch, outcome: outcome, results: results, note: note})
	return nil
}

// The runner completes every launch it claims with its calls' results;
// a report that does not reach the server is sent again, and the calls
// are never performed twice.
func TestAutomationRunner_LaunchesCompleteOnceEach(t *testing.T) {
	g := newFakeGateway(t)
	g.answer = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int) {
		gatewayJSON(w, http.StatusOK, map[string]string{"PC-Decision": "ALLOW", "PC-Transaction-Id": "tx"}, `{}`)
	}
	c, _ := newCallRunner(t, g)
	run := ids.NewV7().String()
	src := &fakeLaunches{
		launches: []*claimedLaunch{
			{ID: "l1", RunID: run, Calls: []runnerCall{httpCallTo("payments", http.MethodPost, "/v1/refunds", `{}`)}},
			{ID: "l2", RunID: "not-a-run", Calls: []runnerCall{httpCallTo("payments", http.MethodPost, "/v1/refunds", `{}`)}},
		},
		failNext: 2,
	}
	var runs []string
	lr := &launchRunner{src: src, poll: time.Millisecond, log: io.Discard, caller: func(r string) *callRunner {
		runs = append(runs, r)
		c.run = r
		return c
	}}
	if err := lr.run(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if reqs, _ := g.calls(); len(reqs) != 1 {
		t.Fatalf("%d calls reached the gateway, want 1", len(reqs))
	}
	if len(runs) != 1 || runs[0] != run {
		t.Fatalf("runs = %v", runs)
	}
	if len(src.completed) != 2 || src.attempts != 4 {
		t.Fatalf("completed %d launches in %d attempts, want 2 in 4", len(src.completed), src.attempts)
	}
	if got := src.completed[0]; got.launch != "l1" || got.outcome != launchSucceeded || len(got.results) != 1 {
		t.Fatalf("l1 = %+v", got)
	}
	if got := src.completed[1]; got.launch != "l2" || got.outcome != launchFailed || len(got.results) != 0 || got.note == "" {
		t.Fatalf("l2 = %+v", got)
	}
}

// With --once a report that never reaches the server is an error after
// a few tries; the calls still ran once.
func TestAutomationRunner_OnceGivesUpReporting(t *testing.T) {
	g := newFakeGateway(t)
	g.answer = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int) {
		gatewayJSON(w, http.StatusOK, map[string]string{"PC-Decision": "ALLOW"}, `{}`)
	}
	c, _ := newCallRunner(t, g)
	src := &fakeLaunches{
		launches: []*claimedLaunch{{ID: "l1", RunID: ids.NewV7().String(), Calls: []runnerCall{httpCallTo("payments", http.MethodPost, "/v1/x", `{}`)}}},
		failNext: 100,
	}
	var log bytes.Buffer
	lr := &launchRunner{src: src, poll: time.Millisecond, log: &log, caller: func(string) *callRunner { return c }}
	err := lr.run(t.Context(), true)
	if err == nil || !strings.Contains(err.Error(), "completing launch l1") {
		t.Fatalf("err = %v", err)
	}
	if reqs, _ := g.calls(); len(reqs) != 1 || src.claims != 1 {
		t.Fatalf("%d calls and %d claims, want 1 and 1", len(reqs), src.claims)
	}
}

func equalResults(got, want []callResult) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		w := want[i]
		w.Index = i
		if got[i] != w {
			return false
		}
	}
	return true
}

// A target answer the gateway passes through says nothing definite when
// it is a 5xx or the gateway recorded the outcome UNKNOWN (D82): the call
// is UNKNOWN and never sent again. A 4xx with a known outcome is FAILED.
func TestAutomationRunner_TargetAnswersFollowTheRecordedOutcome(t *testing.T) {
	cases := map[string]struct {
		status  int
		outcome string
		want    callStatus
	}{
		"502 unknown":      {http.StatusBadGateway, "UNKNOWN", callUnknown},
		"500 no outcome":   {http.StatusInternalServerError, "", callUnknown},
		"409 unknown":      {http.StatusConflict, "UNKNOWN", callUnknown},
		"409 failed":       {http.StatusConflict, "FAILED", callFailed},
		"200 confirmed":    {http.StatusOK, "CONFIRMED", callSucceeded},
		"302 not followed": {http.StatusFound, "", callUnknown},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			g := newFakeGateway(t)
			g.answer = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int) {
				hdr := map[string]string{"PC-Decision": "ALLOW", "PC-Transaction-Id": "tx"}
				if tc.outcome != "" {
					hdr["PC-Outcome"] = tc.outcome
				}
				if tc.status == http.StatusFound {
					hdr["Location"] = "https://elsewhere.example/x"
				}
				gatewayJSON(w, tc.status, hdr, `{}`)
			}
			c, _ := newCallRunner(t, g)
			results, _ := c.runCalls(t.Context(), []runnerCall{httpCallTo("payments", http.MethodPost, "/v1/refunds", `{}`), httpCallTo("payments", http.MethodPost, "/v1/refunds", `{}`)})
			if results[0].Status != tc.want {
				t.Fatalf("status = %s, want %s", results[0].Status, tc.want)
			}
			if reqs, _ := g.calls(); tc.want != callSucceeded && len(reqs) != 1 {
				t.Fatalf("%d calls reached the gateway, want 1", len(reqs))
			}
		})
	}
}

// A refusal or tool error whose recorded outcome is UNKNOWN is UNKNOWN
// whatever its class, and a tool error without PantherClaw's facts has no
// definite outcome (the gateway puts them on every error it makes after
// dispatch; JSON-RPC errors are all made before it, gateway/mcp).
func TestAutomationRunner_UncertainToolErrorsAreUnknown(t *testing.T) {
	cases := map[string]struct {
		face   string
		answer func(w http.ResponseWriter, b []byte)
	}{
		"http class with unknown outcome": {faceHTTP, func(w http.ResponseWriter, _ []byte) {
			gatewayJSON(w, http.StatusBadGateway, nil, `{"error_class":"tool_failed","error":"target_refused","outcome":"UNKNOWN"}`)
		}},
		"mcp class with unknown outcome": {faceMCP, func(w http.ResponseWriter, b []byte) {
			mcpResult(w, b, `{"content":[],"isError":true,"_meta":{"io.pantherclaw/error":{"error_class":"enforcement_failed","error":"x","outcome":"UNKNOWN"}}}`)
		}},
		"mcp tool error without facts": {faceMCP, func(w http.ResponseWriter, b []byte) {
			mcpResult(w, b, `{"content":[{"type":"text","text":"boom"}],"isError":true}`)
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			g := newFakeGateway(t)
			g.answer = func(w http.ResponseWriter, _ *http.Request, b []byte, _ int) { tc.answer(w, b) }
			c, _ := newCallRunner(t, g)
			call := httpCallTo("payments", http.MethodPost, "/v1/refunds", `{}`)
			if tc.face == faceMCP {
				call = mcpCallTo("payments", "refund", `{}`)
			}
			results, _ := c.runCalls(t.Context(), []runnerCall{call, call})
			if len(results) != 2 || results[0].Status != callUnknown || results[1].Status != callSkipped {
				t.Fatalf("results = %+v, want one UNKNOWN", results)
			}
			if reqs, _ := g.calls(); len(reqs) != 1 {
				t.Fatalf("%d calls reached the gateway, want 1", len(reqs))
			}
		})
	}
}

// The runner's log shows method, path and status, never a rendered query
// or input (D82 R5), and says when parameter headers cannot be mirrored
// (R6).
func TestAutomationRunner_LogsCarryNoInputs(t *testing.T) {
	g := newFakeGateway(t)
	g.tools = `[{"name":"refund","inputSchema":{"type":"object","properties":{"charge":{"type":"string","x-mcp-header":"Charge"}}}}]`
	g.answer = hangUp2
	c, _ := newCallRunner(t, g)
	var log bytes.Buffer
	c.log = &log
	c.runCalls(t.Context(), []runnerCall{httpCallTo("payments", http.MethodGet, "/v1/charges", `{"customer":"secret-customer-42"}`)})
	c.runCalls(t.Context(), []runnerCall{mcpCallTo("payments", "refund", `{"charge":{"secret":1}}`)})
	got := log.String()
	if strings.Contains(got, "secret") {
		t.Fatalf("the log carries inputs:\n%s", got)
	}
	if !strings.Contains(got, "GET /payments/v1/charges") || !strings.Contains(got, "cannot be mirrored") {
		t.Fatalf("log = %s", got)
	}
}

func hangUp2(w http.ResponseWriter, r *http.Request, b []byte, _ int) { hangUp(w, r, b) }

// --gateway is https, or http on this machine only with --dev-insecure
// (D82 R4).
func TestHR285_TheGatewayMustBeHTTPS(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://gw.example.com":   true,
		"https://gw.example.com/":  true,
		"http://gw.example.com":    false,
		"http://127.0.0.1:8443":    false,
		"https://gw.example.com/x": false,
		"https://u@gw.example.com": false,
	} {
		if _, err := checkGateway(raw, false); (err == nil) != want {
			t.Errorf("checkGateway(%q) err = %v", raw, err)
		}
	}
	if _, err := checkGateway("http://127.0.0.1:8443", true); err != nil {
		t.Errorf("loopback with --dev-insecure: %v", err)
	}
	if _, err := checkGateway("http://gw.example.com", true); err == nil {
		t.Error("--dev-insecure allowed a remote http gateway")
	}
}

// A claim with fields the runner does not know, or a call it cannot read,
// runs nothing: the launch is returned without a run and completes FAILED
// (D82 R4).
func TestHR285_ClaimsTheRunnerCannotReadRunNothing(t *testing.T) {
	launch := ids.NewV7().String()
	ok := &pantherclawv1.ClaimLaunchResponse{
		Claimed: true, LaunchId: launch, RunId: ids.NewV7().String(),
		Calls: []*pantherclawv1.AutomationRunnerCall{{
			ConnectionId: ids.NewV7().String(), Face: "HTTP", Method: "POST", Path: "/v1/refunds",
			Input: map[string]string{"a": "1", "b": `"x"`, "c": "12.50"},
		}},
	}
	// The gateway routes by connection name (D83); a claim without one
	// cannot be performed.
	ok.Calls[0].ConnectionName = "payments"
	unnamed := proto.Clone(ok).(*pantherclawv1.ClaimLaunchResponse)
	unnamed.Calls[0].ConnectionName = ""
	unknown := proto.Clone(ok).(*pantherclawv1.ClaimLaunchResponse)
	unknown.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	badCall := proto.Clone(ok).(*pantherclawv1.ClaimLaunchResponse)
	badCall.Calls[0].ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	notJSON := proto.Clone(ok).(*pantherclawv1.ClaimLaunchResponse)
	notJSON.Calls[0].Input["b"] = "x"
	for name, tc := range map[string]struct {
		res     *pantherclawv1.ClaimLaunchResponse
		wantRun bool
	}{
		"ok": {ok, true}, "no connection name": {unnamed, false}, "unknown field": {unknown, false},
		"unknown call field": {badCall, false}, "input not JSON": {notJSON, false},
	} {
		t.Run(name, func(t *testing.T) {
			l, err := rpcLaunches{c: fakeLaunchClient{claim: tc.res}}.Claim(t.Context())
			if err != nil || l == nil || l.ID != launch {
				t.Fatalf("claim = %+v, %v", l, err)
			}
			if (l.RunID != "") != tc.wantRun {
				t.Fatalf("run = %q", l.RunID)
			}
			if tc.wantRun && string(l.Calls[0].Input) != `{"a":1,"b":"x","c":12.50}` {
				t.Fatalf("input = %s", l.Calls[0].Input)
			}
		})
	}
	if _, err := (rpcLaunches{c: fakeLaunchClient{claim: &pantherclawv1.ClaimLaunchResponse{Claimed: true}}}).Claim(t.Context()); err == nil {
		t.Fatal("a claim without a launch id was accepted")
	}
}

// fakeLaunchClient answers ClaimLaunch with claim and records completions.
type fakeLaunchClient struct {
	pantherclawv1connect.AutomationLaunchServiceClient
	claim *pantherclawv1.ClaimLaunchResponse
}

func (f fakeLaunchClient) ClaimLaunch(context.Context, *pantherclawv1.ClaimLaunchRequest) (*pantherclawv1.ClaimLaunchResponse, error) {
	return f.claim, nil
}

// oneFailedRestSkipped reports whether results itemize n calls of which
// one FAILED and none was sent.
func oneFailedRestSkipped(results []callResult, n int) bool {
	if len(results) != n && !(n > runnerMaxCalls && len(results) == 1) {
		return false
	}
	failed := 0
	for i, r := range results {
		switch {
		case r.Status == callFailed:
			failed++
		case r.Status != callSkipped || r.Index != i:
			return false
		}
	}
	return failed == 1
}
