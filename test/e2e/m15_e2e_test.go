// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/pclaw"
)

// The M15 exit (G0 M15 D15): the gateway's MCP holds, tasks and sessions
// live on the server, so two gateway processes of one gateway record serve
// the same agent as one, and a restart loses nothing (HR-411..413).

// replica starts another gateway process from the stack's saved identity,
// at its own address; stop ends it as a crash would.
func (s *stack) replica(t *testing.T) (url string, stop func()) {
	t.Helper()
	gs := httptest.NewUnstartedServer(nil)
	cfg := s.gatewayCfg
	cfg.PublicURL = "http://" + gs.Listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	id, err := gateway.LoadOrEnroll(ctx, &cfg, s.gatewayEnroll, s.gatewayLog())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	g, err := gateway.New(ctx, &cfg, id, s.gatewayLog())
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	go func() { _ = g.Run(ctx) }()
	if err := g.WaitReady(ctx, 30*time.Second); err != nil {
		cancel()
		t.Fatal(err)
	}
	gs.Config.Handler = g.Handler()
	gs.Start()
	stop = func() { gs.Close(); cancel() }
	t.Cleanup(stop)
	return gs.URL, stop
}

// mcpProxyAt is mcpProxy through the gateway at gw.
func (s *stack) mcpProxyAt(t *testing.T, gw string, messages ...string) map[int]string {
	t.Helper()
	var out, errb bytes.Buffer
	args := []string{"mcp", "proxy", "--gateway", gw, "--connection", "payments", "--key-file", s.keyFile}
	stdin := strings.NewReader(strings.Join(messages, "\n") + "\n")
	if code := pclaw.Run(context.Background(), args, &out, &errb, noEnv, pclaw.Options{Stdin: stdin}); code != 0 {
		t.Fatalf("mcp proxy exited %d: %s", code, errb.String())
	}
	answers := map[int]string{}
	for line := range strings.Lines(out.String()) {
		var m struct {
			ID *int `json:"id"`
		}
		if json.Unmarshal([]byte(line), &m) == nil && m.ID != nil {
			answers[*m.ID] = line
		}
	}
	return answers
}

// legacyPost sends one PAP/1-signed 2025-11-25 request to the gateway at
// gw in session sid ("" for initialize) and returns the status, the
// session header and the body.
func (s *stack) legacyPost(t *testing.T, gw, sid, body string) (int, string, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, gw+"/mcp/payments", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(gateway.HeaderRunID, s.run)
	if sid != "" {
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		req.Header.Set("Mcp-Session-Id", sid)
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id"), string(b)
}

// latestTransaction is the transaction of the latest approval request.
func (s *stack) latestTransaction(t *testing.T) string {
	t.Helper()
	var txn string
	s.query(t, "SELECT transaction_id::text FROM pc.approval_requests ORDER BY created_at DESC LIMIT 1", nil, &txn)
	return txn
}

// TestE2E_M15_SharedMCPState: two gateway processes A and B on one gateway
// record. A tools/call held on A is approved, and the identical call on B
// reuses the held action and is dispatched once. A task created on A is
// polled to completion on B. A session opened on A is used on B. After A
// restarts, a hold and a session it made before still bind (G0 M15 D15).
func TestE2E_M15_SharedMCPState(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", people: &p, brokerKey: true})
	_, b, key := approver(t, s, &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p})
	a, stopA := s.replica(t)
	bURL, _ := s.replica(t)
	const modern = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
	const withTasks = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`
	call := func(id int, amount, meta string) string {
		return `{"jsonrpc":"2.0","id":` + itoa(int64(id)) + `,"method":"tools/call","params":{"name":"create_refund","arguments":` +
			`{"charge":"ch_1","amount":"` + amount + `","currency":"USD","reason":"duplicate"},` + meta + `}}`
	}

	// A hold made on A binds on B.
	if r := s.mcpProxyAt(t, a, call(1, "85.00", modern))[1]; !strings.Contains(r, `"isError":true`) || s.simCalls.Load() != 0 {
		t.Fatalf("held on A: %s", r)
	}
	held := s.latestTransaction(t)
	s.approve(t, b, key, held)
	if r := s.mcpProxyAt(t, bURL, call(2, "85.00", modern))[2]; !strings.Contains(r, `"isError":false`) || s.simCalls.Load() != 1 {
		t.Fatalf("the identical call on B: %s (target calls %d)", r, s.simCalls.Load())
	}
	if st := s.requestState(t, held); st != "CONSUMED" {
		t.Fatalf("the approval of A's hold after B dispatched: %s", st)
	}

	// A task created on A completes when B polls it.
	var task struct {
		Result struct {
			ResultType string `json:"resultType"`
			TaskID     string `json:"taskId"`
			Status     string `json:"status"`
		} `json:"result"`
	}
	answer := s.mcpProxyAt(t, a, call(3, "86.00", withTasks))[3]
	if err := json.Unmarshal([]byte(answer), &task, json.RejectUnknownMembers(false)); err != nil || task.Result.ResultType != "task" ||
		task.Result.Status != "working" || task.Result.TaskID == "" {
		t.Fatalf("a held refund over MCP on A: %s", answer)
	}
	s.approve(t, b, key, s.latestTransaction(t))
	poll := `{"jsonrpc":"2.0","id":4,"method":"tasks/get","params":{"taskId":"` + task.Result.TaskID + `",` + withTasks + `}}`
	if done := s.mcpProxyAt(t, bURL, poll)[4]; !strings.Contains(done, `"status":"completed"`) || !strings.Contains(done, `"isError":false`) ||
		s.simCalls.Load() != 2 {
		t.Fatalf("A's task polled on B: %s (target calls %d)", done, s.simCalls.Load())
	}

	// A session opened on A is used on B.
	const initialize = `{"jsonrpc":"2.0","id":5,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},` +
		`"clientInfo":{"name":"e2e","version":"1"}}}`
	status, sid, body := s.legacyPost(t, a, "", initialize)
	if status != http.StatusOK || sid == "" {
		t.Fatalf("initialize on A: %d %s", status, body)
	}
	list := `{"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}`
	if status, _, body := s.legacyPost(t, bURL, sid, list); status != http.StatusOK || !strings.Contains(body, `"create_refund"`) {
		t.Fatalf("A's session on B: %d %s", status, body)
	}

	// A restarts: its hold and its session survive.
	if r := s.mcpProxyAt(t, a, call(7, "87.00", modern))[7]; !strings.Contains(r, `"isError":true`) {
		t.Fatalf("held on A before the restart: %s", r)
	}
	held = s.latestTransaction(t)
	stopA()
	a2, _ := s.replica(t)
	s.approve(t, b, key, held)
	if r := s.mcpProxyAt(t, a2, call(8, "87.00", modern))[8]; !strings.Contains(r, `"isError":false`) || s.simCalls.Load() != 3 {
		t.Fatalf("the identical call after A restarted: %s (target calls %d)", r, s.simCalls.Load())
	}
	if st := s.requestState(t, held); st != "CONSUMED" {
		t.Fatalf("the approval of the hold made before the restart: %s", st)
	}
	if status, _, body := s.legacyPost(t, a2, sid, list); status != http.StatusOK || !strings.Contains(body, `"create_refund"`) {
		t.Fatalf("the session after A restarted: %d %s", status, body)
	}
	var replicas int
	s.query(t, "SELECT count(*) FROM pc.gateway_replicas WHERE org_id = $1", []any{s.org}, &replicas)
	if replicas < 3 {
		t.Fatalf("%d replicas reported status, want A, B and A after its restart at least", replicas)
	}
}

// TestE2E_M15_DiscoveryToReviewedTool: a tool the upstream MCP server lists
// beyond the reviewed package is drafted, reviewed, signed and activated
// before any agent can see or call it (G0 M15 D15, D24; helper in
// m15_discovery_test.go).
// Covers: F352
func TestE2E_M15_DiscoveryToReviewedTool(t *testing.T) { discoveryToReviewedTool(t) }

// TestE2E_M15_ResourceAndElicitation: reviewed resources are reads decided
// by the full pipeline, and elicitation reaches the agent only through the
// declared, scanned, policy-decided path (G0 M15 D15, D35; helper in
// m15_surface_test.go).
// Covers: F352, PN-015.2
func TestE2E_M15_ResourceAndElicitation(t *testing.T) { m15ResourceAndElicitation(t) }
