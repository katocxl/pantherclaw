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

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	gapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The gateway's other faces and its own lifecycle, end to end (G0 M6, the
// end-to-end list): MCP in both protocol versions through pclaw mcp proxy,
// the Claude Code hook through pclaw hook claude-code, and a gateway that
// enrolls, renews and is revoked.

// TestE2E_M6_MCPBothVersions: an MCP client reaches the payments
// connection through pclaw mcp proxy, which signs every message with the
// workload's key (HR-092). A 2026-07-28 client lists the reviewed tool and
// refunds statelessly; a 2025-11-25 client initializes a session and does
// the same (HR-083). Each refund is decided and dispatched like an HTTP
// one: the target sees exactly two.
func TestE2E_M6_MCPBothVersions(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	call := func(id int, amount, meta string) string {
		return `{"jsonrpc":"2.0","id":` + itoa(int64(id)) + `,"method":"tools/call","params":{"name":"create_refund","arguments":` +
			`{"charge":"ch_1","amount":"` + amount + `","currency":"USD","reason":"duplicate"}` + meta + `}}`
	}
	const modern = `,"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`

	answers := s.mcpProxy(t,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+modern[1:]+`}}`,
		call(2, "30.00", modern))
	if tools := answers[1]; !strings.Contains(tools, `"create_refund"`) {
		t.Fatalf("2026-07-28 tools/list: %s", tools)
	}
	if r := answers[2]; !strings.Contains(r, `"isError":false`) {
		t.Fatalf("2026-07-28 tools/call: %s", r)
	}

	answers = s.mcpProxy(t,
		`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},`+
			`"clientInfo":{"name":"e2e","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`,
		call(5, "31.00", ""))
	if init := answers[3]; !strings.Contains(init, `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("2025-11-25 initialize: %s", init)
	}
	if tools := answers[4]; !strings.Contains(tools, `"create_refund"`) {
		t.Fatalf("2025-11-25 tools/list: %s", tools)
	}
	if r := answers[5]; !strings.Contains(r, `"isError":false`) {
		t.Fatalf("2025-11-25 tools/call: %s", r)
	}
	if st := s.sim.Stats(); st.Refunds != 2 {
		t.Fatalf("target %+v, want the two refunds", st)
	}

	// A signed client that names another tool in Mcp-Name than in the body
	// is refused before anything is decided, and so is a batch: the gateway
	// takes one request per POST.
	mismatched := call(6, "32.00", modern)
	if status, body := s.mcpPost(t, mismatched, map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "get_refund"}); status != http.StatusBadRequest ||
		!strings.Contains(body, `"code":-32020`) {
		t.Fatalf("header mismatch: %d %s", status, body)
	}
	if status, body := s.mcpPost(t, "["+call(7, "33.00", modern)+"]", nil); status != http.StatusBadRequest || !strings.Contains(body, "batches") {
		t.Fatalf("batch: %d %s", status, body)
	}
	if st := s.sim.Stats(); st.Refunds != 2 {
		t.Fatalf("target %+v after the refused requests, want the two refunds", st)
	}
}

// mcpPost sends one PAP/1-signed 2026-07-28 MCP request straight to the
// gateway, with the protocol header and extra headers, and returns the
// status and the body.
func (s *stack) mcpPost(t *testing.T, body string, headers map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/mcp/payments", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set(gateway.HeaderRunID, s.run)
	for k, v := range headers {
		req.Header.Set(k, v)
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
	return resp.StatusCode, string(b)
}

// TestE2E_M6_ClaudeCodeHook: Claude Code asks pclaw hook claude-code before
// a shell command (HR-186). The seeded grant allows shell commands, so the
// hook answers allow with exit code 0; the decision is recorded as
// delegated, because the command runs on the developer's machine, not
// through the gateway. A command the org's published policy forbids is
// blocked with exit code 2 and the policy's reason, and so is every command
// when the gateway is down or once the kill switch is engaged; the hook
// never asks the local user.
func TestE2E_M6_ClaudeCodeHook(t *testing.T) {
	s := start(t, options{budget: "1000.00", shell: true})
	dir := t.TempDir()
	eventFor := func(id, command string) string {
		b, _ := json.Marshal(map[string]any{
			"session_id": "e2e", "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": dir, "tool_use_id": id,
			"tool_input": map[string]any{"command": command, "description": "e2e"},
		})
		return string(b)
	}
	event := func(id string) string { return eventFor(id, "ls -la") }
	blocked := func(code int, out, errs, want string) bool {
		return code == 2 && out == "" && strings.Contains(errs, want) && !strings.Contains(errs, `"ask"`)
	}
	code, out, errs := s.hook(t, event("toolu_e2e1"))
	if code != 0 || !strings.Contains(out, `"permissionDecision":"allow"`) {
		t.Fatalf("allowed command: %d %s %s", code, out, errs)
	}
	var outcome string
	s.query(t, "SELECT outcome FROM pc.execution_attempts ORDER BY recorded_at DESC LIMIT 1", nil, &outcome)
	if outcome != "delegated" {
		t.Fatalf("recorded outcome %q, want delegated", outcome)
	}
	// The command ran on the developer's machine and pc.shell declares no
	// verifier: its effect is UNVERIFIABLE, reaches no level, and is
	// labeled PARTIAL coverage (G0 M7 design decision 2, HR-186).
	effect := s.row(t, `SELECT e.state || ' ' || e.basis || ' ' || coalesce(e.level_achieved, '-') || ' ' || e.receipt_jws FROM pc.effect_receipts e
		JOIN pc.execution_attempts a ON a.org_id = e.org_id AND a.transaction_id = e.transaction_id ORDER BY a.recorded_at DESC LIMIT 1`)
	if f := strings.Fields(effect); len(f) != 4 || strings.Join(f[:3], " ") != "UNVERIFIABLE definition -" || papClaims(t, f[3])["coverage"] != "PARTIAL" {
		t.Fatalf("the delegated command's effect receipt %q", effect)
	}

	s.publishPolicy(t, `{"id": "shell", "rules": [{"id": "no-rm", "kind": "FORBID", "summary": "destructive commands",
		"operations": ["shell.command.run"], "when": "action.params.command.startsWith(\"rm \")", "reason": "SHELL_DESTRUCTIVE"}]}`)
	if code, out, errs := s.hook(t, eventFor("toolu_e2e2", "rm -rf build")); !blocked(code, out, errs, "SHELL_DESTRUCTIVE") {
		t.Fatalf("forbidden command: %d %s %s", code, out, errs)
	}
	if code, out, errs := s.hook(t, event("toolu_e2e3")); code != 0 {
		t.Fatalf("allowed command after the policy: %d %s %s", code, out, errs)
	}

	up := s.gateway
	s.gateway = "http://" + freeAddr(t) // nothing listens there
	if code, out, errs := s.hook(t, event("toolu_e2e4")); !blocked(code, out, errs, "") {
		t.Fatalf("gateway down: %d %s %s", code, out, errs)
	}
	s.gateway = up

	alice := s.person(t, "alice", td.RoleEmergency)
	if _, err := rapp.New(s.pool, nil, s.apiURL).Engage(alice.ctx, rapp.StepUp{Credential: alice.key, At: time.Now()}, "e2e"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for {
		code, out, errs = s.hook(t, event("toolu_e2e5"))
		if blocked(code, out, errs, "kill_switch") {
			break
		}
		if code == 0 || time.Since(start) > 2*time.Second {
			t.Fatalf("after the kill switch: %d %s %s", code, out, errs)
		}
	}
}

// TestE2E_M6_GatewayEnrollRenewRevoke: a gateway enrolls once with its
// single-use token (HR-180), renews its certificate over mTLS with a new
// key and keeps serving from the saved identity, and stops within a second
// of being revoked (HR-181, HR-002).
func TestE2E_M6_GatewayEnrollRenewRevoke(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	ctx := context.Background()

	// The enrollment token was used by the first start.
	again := s.gatewayCfg
	again.Control.IdentityDir = t.TempDir()
	if _, err := gateway.LoadOrEnroll(ctx, &again, s.gatewayEnroll, pclog.Discard()); err == nil {
		t.Fatal("the enrollment token enrolled a second time")
	}

	id, err := control.Load(s.gatewayCfg.Control.IdentityDir, s.gatewayCfg.Control.CASHA256)
	if err != nil {
		t.Fatal(err)
	}
	c := control.NewClient(id, s.gatewayCfg.Control.IdentityDir, s.gatewayCfg.Control.GatewayURL, s.gatewayCfg.Control.Timeout.D(), pclog.Discard())
	if err := c.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	renewed, err := control.Load(s.gatewayCfg.Control.IdentityDir, s.gatewayCfg.Control.CASHA256)
	if err != nil || renewed.Cert == id.Cert || renewed.Gateway != id.Gateway {
		t.Fatalf("renewed identity %v (was %v): %v", renewed.Cert, id.Cert, err)
	}
	var certs int
	s.query(t, "SELECT count(*) FROM pc.gateway_certs WHERE gateway_id = $1 AND revoked_at IS NULL", []any{id.Gateway}, &certs)
	if certs != 2 {
		t.Fatalf("%d active certificates, want the enrolled and the renewed", certs)
	}
	// A second instance starts from the renewed identity and serves.
	first := s.gateway
	s.gateway = s.anotherGateway(t)
	if code, r := s.refund(t, ids.NewV7(), "30.00"); code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("through the renewed gateway: %d %+v", code, r)
	}

	admin := s.person(t, "gateway-admin", td.RoleGatewayAdmin)
	if _, err := gapp.New(s.pool, nil, "", nil).RevokeGateway(admin.ctx, id.Gateway, "e2e"); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	for _, g := range []string{s.gateway, first} {
		s.gateway = g
		for {
			code, r := s.refund(t, ids.NewV7(), "31.00")
			if r.Error == "gateway_revoked" && code == http.StatusServiceUnavailable {
				break
			}
			if code == http.StatusOK || time.Since(revoked) > 2*time.Second {
				t.Fatalf("gateway %s after revocation: %d %+v", g, code, r)
			}
		}
	}
	if st := s.sim.Stats(); st.Refunds != 1 {
		t.Fatalf("target %+v, want only the refund before the revocation", st)
	}
}

// mcpProxy runs pclaw mcp proxy with messages on stdin, one per line, and
// returns its answers by JSON-RPC id.
func (s *stack) mcpProxy(t *testing.T, messages ...string) map[int]string {
	t.Helper()
	var out, errb bytes.Buffer
	args := []string{"mcp", "proxy", "--gateway", s.gateway, "--connection", "payments", "--key-file", s.keyFile}
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

// publishPolicy creates a policy bundle as a policy author and publishes it
// as a publisher, as pclaw policy create and publish do.
func (s *stack) publishPolicy(t *testing.T, bundle string) {
	t.Helper()
	v := &policyapp.Versions{
		Store: &polpg.Store{Pool: s.pool}, Facts: &factspg.Store{Pool: s.pool}, Definitions: &defspg.Store{Pool: s.pool},
		Authz: grantsapp.SubjectAuthorizer{}, Limits: celenv.DefaultLimits,
	}
	draft, err := v.Create(s.person(t, "policy-author", td.RolePolicyAuthor).ctx, []byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Publish(s.person(t, "policy-publisher", td.RolePolicyPublisher).ctx, draft.ID); err != nil {
		t.Fatal(err)
	}
}

// hook runs pclaw hook claude-code with a PreToolUse event on stdin.
func (s *stack) hook(t *testing.T, event string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	args := []string{"hook", "claude-code", "--gateway", s.gateway, "--connection", "shell", "--key-file", s.keyFile}
	code := pclaw.Run(context.Background(), args, &out, &errb, noEnv, pclaw.Options{Stdin: strings.NewReader(event)})
	return code, out.String(), errb.String()
}

// anotherGateway starts a second gateway from the saved identity, at its
// own address, and returns that address.
func (s *stack) anotherGateway(t *testing.T) string {
	t.Helper()
	gs := httptest.NewUnstartedServer(nil)
	cfg := s.gatewayCfg
	cfg.PublicURL = "http://" + gs.Listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	id, err := gateway.LoadOrEnroll(ctx, &cfg, s.gatewayEnroll, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	g, err := gateway.New(ctx, &cfg, id, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = g.Run(ctx) }()
	if err := g.WaitReady(ctx, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	gs.Config.Handler = g.Handler()
	gs.Start()
	t.Cleanup(gs.Close)
	return gs.URL
}
