// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package live_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/redteam/adapters/live"
	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

const scenarioHead = `apiVersion: pantherclaw.range/v1
id: RT-009
title: t
category: boundary
suite: coding-agent
tier: community
attacker: A1
threats: [T-080]
rules: [HR-201]
steps:
`

func scenario(t *testing.T, steps string) domain.Scenario {
	t.Helper()
	s, err := domain.Parse([]byte(scenarioHead + steps))
	if err != nil {
		t.Fatal(err)
	}
	return *s
}

func driver(t *testing.T, h http.Handler, mod func(*live.Config)) *live.Driver {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := live.Config{
		Gateway: srv.URL, Client: srv.Client(), Run: "00000000-0000-4000-8000-000000000001",
		Roles: map[string]string{"github": "gh-sim"}, Fixture: app.Fixture{"pr": "7"},
		Capabilities: map[app.Capability]bool{app.CapGitHub: true, app.CapMCP: true},
	}
	if mod != nil {
		mod(&cfg)
	}
	return live.New(cfg)
}

func run(t *testing.T, d *live.Driver, steps string) domain.Result {
	t.Helper()
	return (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, steps))
}

func jsonBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("request body %q: %v", b, err)
	}
	return m
}

func TestSDKFaceOutcomes(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sdk/gh-sim" || r.Header.Get("PAP-Run-Id") == "" {
			t.Errorf("path %s run %q", r.URL.Path, r.Header.Get("PAP-Run-Id"))
		}
		in := jsonBody(t, r)
		if in["tool"] != "mcp__gh-sim__merge_pull_request" || in["server"] != "gh-sim" {
			t.Errorf("request %v", in)
		}
		switch r.Header.Get("PC-Action-Id") {
		case "act-1":
			_, _ = io.WriteString(w, `{"decision":"deny","error_class":"policy_denied","code":"ACTION_TAMPERED","reasons":["ACTION_TAMPERED"]}`)
		default:
			_, _ = io.WriteString(w, `{"decision":"hold","error_class":"held","code":"REQUIRE_APPROVAL","action_id":"act-1","transaction_id":"t-1","reasons":["REQUIRE_APPROVAL","GRANT_REQUIRES_APPROVAL"]}`)
		}
	})
	res := run(t, driver(t, h, nil), `  - id: merge
    do: agent.call
    with: {face: sdk, connection: github, tool: merge_pull_request, args: {number: "${fixture.pr}"}}
    expect: {outcome: HOLD, reason: GRANT_REQUIRES_APPROVAL}
  - id: again
    do: agent.call
    with: {face: sdk, connection: github, tool: merge_pull_request, action_of: merge, args: {number: "8"}}
    expect: {outcome: DENY, reason: ACTION_TAMPERED}
`)
	if res.Verdict != domain.VerdictPass {
		t.Fatalf("%+v", res)
	}
	if res.Steps[0].Observed.TransactionID != "t-1" {
		t.Errorf("transaction %q", res.Steps[0].Observed.TransactionID)
	}
}

func TestHookFaceFailsClosedWhenTheGatewayIsUnreachable(t *testing.T) {
	var hits atomic.Int32
	d := driver(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }), nil)
	res := run(t, d, `  - id: hook
    do: agent.call
    with: {face: hook, connection: local, tool: pc.shell, fault: gateway_unreachable, args: {command: "git push"}}
    expect: {outcome: REFUSED, code: hook_exit_2}
`)
	if res.Verdict != domain.VerdictPass || hits.Load() != 0 {
		t.Fatalf("%+v hits=%d", res, hits.Load())
	}
}

func TestHookFaceDecisions(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"decision":"deny","held":true,"error_class":"held","code":"REQUIRE_APPROVAL","transaction_id":"t-2"}`)
	})
	res := run(t, driver(t, h, nil), `  - id: hook
    do: agent.call
    with: {face: hook, connection: local, tool: pc.shell, args: {command: ls}}
    expect: {outcome: HOLD}
`)
	if res.Verdict != domain.VerdictPass {
		t.Fatalf("%+v", res)
	}
}

func TestHTTPFaceRefusalsAndAllows(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gh-sim/repos/range/app/pulls":
			w.Header().Set("PC-Decision", "ALLOW")
			w.Header().Set("PC-Transaction-Id", "t-3")
			_, _ = io.WriteString(w, `{"number": 12}`)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error_class":"cannot_authorize","error":"kill_switch"}`)
		}
	})
	res := run(t, driver(t, h, nil), `  - id: open
    do: agent.call
    with: {face: http, connection: github, method: POST, path: /repos/range/app/pulls, body: {title: x}}
    save: {pr: /number}
    expect: {outcome: ALLOW}
  - id: refused
    do: agent.call
    with: {face: http, connection: github, method: PUT, path: "/repos/range/app/pulls/${pr}/merge"}
    expect: {outcome: REFUSED, code: kill_switch}
`)
	if res.Verdict != domain.VerdictPass {
		t.Fatalf("%+v", res)
	}
}

func TestMCPFaceListsThenCallsWithTheVersionHeaders(t *testing.T) {
	var methods []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in := jsonBody(t, r)
		m, _ := in["method"].(string)
		methods = append(methods, m)
		if r.Header.Get("Mcp-Method") != m || r.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
			t.Errorf("headers %v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		if m == "tools/list" {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"merge_pull_request","inputSchema":{"type":"object"}}]}}`)
			return
		}
		if r.Header.Get("Mcp-Name") != "merge_pull_request" {
			t.Errorf("Mcp-Name %q", r.Header.Get("Mcp-Name"))
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[],"_meta":{"io.pantherclaw/error":{"error_class":"policy_denied","error":"DESTINATION_NOT_GRANTED","decision":"DENY","reasons":["DESTINATION_NOT_GRANTED"],"transaction_id":"t-4"}}}}`)
	})
	step := `  - id: exfil
    do: agent.call
    with: {face: mcp, connection: github, tool: merge_pull_request, args: {repo: other}}
    expect: {outcome: DENY, reason: DESTINATION_NOT_GRANTED}
`
	d := driver(t, h, nil)
	if res := run(t, d, step+strings.Replace(step, "exfil", "exfil2", 1)); res.Verdict != domain.VerdictPass {
		t.Fatalf("%+v", res)
	}
	if strings.Join(methods, ",") != "tools/list,tools/call,tools/call" {
		t.Errorf("methods %v (the tool list is fetched once)", methods)
	}
}

func TestConcurrentCallsAreJudgedEach(t *testing.T) {
	var n atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in := jsonBody(t, r)
		input, _ := in["input"].(map[string]any)
		if !strings.HasPrefix(input["charge"].(string), "c-") {
			t.Errorf("${n} not substituted: %v", input)
		}
		if n.Add(1) <= 2 {
			_, _ = io.WriteString(w, `{"decision":"allow","action_id":"a"}`)
			return
		}
		_, _ = io.WriteString(w, `{"decision":"deny","error_class":"policy_denied","code":"BUDGET_EXHAUSTED"}`)
	})
	d := driver(t, h, func(c *live.Config) { c.Roles = nil })
	res := run(t, d, `  - id: race
    do: agent.call
    with: {face: sdk, connection: payments, tool: refund, concurrent: 5, args: {charge: "c-${n}"}}
    expect: {max_allow: 2}
`)
	if res.Verdict != domain.VerdictPass {
		t.Fatalf("%+v", res)
	}
	n.Store(0)
	res = run(t, d, `  - id: race
    do: agent.call
    with: {face: sdk, connection: payments, tool: refund, concurrent: 5, args: {charge: "c-${n}"}}
    expect: {max_allow: 1}
`)
	if res.Verdict != domain.VerdictFail {
		t.Fatalf("over-allow should FAIL: %+v", res)
	}
}

func TestUnsupportedStepsSkipTheScenario(t *testing.T) {
	d := driver(t, http.NotFoundHandler(), nil)
	for _, step := range []string{
		"  - {id: a, do: sandbox.probe, with: {probe: icmp}, expect: {outcome: BLOCKED}}\n",
		"  - {id: a, do: agent.steal, with: {mode: proof_replay, call: {face: mcp, connection: github, tool: t}}, expect: {outcome: DENY}}\n",
		"  - {id: a, do: agent.call, with: {face: sdk, connection: github, method: GET, path: /x}, expect: {outcome: ALLOW}}\n",
		"  - {id: a, do: agent.call, with: {face: mcp, connection: github, tool: t, instance: other}, expect: {outcome: ALLOW}}\n",
		"  - {id: a, do: wait, with: {for: effect_confirmed, of: a, max_seconds: 1}, expect: {outcome: CONFIRMED}}\n",
	} {
		if strings.Contains(step, "do: wait") {
			// wait needs an earlier step: put a revoke first.
			step = "  - {id: b, do: operator.revoke_grant}\n" + strings.Replace(step, "of: a", "of: b", 1)
		}
		if res := run(t, d, step); res.Verdict != domain.VerdictSkipped {
			t.Errorf("%s: %+v", step, res)
		}
	}
	if d.Capabilities()[app.CapPerson] {
		t.Error("a driver without an operator claims the person capability")
	}
}

type fakeTxns struct{ states map[string]live.TxnState }

func (f fakeTxns) State(_ context.Context, id string) (live.TxnState, error) {
	s, ok := f.states[id]
	if !ok {
		return live.TxnState{}, errors.New("unknown transaction")
	}
	return s, nil
}

type fakeOperator struct{ asked []string }

func (o *fakeOperator) Decide(_ context.Context, txn, role string, approve bool) error {
	o.asked = append(o.asked, txn+":"+role)
	return nil
}

func TestPersonWaitAndReceiptSteps(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"decision":"hold","error_class":"held","code":"REQUIRE_APPROVAL","transaction_id":"t-9"}`)
	})
	op := &fakeOperator{}
	txns := fakeTxns{states: map[string]live.TxnState{"t-9": {
		Approved: true, Effect: "CONFIRMED", Decision: "HOLD",
		Receipt: map[string]bool{"grant": true, "policy_version": true, "package_version": true, "facts": true, "simulated": true},
	}}}
	d := driver(t, h, func(c *live.Config) { c.Operator, c.Txns = op, txns })
	if !d.Capabilities()[app.CapPerson] {
		t.Fatal("no person capability with an operator")
	}
	res := run(t, d, `  - {id: merge, do: agent.call, with: {face: sdk, connection: github, tool: merge_pull_request}, expect: {outcome: HOLD}}
  - {id: approve, do: person.approve, with: {step: merge, as: approver}, expect: {outcome: ALLOW}}
  - {id: settled, do: wait, with: {for: effect_confirmed, of: merge, max_seconds: 2}, expect: {outcome: CONFIRMED}}
  - {id: evidence, do: check.receipt, with: {of: merge, has: [grant, policy_version, package_version, facts, simulated]}, expect: {outcome: HOLD}}
`)
	if res.Verdict != domain.VerdictPass || len(op.asked) != 1 || op.asked[0] != "t-9:approver" {
		t.Fatalf("%+v asked=%v", res, op.asked)
	}
	// A receipt that lacks a part FAILS the step.
	txns.states["t-9"] = live.TxnState{Approved: true, Effect: "CONFIRMED", Decision: "HOLD", Receipt: map[string]bool{"grant": true}}
	res = run(t, d, `  - {id: merge, do: agent.call, with: {face: sdk, connection: github, tool: merge_pull_request}, expect: {outcome: HOLD}}
  - {id: evidence, do: check.receipt, with: {of: merge, has: [grant, simulated]}, expect: {outcome: HOLD}}
`)
	if res.Verdict != domain.VerdictFail {
		t.Fatalf("%+v", res)
	}
}

// A client that fails the test if it is used: the hook's unreachable path
// must never reach for the workload-signing client.
type forbiddenTransport struct{ t *testing.T }

func (f forbiddenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("the signing client was used for %s", r.URL)
	return nil, errors.New("forbidden")
}

func TestHookFaultSendsNothingToTheUnreachableAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var received atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, _ := c.Read(make([]byte, 4096))
			received.Add(int64(n))
			_ = c.Close()
		}
	}()
	d := live.New(live.Config{
		Gateway: "http://127.0.0.1:9", Client: &http.Client{Transport: forbiddenTransport{t}}, Run: "r",
		Unreachable: "http://" + ln.Addr().String(),
	})
	// Something listens there, so the "unreachable" gateway answers: that is
	// an error, and not one byte (no PAP proof, no token) was sent to it.
	res := (&app.Runner{Driver: d}).Run(context.Background(), scenario(t, `  - id: hook
    do: agent.call
    with: {face: hook, connection: local, tool: pc.shell, fault: gateway_unreachable, args: {command: ls}}
    expect: {outcome: REFUSED, code: hook_exit_2}
`))
	time.Sleep(400 * time.Millisecond)
	if res.Verdict != domain.VerdictError || received.Load() != 0 {
		t.Fatalf("%+v received %d bytes", res, received.Load())
	}
}
