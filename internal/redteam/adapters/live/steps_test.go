// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package live_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/redteam/adapters/live"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

const childRun = "0192aaaa-bbbb-7ccc-8ddd-0000000000c9"

func TestSupportsFollowsD33(t *testing.T) {
	d := live.New(live.Config{})
	for _, k := range []string{"agent.call", "agent.child", "agent.steal", "target.replay", "wait", "check.receipt", "person.approve", "person.decline"} {
		if !d.Supports(k) {
			t.Errorf("%s unsupported", k)
		}
	}
	for _, k := range []string{"agent.direct", "sim.mutate", "operator.revoke_grant", "operator.kill_switch", "server.read", "sandbox.probe"} {
		if d.Supports(k) {
			t.Errorf("%s supported", k)
		}
	}
	// An unsupported kind skips the scenario before anything is set up.
	res := run(t, d, "  - {id: a, do: operator.revoke_grant}\n")
	if res.Verdict != domain.VerdictSkipped || res.Detail != "driver lacks operator.revoke_grant" {
		t.Errorf("%+v", res)
	}
}

func TestHTTPFaceSendsRunAndActionIDs(t *testing.T) {
	var mu sync.Mutex
	var actions []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PAP-Run-Id") == "" || r.Header.Get("PC-Action-Id") == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error_class":"cannot_authorize","error":"run_and_action_ids_required"}`)
			return
		}
		mu.Lock()
		actions = append(actions, r.Header.Get("PC-Action-Id"))
		mu.Unlock()
		w.Header().Set("PC-Decision", "ALLOW")
		_, _ = io.WriteString(w, `{}`)
	})
	res := run(t, driver(t, h, nil), `  - {id: a, do: agent.call, with: {face: http, connection: github, method: GET, path: /x}, expect: {outcome: ALLOW}}
  - {id: b, do: agent.call, with: {face: http, connection: github, method: GET, path: /x}, expect: {outcome: ALLOW}}
`)
	if res.Verdict != domain.VerdictPass || len(actions) != 2 || actions[0] == actions[1] || len(actions[0]) != 36 {
		t.Fatalf("%+v actions=%v", res, actions)
	}
}

type fakeWorkload struct {
	pantherclawv1connect.UnimplementedWorkloadServiceHandler
	delegated *pantherclawv1.DelegateGrantRequest
}

func (f *fakeWorkload) StartChildRun(context.Context, *pantherclawv1.StartChildRunRequest) (*pantherclawv1.StartChildRunResponse, error) {
	return &pantherclawv1.StartChildRunResponse{Run: &pantherclawv1.Run{Id: childRun}}, nil
}

func (f *fakeWorkload) DelegateGrant(_ context.Context, r *pantherclawv1.DelegateGrantRequest) (*pantherclawv1.DelegateGrantResponse, error) {
	f.delegated = r
	return nil, connect.NewError(connect.CodePermissionDenied, "OUTSIDE_ALLOWED_AUTHORITY: wider than the parent")
}

func TestAgentChildDelegatesThenActsInTheChildRun(t *testing.T) {
	fw := &fakeWorkload{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterWorkloadServiceHandler(cs, fw)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	wsrv := httptest.NewServer(mux)
	t.Cleanup(wsrv.Close)
	var childSaw string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		childSaw = r.Header.Get("PAP-Run-Id")
		_, _ = io.WriteString(w, `{"decision":"deny","error_class":"policy_denied","code":"NO_GRANT","reasons":["NO_GRANT"]}`)
	})
	d := driver(t, h, func(c *live.Config) {
		c.Workload = pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(wsrv.Client(), wsrv.URL)))
		c.AgentID = "0192aaaa-bbbb-7ccc-8ddd-0000000000a1"
		c.Roles = nil
	})
	res := run(t, d, `  - id: child
    do: agent.child
    with: {grant: {widen: [operations]}, then: {face: sdk, connection: github, tool: create_pull_request, args: {title: x}}}
    expect: {outcome: DENY, reason: NO_GRANT, code: OUTSIDE_ALLOWED_AUTHORITY}
`)
	if res.Verdict != domain.VerdictPass || childSaw != childRun || fw.delegated.GetChildRunId() != childRun || !strings.Contains(string(fw.delegated.GetBounds()), "github.*") {
		t.Fatalf("%+v childSaw=%q delegated=%v", res, childSaw, fw.delegated)
	}
	// A dimension the driver cannot widen skips the scenario.
	if res := run(t, d, `  - {id: child, do: agent.child, with: {grant: {widen: [amount]}, then: {face: sdk, connection: github, tool: t}}, expect: {outcome: DENY}}
`); res.Verdict != domain.VerdictSkipped {
		t.Errorf("%+v", res)
	}
}

// stealGateway records the PAP headers of each request and refuses the way
// the gateway does.
type stealGateway struct {
	mu     sync.Mutex
	proofs []string
}

func (g *stealGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.proofs = append(g.proofs, r.Header.Get("PAP-Proof"))
	n := len(g.proofs)
	g.mu.Unlock()
	code := map[string]string{"/gh-sim/replay": "proof_replay", "/gh-sim/nonce": "use_nonce"}[r.URL.Path]
	if code == "" {
		code = "key_mismatch"
	}
	if code == "proof_replay" && n == 1 {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{}`)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"error_class":"authentication_failed","error":"`+code+`"}`)
}

func TestAgentStealModes(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	gw := &stealGateway{}
	d := driver(t, gw, func(c *live.Config) {
		c.Key, c.Token = key, func() string { return "tok" }
	})
	res := run(t, d, `  - id: no-key
    do: agent.steal
    with: {mode: token_without_key, call: {face: http, connection: github, method: GET, path: /thing}}
    expect: {outcome: REFUSED, code: key_mismatch}
`)
	if res.Verdict != domain.VerdictPass || len(gw.proofs) == 0 || gw.proofs[0] == "" {
		t.Fatalf("token without key: %+v proofs=%v", res, gw.proofs)
	}

	gw.proofs = nil
	res = run(t, d, `  - id: replay
    do: agent.steal
    with: {mode: proof_replay, call: {face: http, connection: github, method: GET, path: /replay}}
    expect: {outcome: REFUSED, code: proof_replay}
`)
	if res.Verdict != domain.VerdictPass || len(gw.proofs) != 2 || gw.proofs[0] != gw.proofs[1] {
		t.Fatalf("proof replay: %+v proofs=%v", res, gw.proofs)
	}

	gw.proofs = nil
	res = run(t, d, `  - id: stale
    do: agent.steal
    with: {mode: stale_nonce, call: {face: http, connection: github, method: GET, path: /nonce}}
    expect: {outcome: REFUSED, code: use_nonce}
`)
	if res.Verdict != domain.VerdictPass || len(gw.proofs) != 1 || gw.proofs[0] == "" {
		t.Fatalf("stale nonce: %+v proofs=%v", res, gw.proofs)
	}

	// A second instance is beyond the live driver's means.
	if res := run(t, d, `  - id: other
    do: agent.steal
    with: {mode: other_instance, call: {face: http, connection: github, method: GET, path: /x}}
    expect: {outcome: REFUSED}
`); res.Verdict != domain.VerdictSkipped {
		t.Errorf("other_instance: %+v", res)
	}
}

func TestTargetReplayDeliversTheHandedRequestTwice(t *testing.T) {
	var deliveries int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveries++
		if r.Header.Get("X-Action-Token") != "at-1" {
			t.Errorf("headers %v", r.Header)
		}
		if deliveries > 1 {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"action_token_replayed"}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(target.Close)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"decision":"allow","action_id":"a1","dispatch":{"method":"POST","url":"`+target.URL+`/v1/refunds","headers":{"X-Action-Token":"at-1"},"body":""}}`)
	})
	res := run(t, driver(t, h, func(c *live.Config) { c.Roles = nil }), `  - {id: refund, do: agent.call, with: {face: sdk, connection: payments, tool: create_refund, args: {charge: c}}, expect: {outcome: ALLOW}}
  - {id: first, do: target.replay, with: {of: refund}, expect: {outcome: ALLOW}}
  - {id: second, do: target.replay, with: {of: refund}, expect: {outcome: TARGET_REFUSED, code: action_token_replayed}}
`)
	if res.Verdict != domain.VerdictPass || deliveries != 2 {
		t.Fatalf("%+v deliveries=%d", res, deliveries)
	}
}

type countingTransport struct{ n int }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n++
	return nil, errors.New("must not be sent")
}

func TestTargetReplayOnlyDeliversToALocalLiteral(t *testing.T) {
	ct := &countingTransport{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"decision":"allow","action_id":"a1","dispatch":{"method":"POST","url":"https://api.github.com/repos/x/y/merge","headers":{},"body":""}}`)
	})
	d := driver(t, h, func(c *live.Config) { c.Roles, c.Transport = nil, ct })
	res := run(t, d, `  - {id: merge, do: agent.call, with: {face: sdk, connection: github, tool: merge_pull_request}, expect: {outcome: ALLOW}}
  - {id: replay, do: target.replay, with: {of: merge}, expect: {outcome: ALLOW}}
`)
	if res.Verdict != domain.VerdictError || ct.n != 0 || !strings.Contains(res.Detail, "loopback or private IP literal") {
		t.Fatalf("%+v sent=%d", res, ct.n)
	}
}

func TestAgentChildShowsWhatItWidened(t *testing.T) {
	fw := &fakeWorkload{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterWorkloadServiceHandler(cs, fw)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	wsrv := httptest.NewServer(mux)
	t.Cleanup(wsrv.Close)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"decision":"deny","error_class":"policy_denied","code":"NO_GRANT"}`)
	})
	d := driver(t, h, func(c *live.Config) {
		c.Workload = pantherclawv1connect.NewWorkloadServiceClient(connect.NewClient(connecthttp.NewTransport(wsrv.Client(), wsrv.URL)))
		c.AgentID, c.Roles = "0192aaaa-bbbb-7ccc-8ddd-0000000000a1", nil
	})
	res := run(t, d, `  - id: child
    do: agent.child
    with: {grant: {widen: [operations, lifetime]}, then: {face: sdk, connection: github, tool: t}}
    expect: {outcome: DENY}
`)
	if len(res.Steps) != 1 || !strings.HasPrefix(res.Steps[0].Observed.Detail, "widened operations, lifetime; ") {
		t.Fatalf("%+v", res)
	}
}
