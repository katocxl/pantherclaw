// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	runtimeface "github.com/katocxl/pantherclaw/internal/gateway/runtime"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	agentcoresim "github.com/katocxl/pantherclaw/internal/sim/agentcore"
)

// The AgentCore face (G0 M34 D994, HR-760, HR-764, HR-765; T-345, T-346).

const (
	rtGatewayARN = "arn:aws:bedrock-agentcore:us-east-1:111122223333:gateway/payments-gw-1"
	rtTarget     = "payments-target"
	rtTool       = rtTarget + "___create_refund"
	rtArgs       = `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`
)

// withRuntime makes the connection a kind-mcp, agent-held connection bound
// to the AgentCore target rtTarget of rtGatewayARN (D991).
func withRuntime(h *harness) {
	h.conn.Kind, h.conn.AccessMode = "mcp", "agent_held"
	h.conn.RuntimeTarget = runtimeface.TargetPrefix + rtGatewayARN + "/" + rtTarget
}

// rtRPC is a JSON-RPC request of an interceptor event.
func rtRPC(method, params string) string {
	if params == "" {
		return `{"jsonrpc":"2.0","id":11,"method":"` + method + `"}`
	}
	return `{"jsonrpc":"2.0","id":11,"method":"` + method + `","params":` + params + `}`
}

// rtCall is a tools/call of name with arguments.
func rtCall(name, args string) string {
	return rtRPC("tools/call", `{"name":"`+name+`","arguments":`+args+`}`)
}

// rtEvent is an AgentCore MCP request interceptor event carrying rpc.
func rtEvent(rpc string) string {
	raw, _ := json.Marshal(rpc)
	return `{"interceptorInputVersion":"1.0","mcp":{"rawGatewayRequest":{"body":` + string(raw) +
		`},"gatewayRequest":{"path":"/mcp","httpMethod":"POST","body":` + rpc + `}}}`
}

type rtOutput struct {
	Version string `json:"interceptorOutputVersion"`
	MCP     struct {
		Request *struct {
			Body jsontext.Value `json:"body"`
		} `json:"transformedGatewayRequest"`
		Response *struct {
			StatusCode int `json:"statusCode"`
			Body       struct {
				ID     jsontext.Value `json:"id"`
				Result *struct {
					IsError bool `json:"isError"`
					Content []struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"content"`
				} `json:"result"`
				Error *struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			} `json:"body"`
		} `json:"transformedGatewayResponse"`
	} `json:"mcp"`
}

type rtReply struct {
	code int
	hdr  http.Header
	raw  []byte
	out  rtOutput
	// refusal is a pre-answer refusal (D994b).
	refusal struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
}

// passed reports whether the answer lets the original request through.
func (r rtReply) passed(rpc string) bool {
	return r.code == http.StatusOK && r.out.Version == "1.0" && r.out.MCP.Request != nil && r.out.MCP.Response == nil &&
		string(r.out.MCP.Request.Body) == rpc
}

// toolError is the text of a tool error answer, or "".
func (r rtReply) toolError() string {
	if r.code != http.StatusOK || r.out.MCP.Request != nil || r.out.MCP.Response == nil || r.out.MCP.Response.StatusCode != http.StatusOK {
		return ""
	}
	res := r.out.MCP.Response.Body.Result
	if res == nil || !res.IsError || len(res.Content) != 1 || res.Content[0].Type != "text" {
		return ""
	}
	return res.Content[0].Text
}

func (h *harness) runtime(t *testing.T, method, body string, hdr map[string]string) rtReply {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), method, h.url+runtimeface.AgentCorePath, strings.NewReader(body))
	req.Header.Set("Authorization", "PAP "+testWorkloadToken())
	req.Header.Set(HeaderProof, "proof-not-checked-by-the-gateway")
	req.Header.Set(HeaderRunID, ids.NewV7().String())
	req.Header.Set(runtimeface.HeaderGateway, rtGatewayARN)
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	r := rtReply{code: resp.StatusCode, hdr: resp.Header, raw: b}
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(b, &r.out); err != nil {
			t.Fatalf("answer %q: %v", b, err)
		}
	} else if err := json.Unmarshal(b, &r.refusal); err != nil {
		t.Fatalf("refusal %d %q: %v", resp.StatusCode, b, err)
	}
	return r
}

// TestHR760_RuntimeActionsAreDelegatedAndNeverForwarded: an allowed
// tools/call on channel runtime is committed with BeginDispatch (no
// outbound request), recorded DELEGATED and answered with the original
// request, and nothing reaches the connection's upstream. The action's
// channel is runtime, mapped through the package's MCP mapping. A decision
// with obligations is refused: the runtime's gateway can honor none.
func TestHR760_RuntimeActionsAreDelegatedAndNeverForwarded(t *testing.T) {
	h := setup(t, withRuntime)
	call := rtCall(rtTool, rtArgs)
	r := h.runtime(t, http.MethodPost, rtEvent(call), nil)
	s := h.auth.snap()
	if !r.passed(call) || len(s.begins) != 1 || s.begins[0].GetOutboundMethod() != "" || len(s.begins[0].GetOutboundBodySha256()) != 0 ||
		s.outcome() != pb.Outcome_OUTCOME_DELEGATED || h.target.calls() != 0 {
		t.Fatalf("allowed = %d %s, begins %+v, outcome %s, target %d", r.code, r.raw, s.begins, s.outcome(), h.target.calls())
	}
	if a := s.actions[0].Action; a.Channel != "runtime" || a.Route != "payments-refund" || a.Connection != connID {
		t.Fatalf("mapped %+v", a)
	}

	h = setup(t, withRuntime, func(h *harness) { h.auth.obligations = []*pb.Obligation{{Kind: "clamp"}} })
	r = h.runtime(t, http.MethodPost, rtEvent(call), nil)
	if txt := r.toolError(); !strings.Contains(txt, "obligation_unsupported") || len(h.auth.snap().records) != 0 || h.target.calls() != 0 {
		t.Fatalf("obligations = %s, records %d", r.raw, len(h.auth.snap().records))
	}
}

// TestHR764_TheAgentCoreFaceDecidesToolsCallsOnly: tools/call is decided;
// initialize, ping, tools/list and notifications/* pass undecided; any
// other method is a JSON-RPC -32601 (RUNTIME_METHOD_NOT_DECIDED); a deny
// and a hold answer with a tool error (the hold names where to approve);
// an HTTP target's event, another HTTP method, an Origin, a body over
// 1 MiB, a missing proof or token, no run, and a header that is no
// AgentCore gateway ARN are refused before any decision.
func TestHR764_TheAgentCoreFaceDecidesToolsCallsOnly(t *testing.T) {
	h := setup(t, withRuntime)
	for _, rpc := range []string{
		rtRPC("initialize", `{"protocolVersion":"2025-06-18"}`), rtRPC("ping", ""), rtRPC("tools/list", ""),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	} {
		if r := h.runtime(t, http.MethodPost, rtEvent(rpc), nil); !r.passed(rpc) {
			t.Errorf("%s: %d %s", rpc, r.code, r.raw)
		}
	}
	r := h.runtime(t, http.MethodPost, rtEvent(rtRPC("resources/read", `{"uri":"file:///etc/passwd"}`)), nil)
	if e := r.out.MCP.Response; r.code != 200 || e == nil || e.Body.Error == nil || e.Body.Error.Code != -32601 ||
		!strings.Contains(e.Body.Error.Message, runtimeface.CodeMethodNotDecided) || string(e.Body.ID) != "11" {
		t.Errorf("resources/read = %d %s", r.code, r.raw)
	}
	if n := h.auth.snap().authorize; n != 0 {
		t.Fatalf("undecided methods asked the Authority %d times", n)
	}

	for name, tc := range map[string]struct {
		decision pb.Decision
		want     string
	}{
		"denied": {pb.Decision_DECISION_DENY, "GRANT_AMOUNT_EXCEEDED"},
		"held":   {pb.Decision_DECISION_REQUIRE_APPROVAL, runtimeface.HeldText},
	} {
		h := setup(t, withRuntime, func(h *harness) { h.auth.decision = tc.decision })
		r := h.runtime(t, http.MethodPost, rtEvent(rtCall(rtTool, rtArgs)), nil)
		txt := r.toolError()
		s := h.auth.snap()
		if !strings.Contains(txt, tc.want) || !strings.Contains(txt, s.txn) || len(s.records) != 0 || len(s.begins) != 0 || h.target.calls() != 0 {
			t.Errorf("%s: %s, records %d, begins %d", name, r.raw, len(s.records), len(s.begins))
		}
	}

	big := rtEvent(rtCall(rtTool, `{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"`+strings.Repeat("x", runtimeface.MaxBody)+`"}`))
	for name, tc := range map[string]struct {
		method, body string
		hdr          map[string]string
		status       int
		code         string
	}{
		"http event": {http.MethodPost, `{"interceptorInputVersion":"1.0","http":{"body":"e30="}}`, nil, 422, runtimeface.CodeHTTPNotSupported},
		"GET":        {http.MethodGet, "", nil, 405, "method_not_allowed"},
		"Origin":     {http.MethodPost, rtEvent(rtCall(rtTool, rtArgs)), map[string]string{"Origin": "https://evil.example"}, 403, "origin_not_allowed"},
		"too large":  {http.MethodPost, big, nil, 413, "request_too_large"},
		"no proof":   {http.MethodPost, rtEvent(rtCall(rtTool, rtArgs)), map[string]string{HeaderProof: ""}, 401, "use_nonce"},
		"no token":   {http.MethodPost, rtEvent(rtCall(rtTool, rtArgs)), map[string]string{"Authorization": ""}, 401, ""},
		"no run":     {http.MethodPost, rtEvent(rtCall(rtTool, rtArgs)), map[string]string{HeaderRunID: ""}, 400, "run_required"},
		"not an ARN": {http.MethodPost, rtEvent(rtCall(rtTool, rtArgs)), map[string]string{runtimeface.HeaderGateway: "payments-gw-1"}, 400, runtimeface.CodeGatewayARNInvalid},
		"not JSON":   {http.MethodPost, `{"mcp":`, nil, 400, runtimeface.CodeEventInvalid},
	} {
		h := setup(t, withRuntime)
		r := h.runtime(t, tc.method, tc.body, tc.hdr)
		if r.code != tc.status || (tc.code != "" && r.refusal.Code != tc.code) || h.auth.snap().authorize != 0 || h.target.calls() != 0 {
			t.Errorf("%s: %d %s, authorize %d", name, r.code, r.raw, h.auth.snap().authorize)
		}
	}
}

// TestHR764_UndecidedRuntimeMethodsVerifyTheWorkload ensures a forged proof
// cannot pass through an otherwise undecided method.
func TestHR764_UndecidedRuntimeMethodsVerifyTheWorkload(t *testing.T) {
	cases := map[string]string{
		"initialize": rtRPC("initialize", ""), "ping": rtRPC("ping", ""), "tools/list": rtRPC("tools/list", ""),
		"notification": rtRPC("notifications/initialized", ""), "unsupported": rtRPC("resources/read", ""),
		"bad params": rtRPC("tools/call", ""), "bad target": rtCall("bad", `{}`),
		"unbound target": rtCall("other___tool", `{}`), "unmapped tool": rtCall(rtTarget+"___unknown", `{}`),
	}
	for name, rpc := range cases {
		t.Run(name, func(t *testing.T) {
			h := setup(t, withRuntime, func(h *harness) { h.auth.identity = "invalid_proof" })
			r := h.runtime(t, http.MethodPost, rtEvent(rpc), nil)
			if r.code != http.StatusUnauthorized || r.hdr.Get(dispatch.HeaderError) != "invalid_proof" || h.auth.verifies != 1 {
				t.Fatalf("%s: status %d, error %q, verifications %d", name, r.code, r.hdr.Get(dispatch.HeaderError), h.auth.verifies)
			}
		})
	}
	h := setup(t, withRuntime, func(h *harness) { h.auth.identity = "run_mismatch" })
	r := h.runtime(t, http.MethodPost, rtEvent(rtRPC("ping", "")), nil)
	if r.code != http.StatusUnauthorized || r.hdr.Get(runtimeface.HeaderRunEnded) != "1" {
		t.Fatalf("ended run: %d, header %q", r.code, r.hdr.Get(runtimeface.HeaderRunEnded))
	}
}

// TestHR765_TheFaceDecidesThroughTheOneBoundTarget: the tool name splits on
// its first "___", so a tool whose own name has "___" stays whole; the
// connection is the one bound to "agentcore:<header ARN>/<target>"; the
// Authority's agent-safe account refusal (D994a) is shown as is, and a run
// that ended sets PC-Run-Ended (D994b).
func TestHR765_TheFaceDecidesThroughTheOneBoundTarget(t *testing.T) {
	h := setup(t, withRuntime)
	if r := h.runtime(t, http.MethodPost, rtEvent(rtCall(rtTool, rtArgs)), nil); !r.passed(rtCall(rtTool, rtArgs)) {
		t.Fatalf("bound = %s", r.raw)
	}
	r := h.runtime(t, http.MethodPost, rtEvent(rtCall(rtTool+"___x", rtArgs)), nil)
	if txt := r.toolError(); !strings.Contains(txt, "does not map create_refund___x") {
		t.Errorf("first-split tool = %s", r.raw)
	}

	const detail = "PantherClaw refuses this tool call: the AgentCore gateway's AWS account does not match the account its interceptor proved."
	h = setup(t, withRuntime, func(h *harness) {
		h.auth.decision = pb.Decision_DECISION_CANNOT_AUTHORIZE
		h.auth.reasons = []*pb.Reason{{Code: "RUNTIME_ACCOUNT_MISMATCH", Check: "scope", Decisive: true, Detail: detail}}
	})
	r = h.runtime(t, http.MethodPost, rtEvent(rtCall(rtTool, rtArgs)), nil)
	if txt := r.toolError(); !strings.HasPrefix(txt, detail) || len(h.auth.snap().begins) != 0 {
		t.Errorf("account mismatch = %s", r.raw)
	}

	h = setup(t, withRuntime, func(h *harness) {
		h.auth.decision = pb.Decision_DECISION_CANNOT_AUTHORIZE
		h.auth.reasons = []*pb.Reason{{Code: "RUN_NOT_ACTIVE", Check: "run", Decisive: true, Detail: "the run ended"}}
	})
	r = h.runtime(t, http.MethodPost, rtEvent(rtCall(rtTool, rtArgs)), nil)
	if r.toolError() == "" || r.hdr.Get(runtimeface.HeaderRunEnded) != "1" || strings.Contains(r.toolError(), "the run ended") {
		t.Errorf("run ended = %s %v", r.raw, r.hdr)
	}
}

// TestT346_AForgedGatewayARNDecidesNothing: a header that names another
// gateway, a tool whose target no connection is bound to, a name without
// a target, a connection that is not kind mcp, and two connections bound to
// one target are each RUNTIME_TARGET_UNKNOWN, before any decision.
func TestT346_AForgedGatewayARNDecidesNothing(t *testing.T) {
	other := "arn:aws:bedrock-agentcore:us-east-1:444455556666:gateway/payments-gw-1"
	for name, tc := range map[string]struct {
		opt  func(*harness)
		tool string
		hdr  map[string]string
	}{
		"other gateway":  {nil, rtTool, map[string]string{runtimeface.HeaderGateway: other}},
		"unbound target": {nil, "other-target___create_refund", nil},
		"no target":      {nil, "create_refund", nil},
		"empty tool":     {nil, rtTarget + "___", nil},
		"not mcp":        {func(h *harness) { h.conn.Kind = "http" }, rtTool, nil},
		"two bound": {func(h *harness) {
			c, err := compile(t, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			c.GatewayConnection = &pb.GatewayConnection{
				Id: "01920000-0000-7000-8000-0000000000d2", Name: "payments-2", Kind: "mcp", Package: "pc.mock-payments", PackageVersion: "1.0.0",
				AccessMode: "agent_held", DefaultMode: "enforce", State: "ACTIVE", Revision: 1, RuntimeTarget: h.conn.RuntimeTarget,
			}
			c.Modes = map[string]string{}
			h.extra = []*control.Connection{c}
		}, rtTool, nil},
	} {
		opts := []func(*harness){withRuntime}
		if tc.opt != nil {
			opts = append(opts, tc.opt)
		}
		h := setup(t, opts...)
		r := h.runtime(t, http.MethodPost, rtEvent(rtCall(tc.tool, rtArgs)), tc.hdr)
		if txt := r.toolError(); !strings.HasPrefix(txt, runtimeface.CodeTargetUnknown) || h.auth.snap().authorize != 0 || h.target.calls() != 0 {
			t.Errorf("%s: %s, authorize %d", name, r.raw, h.auth.snap().authorize)
		}
	}
}

// TestT345_ARuntimeActionIsNeverForwarded: whatever the connection's kind,
// an action on channel runtime is only committed and recorded DELEGATED:
// the engine sends nothing upstream, even on an http connection whose
// template could reach the target (HR-760). A gateway without the face
// therefore cannot be made to forward one.
func TestT345_ARuntimeActionIsNeverForwarded(t *testing.T) {
	h := setup(t) // the default http connection, its target reachable
	ctx := context.Background()
	a, err := h.conn.Mapper.Runtime(ctx, mappingContext(), "create_refund", []byte(rtArgs))
	if err != nil {
		t.Fatal(err)
	}
	creds := &pb.WorkloadCredentials{
		WorkloadToken: testWorkloadToken(), Proof: "proof-not-checked-by-the-gateway", BodySha256: make([]byte, 32), Htm: http.MethodPost,
		Htu: h.url + runtimeface.AgentCorePath,
	}
	res := h.gw.engine.Dispatch(ctx, dispatch.Call{Connection: h.conn, Action: a, Workload: creds})
	s := h.auth.snap()
	if res.Class != "" || res.Outcome != pb.Outcome_OUTCOME_DELEGATED || h.target.calls() != 0 || len(s.begins) != 1 ||
		s.begins[0].GetOutboundMethod() != "" || s.outcome() != pb.Outcome_OUTCOME_DELEGATED {
		t.Fatalf("runtime on http: class %q code %q reasons %v outcome %s, target %d, begins %+v", res.Class, res.Code, res.Reasons, res.Outcome, h.target.calls(), s.begins)
	}
	// The same call on the http channel is forwarded: the fixture is live.
	m, err := h.conn.Mapper.MCP(ctx, mappingContext(), "create_refund", []byte(rtArgs))
	if err != nil {
		t.Fatal(err)
	}
	if res := h.gw.engine.Dispatch(ctx, dispatch.Call{Connection: h.conn, Action: m, Workload: creds}); res.Class != "" || h.target.calls() != 1 {
		t.Fatalf("mcp on http: class %q, target %d", res.Class, h.target.calls())
	}
}

func mappingContext() mapping.Context {
	return mapping.Context{Org: testOrg, Env: testEnv, RunID: ids.NewV7().String(), ActionID: ids.NewV7().String(), AgentInstance: testAgent, Connection: connID}
}

// TestHR764_TheSimulatorsEventIsDecided: the AgentCore simulator's event
// (internal/sim/agentcore, D998) is the shape the face reads: its tools/call
// for the simulated gateway's target is decided and passes.
func TestHR764_TheSimulatorsEventIsDecided(t *testing.T) {
	h := setup(t, withRuntime, func(h *harness) {
		h.conn.RuntimeTarget = runtimeface.TargetPrefix + agentcoresim.GatewayARN + "/" + agentcoresim.Target
	})
	ev, err := agentcoresim.Event(agentcoresim.Target+"___create_refund", map[string]any{
		"charge": "ch_1", "amount": "30.00", "currency": "USD", "reason": "duplicate",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := h.runtime(t, http.MethodPost, string(ev), map[string]string{runtimeface.HeaderGateway: agentcoresim.GatewayARN})
	if r.code != http.StatusOK || r.out.MCP.Request == nil || h.auth.snap().outcome() != pb.Outcome_OUTCOME_DELEGATED {
		t.Fatalf("simulator event = %d %s", r.code, r.raw)
	}
}
