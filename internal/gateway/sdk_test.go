// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/sdk"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const sdkPath = "/sdk/payments"

// withAgentPayments makes the connection a kind-local connection serving
// the mock payments package: an agent that calls the payments MCP server
// itself asks through the SDK face (HR-201).
func withAgentPayments(h *harness) {
	h.conn.Kind, h.conn.AccessMode = "local", "none"
}

// sdkCall is an SDK's raw call to a built-in tool.
func sdkCall(tool, cwd, callID string, input any) string {
	m := map[string]any{"tool": tool, "input": input, "tool_use_id": callID}
	if cwd != "" {
		m["cwd"] = cwd
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// sdkMCP is an SDK's raw call to an MCP tool.
func sdkMCP(server, tool string, input any) string {
	b, _ := json.Marshal(map[string]any{"tool": "mcp__" + server + "__" + tool, "server": server, "input": input, "tool_use_id": "toolu_01"})
	return string(b)
}

// shellParams are a pc.shell action's params.
type shellParams struct {
	Shell   string `json:"shell"`
	Command string `json:"command"`
	Cwd     string `json:"cwd"`
	Call    string `json:"call"`
}

type sdkReply struct {
	code   int
	hdr    http.Header
	answer sdk.Answer
}

func (h *harness) sdk(t *testing.T, body string, hdr map[string]string) sdkReply {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, h.url+sdkPath, strings.NewReader(body))
	req.Header.Set("Authorization", "PAP "+testWorkloadToken())
	req.Header.Set(HeaderProof, "proof-not-checked-by-the-gateway")
	req.Header.Set(HeaderRunID, ids.NewV7().String())
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
	r := sdkReply{code: resp.StatusCode, hdr: resp.Header}
	if err := json.Unmarshal(b, &r.answer); err != nil {
		t.Fatalf("answer %d %q: %v", resp.StatusCode, b, err)
	}
	return r
}

// TestHR201_TheSDKFaceMapsTheRawCallItself: a Bash call is mapped by the
// gateway through pc.shell's reviewed mapping into an sdk-channel action
// on the connection, decided over the exact bytes the proof covers,
// committed and recorded DELEGATED, and answered allow with the action's
// id and hash, labeled PARTIAL; nothing reaches any target. PowerShell is
// the other shell, and an MCP tool goes through its package's MCP mapping.
func TestHR201_TheSDKFaceMapsTheRawCallItself(t *testing.T) {
	h := setup(t, withShell)
	action := ids.NewV7().String()
	body := sdkCall("Bash", "/home/dev/proj/./x/..", "toolu_01", map[string]any{
		"command": "go  test ./...", "description": "run the tests", "timeout": 120000, "run_in_background": false,
	})
	r := h.sdk(t, body, map[string]string{HeaderActionID: action})
	s := h.auth.snap()
	if r.code != http.StatusOK || r.answer.Decision != "allow" || r.answer.Coverage != sdk.CoveragePartial || r.answer.Mode != "enforce" ||
		r.answer.TransactionID != s.txn || r.answer.Receipt != "receipt-jws" || r.answer.ActionID != action ||
		len(s.actions) != 1 || r.answer.ActionHash != s.actions[0].HashHex() ||
		len(s.begins) != 1 || s.begins[0].GetOutboundMethod() != "" || s.outcome() != pb.Outcome_OUTCOME_DELEGATED || h.target.calls() != 0 {
		t.Fatalf("allowed = %d %+v, begins %+v, outcome %s, target %d", r.code, r.answer, s.begins, s.outcome(), h.target.calls())
	}
	// The SDK can check the hash: action_ir is the exact canonical action
	// the Authority received.
	ir, err := base64.RawURLEncoding.DecodeString(r.answer.ActionIR)
	if sum := sha256.Sum256(ir); err != nil || !bytes.Equal(ir, s.actions[0].Canonical) || hex.EncodeToString(sum[:]) != r.answer.ActionHash {
		t.Fatalf("action_ir %q: %v", r.answer.ActionIR, err)
	}
	a := s.actions[0].Action
	var p shellParams
	if err := a.DecodeParams(&p); err != nil || a.Channel != "sdk" || a.Operation != "shell.command.run" || a.Route != "shell-command" ||
		a.Connection != connID || a.ActionID != action || p.Shell != "bash" || p.Command != "go  test ./..." || p.Cwd != "/home/dev/proj" ||
		p.Call != "toolu_01" {
		t.Fatalf("mapped %+v params %+v %v", a, p, err)
	}
	if sum := sha256.Sum256([]byte(body)); !bytes.Equal(s.creds.GetBodySha256(), sum[:]) || !strings.HasSuffix(s.creds.GetHtu(), sdkPath) ||
		s.creds.GetHtm() != http.MethodPost {
		t.Fatalf("the Authority verifies the proof over %+v", s.creds)
	}

	h = setup(t, withShell)
	if r := h.sdk(t, sdkCall("PowerShell", `C:\Users\dev\app\`, "toolu_02", map[string]any{"command": "Get-ChildItem"}), nil); r.answer.Decision != "allow" ||
		r.answer.ActionID == "" {
		t.Fatalf("PowerShell: %+v", r.answer)
	}
	var ps shellParams
	if err := h.auth.snap().actions[0].Action.DecodeParams(&ps); err != nil || ps.Shell != "powershell" || ps.Cwd != `C:\Users\dev\app` {
		t.Fatalf("PowerShell params %+v %v", ps, err)
	}

	h = setup(t, withAgentPayments)
	r = h.sdk(t, sdkMCP("pay", "create_refund", map[string]string{"charge": "ch_1", "amount": "30.00", "currency": "USD", "reason": "duplicate"}), nil)
	s = h.auth.snap()
	if r.answer.Decision != "allow" || len(s.actions) != 1 || s.actions[0].Action.Channel != "sdk" ||
		s.actions[0].Action.Operation != "payments.refund.create" || s.actions[0].Action.Route != "payments-refund" ||
		s.outcome() != pb.Outcome_OUTCOME_DELEGATED || h.target.calls() != 0 {
		t.Fatalf("MCP tool: %+v, actions %+v, outcome %s, target %d", r.answer, s.actions, s.outcome(), h.target.calls())
	}
}

// TestHR201_NothingTheSDKComputedIsTrusted: a request that carries an
// ActionIR, a hash or a canonical form is refused, and so is a call the
// reviewed package does not map or whose input does not fit it: none of
// them reaches the Authority, and none is allowed.
func TestHR201_NothingTheSDKComputedIsTrusted(t *testing.T) {
	bash := map[string]any{"command": "ls"}
	for name, tc := range map[string]struct {
		opt  func(*harness)
		body string
		code int
		want string
	}{
		"an action":         {withShell, `{"tool":"Bash","input":{"command":"ls"},"tool_use_id":"t1","cwd":"/x","action_ir":{"v":1}}`, http.StatusBadRequest, "invalid_request"},
		"a hash":            {withShell, `{"tool":"Bash","input":{"command":"ls"},"tool_use_id":"t1","cwd":"/x","action_hash":"ab"}`, http.StatusBadRequest, "invalid_request"},
		"an extra input":    {withShell, sdkCall("Bash", "/x", "t1", map[string]any{"command": "ls", "dangerouslyDisableSandbox": true}), http.StatusOK, sdk.CodeInvalidInput},
		"no command":        {withShell, sdkCall("Bash", "/x", "t1", map[string]any{"description": "x"}), http.StatusOK, sdk.CodeInvalidInput},
		"no cwd":            {withShell, sdkCall("Bash", "", "t1", bash), http.StatusBadRequest, "invalid_request"},
		"a relative cwd":    {withShell, sdkCall("Bash", "proj", "t1", bash), http.StatusOK, sdk.CodeInvalidInput},
		"a device cwd":      {withShell, sdkCall("Bash", `\\.\pipe\x`, "t1", bash), http.StatusOK, sdk.CodeInvalidInput},
		"a bad call id":     {withShell, sdkCall("Bash", "/x", "toolu 01", bash), http.StatusBadRequest, "invalid_request"},
		"shell unmapped":    {withAgentPayments, sdkCall("Bash", "/x", "t1", bash), http.StatusOK, sdk.CodeUnknownTool},
		"mcp unmapped":      {withAgentPayments, sdkMCP("pay", "delete_everything", map[string]any{}), http.StatusOK, sdk.CodeUnknownTool},
		"mcp on the shell":  {withShell, sdkMCP("pay", "create_refund", map[string]any{}), http.StatusOK, sdk.CodeUnknownTool},
		"mcp extra input":   {withAgentPayments, sdkMCP("pay", "get_refund", map[string]any{"refund": "re_1", "x": 1}), http.StatusOK, sdk.CodeInvalidInput},
		"server mismatch":   {withAgentPayments, `{"tool":"mcp__pay__get_refund","server":"other","input":{},"tool_use_id":"t1"}`, http.StatusBadRequest, "invalid_request"},
		"no server":         {withAgentPayments, `{"tool":"mcp__pay__get_refund","input":{},"tool_use_id":"t1"}`, http.StatusBadRequest, "invalid_request"},
		"mcp with a cwd":    {withAgentPayments, `{"tool":"mcp__pay__get_refund","server":"pay","input":{},"tool_use_id":"t1","cwd":"/x"}`, http.StatusBadRequest, "invalid_request"},
		"a server on Bash":  {withShell, `{"tool":"Bash","server":"pay","input":{"command":"ls"},"tool_use_id":"t1","cwd":"/x"}`, http.StatusBadRequest, "invalid_request"},
		"input not object":  {withShell, `{"tool":"Bash","input":"ls","tool_use_id":"t1","cwd":"/x"}`, http.StatusBadRequest, "invalid_request"},
		"duplicate members": {withShell, `{"tool":"Read","tool":"Bash","input":{"command":"ls"},"tool_use_id":"t1","cwd":"/x"}`, http.StatusBadRequest, "invalid_request"},
	} {
		h := setup(t, tc.opt)
		r := h.sdk(t, tc.body, nil)
		if r.code != tc.code || r.answer.Decision != "deny" || r.answer.Code != tc.want || r.answer.ErrorClass != "cannot_authorize" ||
			r.answer.Coverage != sdk.CoveragePartial {
			t.Errorf("%s: %d %+v", name, r.code, r.answer)
		}
		if s := h.auth.snap(); s.authorize != 0 || len(s.begins) != 0 {
			t.Errorf("%s: reached the Authority %d times", name, s.authorize)
		}
	}
}

// TestHR200_TheSDKFaceAllowsOnlyWhatWasRecordedDelegated: a denial, an
// allow with obligations the agent cannot honor and the kill switch are
// deny with the reason; a hold is hold with the Authority's wait handle and
// says to resubmit the same call; none of them is recorded. In monitor
// mode the call is recorded, not prevented.
func TestHR200_TheSDKFaceAllowsOnlyWhatWasRecordedDelegated(t *testing.T) {
	call := sdkCall("Bash", "/home/dev/proj", "toolu_01", map[string]any{"command": "rm -rf build"})
	deadline := time.Date(2026, 10, 11, 13, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		opt      func(*harness)
		decision string
		code     string
	}{
		"denied": {func(h *harness) { h.auth.decision = pb.Decision_DECISION_DENY }, "deny", "GRANT_AMOUNT_EXCEEDED"},
		"held": {func(h *harness) {
			h.auth.decision = pb.Decision_DECISION_REQUIRE_APPROVAL
			h.auth.wait = &pb.WaitInfo{
				Handle: "01920000-0000-7000-8000-0000000000f1", RetryAfterSeconds: 5, DeadlineTime: timestamppb.New(deadline),
				State: pb.WaitState_WAIT_STATE_PENDING, ApprovalRequestId: "01920000-0000-7000-8000-0000000000f2",
			}
		}, "hold", "GRANT_AMOUNT_EXCEEDED"},
		"obligations": {func(h *harness) { h.auth.obligations = []*pb.Obligation{{Kind: "clamp"}} }, "deny", "obligation_unsupported"},
		"kill switch": {func(h *harness) { h.containment.err = control.ErrKillSwitch }, "deny", "kill_switch"},
		"quarantined": {func(h *harness) { h.conn.State = "QUARANTINED" }, "deny", "connection_quarantined"},
	} {
		h := setup(t, withShell, tc.opt)
		r := h.sdk(t, call, nil)
		s := h.auth.snap()
		if r.code != http.StatusOK || r.answer.Decision != tc.decision || r.answer.Code != tc.code || len(s.records) != 0 ||
			r.answer.Coverage != sdk.CoveragePartial || !strings.Contains(r.answer.Reason, "PantherClaw") || r.answer.ActionID == "" {
			t.Errorf("%s: %d %+v, records %d", name, r.code, r.answer, len(s.records))
		}
		if tc.decision == "hold" {
			w := r.answer.Wait
			if w == nil || w.Handle != "01920000-0000-7000-8000-0000000000f1" || w.State != "PENDING" || w.RetryAfterSeconds != 5 ||
				w.Deadline != "2026-10-11T13:00:00Z" || w.ApprovalRequestID != "01920000-0000-7000-8000-0000000000f2" || w.ConsumeBy != "" ||
				!strings.Contains(r.answer.Reason, "same action id") {
				t.Errorf("%s: wait %+v, reason %q", name, w, r.answer.Reason)
			}
		} else if r.answer.Wait != nil {
			t.Errorf("%s: a wait handle %+v", name, r.answer.Wait)
		}
	}

	// A hold without the Authority's wait info still names its handle: the
	// transaction id.
	h := setup(t, withShell, func(h *harness) { h.auth.decision = pb.Decision_DECISION_REQUIRE_STEP_UP })
	if r := h.sdk(t, call, nil); r.answer.Decision != "hold" || r.answer.Wait == nil || r.answer.Wait.Handle != r.answer.TransactionID {
		t.Fatalf("step-up hold: %+v", r.answer)
	}

	h = setup(t, withShell, func(h *harness) {
		h.auth.decision, h.auth.mode = pb.Decision_DECISION_DENY, pb.DispatchMode_DISPATCH_MODE_MONITOR
	})
	if r := h.sdk(t, call, nil); r.answer.Decision != "allow" || r.answer.Mode != "monitor" || r.answer.Coverage != sdk.CoveragePartial ||
		h.auth.snap().outcome() != pb.Outcome_OUTCOME_DELEGATED {
		t.Fatalf("monitor = %+v", r.answer)
	}
}

// TestHR200_UnmappedBuiltInToolsAreObservedOnly: a built-in tool without a
// mapping is allowed and labeled OBSERVE_ONLY once the Authority verified
// the workload in its run, without a decision; an unverified workload is
// 401, and an unreachable Authority is no answer to rely on.
func TestHR200_UnmappedBuiltInToolsAreObservedOnly(t *testing.T) {
	h := setup(t, withShell)
	run := ids.NewV7().String()
	r := h.sdk(t, `{"tool":"Read","input":{"file_path":"/etc/hosts"},"tool_use_id":"toolu_01"}`, map[string]string{HeaderRunID: run})
	h.auth.mu.Lock()
	verified := append([]string(nil), h.auth.verifiedRuns...)
	h.auth.mu.Unlock()
	if r.code != http.StatusOK || r.answer.Decision != "allow" || r.answer.Coverage != sdk.CoverageObserveOnly || r.answer.Mode != "monitor" ||
		h.auth.snap().authorize != 0 || len(verified) != 1 || verified[0] != run {
		t.Fatalf("observed = %d %+v, verified %v", r.code, r.answer, verified)
	}
	h.auth.setIdentity("invalid_proof")
	if r := h.sdk(t, `{"tool":"Write","input":{},"tool_use_id":"toolu_02"}`, nil); r.code != http.StatusUnauthorized ||
		r.hdr.Get(HeaderError) != "invalid_proof" || r.answer.Decision != "deny" {
		t.Fatalf("unverified: %d %+v", r.code, r.answer)
	}
	h = setup(t, withShell, func(h *harness) { h.authorityURL = "http://127.0.0.1:1" })
	if r := h.sdk(t, `{"tool":"Read","input":{},"tool_use_id":"toolu_03"}`, nil); r.answer.Decision != "deny" ||
		r.answer.Code != "authority_unavailable" {
		t.Fatalf("Authority down: %+v", r.answer)
	}
}

// TestHR201_TheSDKEndpointRefusesWhatIsNotAnSDKCall: no run, no proof, a
// browser Origin, a malformed body, a GET and a connection that is not
// local are refused without asking the Authority to decide.
func TestHR201_TheSDKEndpointRefusesWhatIsNotAnSDKCall(t *testing.T) {
	h := setup(t, withShell)
	call := sdkCall("Bash", "/x", "t1", map[string]any{"command": "ls"})
	for name, tc := range map[string]struct {
		body string
		hdr  map[string]string
		code int
	}{
		"no run":   {call, map[string]string{HeaderRunID: ""}, http.StatusBadRequest},
		"no proof": {call, map[string]string{HeaderProof: ""}, http.StatusUnauthorized},
		"origin":   {call, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		"not json": {"{", nil, http.StatusBadRequest},
		"too big":  {`{"tool":"Bash","input":{"command":"` + strings.Repeat("a", sdk.MaxBody) + `"}}`, nil, http.StatusRequestEntityTooLarge},
	} {
		if r := h.sdk(t, tc.body, tc.hdr); r.code != tc.code || r.answer.Decision != "deny" {
			t.Errorf("%s: %d %+v", name, r.code, r.answer)
		}
	}
	if s := h.auth.snap(); s.authorize != 0 {
		t.Fatalf("a refused request reached the Authority %d times", s.authorize)
	}
	payments := setup(t) // a kind-http connection
	client := &http.Client{Timeout: 5 * time.Second}
	for _, req := range []*http.Request{
		mustRequest(t, http.MethodPost, payments.url+sdkPath, call),
		mustRequest(t, http.MethodGet, h.url+sdkPath, ""),
	} {
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if want := map[string]int{http.MethodPost: http.StatusNotFound, http.MethodGet: http.StatusMethodNotAllowed}[req.Method]; resp.StatusCode != want {
			t.Errorf("%s %s: %d", req.Method, req.URL, resp.StatusCode)
		}
	}
}

func mustRequest(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return req
}
