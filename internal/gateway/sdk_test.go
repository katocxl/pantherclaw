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
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/sdk"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const sdkPath = "/sdk/payments"

// withAgentHeld makes the payments connection one whose agent holds its
// own credential and calls the target itself: the SDK face serves it.
func withAgentHeld(h *harness) { h.conn.AccessMode = "agent_held" }

// withTargetEnforced makes it one whose target checks action tokens.
func withTargetEnforced(h *harness) {
	h.conn.AccessMode = "target_enforced"
	h.auth.token = "action-token-jws"
}

// sdkRefund is an SDK's raw call to the payments MCP server's create_refund.
func sdkRefund(amount string) string {
	b, _ := json.Marshal(map[string]any{
		"tool": "mcp__payments__create_refund", "server": "payments", "tool_use_id": "toolu_01",
		"input": map[string]string{"charge": "ch_1", "amount": amount, "currency": "USD", "reason": "duplicate"},
	})
	return string(b)
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

// TestHR201_TheSDKFaceMapsTheRawCallItself: an MCP tool call is mapped by
// the gateway through the package's reviewed MCP mapping into an
// sdk-channel action on the connection in the path, decided over the
// exact bytes the proof covers, committed and recorded DELEGATED, and
// answered allow with the action's id, canonical form and hash, labeled
// PARTIAL; the gateway sends nothing.
func TestHR201_TheSDKFaceMapsTheRawCallItself(t *testing.T) {
	h := setup(t, withAgentHeld)
	action := ids.NewV7().String()
	body := sdkRefund("30.00")
	r := h.sdk(t, body, map[string]string{HeaderActionID: action})
	s := h.auth.snap()
	if r.code != http.StatusOK || r.answer.Decision != "allow" || r.answer.Coverage != sdk.CoveragePartial || r.answer.Mode != "enforce" ||
		r.answer.TransactionID != s.txn || r.answer.Receipt != "receipt-jws" || r.answer.ActionID != action || r.answer.Dispatch != nil ||
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
	if a := s.actions[0].Action; a.Channel != "sdk" || a.Operation != "payments.refund.create" || a.Route != "payments-refund" ||
		a.Connection != connID || a.ActionID != action {
		t.Fatalf("mapped %+v", a)
	}
	if sum := sha256.Sum256([]byte(body)); !bytes.Equal(s.creds.GetBodySha256(), sum[:]) || !strings.HasSuffix(s.creds.GetHtu(), sdkPath) ||
		s.creds.GetHtm() != http.MethodPost {
		t.Fatalf("the Authority verifies the proof over %+v", s.creds)
	}
}

// TestHR201_TargetEnforcedCallsCarryTheGatewaysOwnRequest: on a
// target-enforced connection the gateway re-serializes the outbound
// request from the action it mapped, commits its body hash at
// BeginDispatch so the action token binds exactly those bytes, and returns
// request and token for the SDK to send unchanged; it sends nothing
// itself. Without a token the call is recorded failed, never allowed.
func TestHR201_TargetEnforcedCallsCarryTheGatewaysOwnRequest(t *testing.T) {
	h := setup(t, withTargetEnforced)
	r := h.sdk(t, sdkRefund("30.00"), nil)
	s := h.auth.snap()
	d := r.answer.Dispatch
	if r.answer.Decision != "allow" || d == nil || s.outcome() != pb.Outcome_OUTCOME_DELEGATED || h.target.calls() != 0 || len(s.begins) != 1 {
		t.Fatalf("allowed = %+v, outcome %s, target %d", r.answer, s.outcome(), h.target.calls())
	}
	body, err := base64.RawURLEncoding.DecodeString(d.Body)
	sum := sha256.Sum256(body)
	if err != nil || string(body) != outbound || d.Method != http.MethodPost || d.URL != h.targetURL+"/v1/refunds" ||
		d.ActionToken != "action-token-jws" || d.Headers[dispatch.HeaderAction] != "action-token-jws" || d.Headers["Content-Type"] != "application/json" ||
		d.Headers["Idempotency-Key"] == "" {
		t.Fatalf("dispatch %+v body %q %v", d, body, err)
	}
	b := s.begins[0]
	if b.GetOutboundMethod() != http.MethodPost || b.GetOutboundUrl() != d.URL || !bytes.Equal(b.GetOutboundBodySha256(), sum[:]) {
		t.Fatalf("committed %+v, want the hash of %q", b, body)
	}

	h = setup(t, withTargetEnforced, func(h *harness) { h.auth.token = "" })
	if r := h.sdk(t, sdkRefund("30.00"), nil); r.answer.Decision != "deny" || r.answer.Dispatch != nil ||
		h.auth.snap().outcome() != pb.Outcome_OUTCOME_FAILED {
		t.Fatalf("no token: %+v, outcome %s", r.answer, h.auth.snap().outcome())
	}
}

// TestHR201_TheFaceServesOnlyConnectionsAnSDKReachesItself: the gateway
// holds a pantherclaw_held connection's credential, so the SDK is told to
// use the gateway's face (HR-186), and an open one gets the same answer; a
// local connection (the hook's) is not served. None reaches the Authority.
func TestHR201_TheFaceServesOnlyConnectionsAnSDKReachesItself(t *testing.T) {
	for name, tc := range map[string]struct {
		opt  func(*harness)
		code int
		want string
	}{
		"gateway held": {func(h *harness) { h.conn.AccessMode = "pantherclaw_held" }, http.StatusOK, sdk.CodeUseGatewayFace},
		"open target":  {func(h *harness) { h.conn.AccessMode = "none" }, http.StatusOK, sdk.CodeUseGatewayFace},
		"local":        {func(h *harness) { h.conn.Kind = "local" }, http.StatusNotFound, "unknown_connection"},
	} {
		h := setup(t, tc.opt)
		r := h.sdk(t, sdkRefund("30.00"), nil)
		if r.code != tc.code || r.answer.Decision != "deny" || r.answer.Code != tc.want || h.auth.snap().authorize != 0 {
			t.Errorf("%s: %d %+v", name, r.code, r.answer)
		}
	}
}

// TestHR201_NothingTheSDKComputedIsTrusted: a request that carries an
// ActionIR, a hash or a member the contract does not name is refused, and
// so is an MCP call the reviewed package does not map or whose input does
// not fit it, a tool of another MCP server than the connection's, and a
// name that is neither an MCP tool nor a built-in tool (bash in lowercase
// too): none of them reaches the Authority, and none is allowed.
func TestHR201_NothingTheSDKComputedIsTrusted(t *testing.T) {
	refund := `"input":{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}`
	for name, tc := range map[string]struct {
		body string
		code int
		want string
	}{
		"an action":         {`{"tool":"mcp__payments__create_refund","server":"payments",` + refund + `,"tool_use_id":"t1","action_ir":{"v":1}}`, http.StatusBadRequest, "invalid_request"},
		"a hash":            {`{"tool":"mcp__payments__create_refund","server":"payments",` + refund + `,"tool_use_id":"t1","action_hash":"ab"}`, http.StatusBadRequest, "invalid_request"},
		"a cwd":             {`{"tool":"mcp__payments__create_refund","server":"payments",` + refund + `,"tool_use_id":"t1","cwd":"/x"}`, http.StatusBadRequest, "invalid_request"},
		"unmapped":          {`{"tool":"mcp__payments__delete_everything","server":"payments","input":{},"tool_use_id":"t1"}`, http.StatusOK, sdk.CodeUnknownTool},
		"extra input":       {`{"tool":"mcp__payments__get_refund","server":"payments","input":{"refund":"re_1","x":1},"tool_use_id":"t1"}`, http.StatusOK, sdk.CodeInvalidInput},
		"server mismatch":   {`{"tool":"mcp__payments__get_refund","server":"other","input":{},"tool_use_id":"t1"}`, http.StatusBadRequest, "invalid_request"},
		"no server":         {`{"tool":"mcp__payments__get_refund","input":{},"tool_use_id":"t1"}`, http.StatusBadRequest, "invalid_request"},
		"a server on Read":  {`{"tool":"Read","server":"payments","input":{},"tool_use_id":"t1"}`, http.StatusBadRequest, "invalid_request"},
		"a bad name":        {`{"tool":"rm -rf","input":{},"tool_use_id":"t1"}`, http.StatusBadRequest, "invalid_request"},
		"another server":    {`{"tool":"mcp__evil__get_refund","server":"evil","input":{"refund":"re_1"},"tool_use_id":"t1"}`, http.StatusOK, sdk.CodeUnknownServer},
		"an unknown tool":   {`{"tool":"merge_pr","input":{},"tool_use_id":"t1"}`, http.StatusOK, sdk.CodeUnknownTool},
		"bash in lowercase": {`{"tool":"bash","input":{"command":"ls"},"tool_use_id":"t1"}`, http.StatusOK, sdk.CodeUnknownTool},
		"a bad call id":     {`{"tool":"Read","input":{},"tool_use_id":"toolu 01"}`, http.StatusBadRequest, "invalid_request"},
		"input not object":  {`{"tool":"Read","input":"x","tool_use_id":"t1"}`, http.StatusBadRequest, "invalid_request"},
		"duplicate members": {`{"tool":"Read","tool":"mcp__payments__get_refund","input":{},"tool_use_id":"t1"}`, http.StatusBadRequest, "invalid_request"},
	} {
		h := setup(t, withAgentHeld)
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
// allow with obligations the agent cannot honor, the kill switch and a
// quarantine are deny with the reason; a hold is hold with the Authority's
// wait handle and says to resubmit the same call; none of them is recorded
// or carries a request to send. In monitor mode the call is recorded, not
// prevented.
func TestHR200_TheSDKFaceAllowsOnlyWhatWasRecordedDelegated(t *testing.T) {
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
		h := setup(t, withTargetEnforced, tc.opt)
		r := h.sdk(t, sdkRefund("85.00"), nil)
		s := h.auth.snap()
		if r.code != http.StatusOK || r.answer.Decision != tc.decision || r.answer.Code != tc.code || len(s.records) != 0 ||
			r.answer.Dispatch != nil || r.answer.Coverage != sdk.CoveragePartial || !strings.Contains(r.answer.Reason, "PantherClaw") ||
			r.answer.ActionID == "" {
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
	h := setup(t, withAgentHeld, func(h *harness) { h.auth.decision = pb.Decision_DECISION_REQUIRE_STEP_UP })
	if r := h.sdk(t, sdkRefund("85.00"), nil); r.answer.Decision != "hold" || r.answer.Wait == nil || r.answer.Wait.Handle != r.answer.TransactionID {
		t.Fatalf("step-up hold: %+v", r.answer)
	}

	h = setup(t, withAgentHeld, func(h *harness) {
		h.auth.decision, h.auth.mode = pb.Decision_DECISION_DENY, pb.DispatchMode_DISPATCH_MODE_MONITOR
	})
	if r := h.sdk(t, sdkRefund("85.00"), nil); r.answer.Decision != "allow" || r.answer.Mode != "monitor" ||
		r.answer.Coverage != sdk.CoveragePartial || h.auth.snap().outcome() != pb.Outcome_OUTCOME_DELEGATED {
		t.Fatalf("monitor = %+v", r.answer)
	}
}

// TestHR200_BuiltInToolsAreObservedOnly: a tool the agent SDK has built in
// (Read, or Bash when the application only observes the shell, HR-200) is
// allowed and labeled OBSERVE_ONLY once the Authority verified the
// workload in its run and recorded its name and input digest, without a
// decision; an unverified workload is 401, a connection the Authority does
// not have this gateway serving is denied connection_not_served,
// and an unreachable Authority is no answer to rely on.
func TestHR200_BuiltInToolsAreObservedOnly(t *testing.T) {
	h := setup(t, withAgentHeld)
	run := ids.NewV7().String()
	for _, tool := range []string{"Read", "Bash"} {
		r := h.sdk(t, `{"tool":"`+tool+`","input":{"file_path":"/etc/hosts"},"tool_use_id":"toolu_01"}`, map[string]string{HeaderRunID: run})
		if r.code != http.StatusOK || r.answer.Decision != "allow" || r.answer.Coverage != sdk.CoverageObserveOnly ||
			r.answer.Mode != "monitor" || r.answer.ActionHash != "" {
			t.Fatalf("%s observed = %d %+v", tool, r.code, r.answer)
		}
	}
	h.auth.mu.Lock()
	verified := append([]string(nil), h.auth.verifiedRuns...)
	observed := append([]*pb.RecordToolObservationRequest(nil), h.auth.observed...)
	h.auth.mu.Unlock()
	input := sha256.Sum256([]byte(`{"file_path":"/etc/hosts"}`))
	if h.auth.snap().authorize != 0 || len(verified) != 2 || verified[0] != run || len(observed) != 2 ||
		observed[1].GetTool() != "Bash" || observed[1].GetRunId() != run || observed[1].GetConnectionId() != connID ||
		!bytes.Equal(observed[1].GetInputSha256(), input[:]) {
		t.Fatalf("verified %v, observed %+v", verified, observed)
	}
	h.auth.mu.Lock()
	h.auth.observeCode = sdk.CodeConnectionNotServed
	h.auth.mu.Unlock()
	if r := h.sdk(t, `{"tool":"Read","input":{},"tool_use_id":"toolu_04"}`, map[string]string{HeaderRunID: run}); r.code != http.StatusOK ||
		r.answer.Decision != "deny" || r.answer.Code != sdk.CodeConnectionNotServed || r.hdr.Get(HeaderError) != "" {
		t.Fatalf("connection not served: %d %+v", r.code, r.answer)
	}
	h.auth.setIdentity("invalid_proof")
	if r := h.sdk(t, `{"tool":"Write","input":{},"tool_use_id":"toolu_02"}`, nil); r.code != http.StatusUnauthorized ||
		r.hdr.Get(HeaderError) != "invalid_proof" || r.answer.Decision != "deny" {
		t.Fatalf("unverified: %d %+v", r.code, r.answer)
	}
	h = setup(t, withAgentHeld, func(h *harness) { h.authorityURL = "http://127.0.0.1:1" })
	if r := h.sdk(t, `{"tool":"Read","input":{},"tool_use_id":"toolu_03"}`, nil); r.answer.Decision != "deny" ||
		r.answer.Code != "authority_unavailable" {
		t.Fatalf("Authority down: %+v", r.answer)
	}
}

// TestHR201_TheSDKEndpointRefusesWhatIsNotAnSDKCall: no run, no proof, a
// browser Origin, a malformed or oversized body and a GET are refused
// without asking the Authority to decide.
func TestHR201_TheSDKEndpointRefusesWhatIsNotAnSDKCall(t *testing.T) {
	h := setup(t, withAgentHeld)
	call := sdkRefund("30.00")
	for name, tc := range map[string]struct {
		body string
		hdr  map[string]string
		code int
	}{
		"no run":   {call, map[string]string{HeaderRunID: ""}, http.StatusBadRequest},
		"no proof": {call, map[string]string{HeaderProof: ""}, http.StatusUnauthorized},
		"origin":   {call, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		"not json": {"{", nil, http.StatusBadRequest},
		"too big":  {`{"tool":"Read","input":{"x":"` + strings.Repeat("a", sdk.MaxBody) + `"}}`, nil, http.StatusRequestEntityTooLarge},
	} {
		if r := h.sdk(t, tc.body, tc.hdr); r.code != tc.code || r.answer.Decision != "deny" {
			t.Errorf("%s: %d %+v", name, r.code, r.answer)
		}
	}
	if s := h.auth.snap(); s.authorize != 0 {
		t.Fatalf("a refused request reached the Authority %d times", s.authorize)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, h.url+sdkPath, nil)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
}

// RecordToolObservation verifies as VerifyWorkload does and keeps what a
// verified workload's observation names.
func (f *fakeAuthority) RecordToolObservation(ctx context.Context, req *pb.RecordToolObservationRequest) (*pb.RecordToolObservationResponse, error) {
	v, err := f.VerifyWorkload(ctx, &pb.VerifyWorkloadRequest{Workload: req.GetWorkload(), RunId: req.GetRunId()})
	if err != nil || !v.GetVerified() {
		return &pb.RecordToolObservationResponse{ErrorCode: v.GetErrorCode(), Nonce: v.GetNonce()}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.observeCode != "" {
		return &pb.RecordToolObservationResponse{ErrorCode: f.observeCode, Nonce: v.GetNonce()}, nil
	}
	f.observed = append(f.observed, req)
	return &pb.RecordToolObservationResponse{Verified: true, InstanceId: v.GetInstanceId(), Nonce: v.GetNonce(), ObservationId: ids.NewV7().String()}, nil
}
