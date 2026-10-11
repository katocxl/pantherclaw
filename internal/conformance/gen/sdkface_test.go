// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gen_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// The /sdk face contract (HR-200, HR-201) between the SDKs (track S) and
// the gateway's face (track C, internal/gateway/sdk): how an agent's tool
// call becomes a request, what an SDK concludes from each answer, and the
// server exchanges it renews its token and waits with.

// FaceCall is how an Agent SDK tool call becomes a /sdk request.
type FaceCall struct {
	Name string `json:"name"`
	// Tool, Input, ToolUseID and Cwd are the call as the agent made it.
	Tool      string         `json:"tool"`
	Input     jsontext.Value `json:"input"`
	ToolUseID string         `json:"tool_use_id"`
	Cwd       string         `json:"cwd,omitzero"`
	// Path and Body are the request (credentials aside: see proofs.json),
	// or Class says why there is none: "builtin" (an unmapped built-in,
	// still sent so PantherClaw records it), or "refused" (a name the SDK
	// cannot route: a deny, never sent).
	Path  string         `json:"path,omitzero"`
	Body  jsontext.Value `json:"body,omitzero"`
	Class string         `json:"class"`
}

// FaceAnswer is one gateway answer and the outcome an SDK reaches.
type FaceAnswer struct {
	Name    string            `json:"name"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitzero"`
	Body    string            `json:"body"`
	// ActionID is the PC-Action-Id the SDK sent; FirstHash, when set, the
	// action hash of the first answer for that action.
	ActionID  string `json:"action_id"`
	FirstHash string `json:"first_hash,omitzero"`
	// Outcome: allow, observe, hold, deny, cannot_decide, retry_nonce or
	// refresh_token.
	Outcome string `json:"outcome"`
}

// FaceExchange is one exchange with the PantherClaw server: token issuance
// or a long-poll wait (Connect JSON), or the SSE wait stream.
type FaceExchange struct {
	Name    string            `json:"name"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Request jsontext.Value    `json:"request,omitzero"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitzero"`
	Body    string            `json:"body"`
	// What the SDK reads: a token and its expiry, the wait states in
	// order, and what to do next (token, retry_nonce, wait, resubmit,
	// deny).
	Token     string   `json:"token,omitzero"`
	ExpiresAt int64    `json:"expires_at,omitzero"`
	States    []string `json:"states,omitzero"`
	Outcome   string   `json:"outcome"`
}

// FaceFile is sdk_face.json.
type FaceFile struct {
	header
	Gateway string `json:"gateway"`
	Server  string `json:"server"`
	// Connection is the local connection the calls go through; Servers the
	// MCP servers the agent is configured with.
	Connection string         `json:"connection"`
	Servers    []string       `json:"servers"`
	Calls      []FaceCall     `json:"calls"`
	Answers    []FaceAnswer   `json:"answers"`
	Exchanges  []FaceExchange `json:"exchanges"`
}

// faceAnswer is the gateway's answer (internal/gateway/sdk Answer), with
// the canonical action the SDK checks the hash against.
type faceAnswer struct {
	Decision      string    `json:"decision"`
	Reason        string    `json:"reason"`
	ErrorClass    string    `json:"error_class,omitzero"`
	Code          string    `json:"code,omitzero"`
	Reasons       []string  `json:"reasons,omitzero"`
	ActionID      string    `json:"action_id,omitzero"`
	ActionHash    string    `json:"action_hash,omitzero"`
	ActionIR      string    `json:"action_ir,omitzero"`
	TransactionID string    `json:"transaction_id,omitzero"`
	Mode          string    `json:"mode"`
	Coverage      string    `json:"coverage"`
	Wait          *faceWait `json:"wait,omitzero"`
}

type faceWait struct {
	Handle            string `json:"handle"`
	State             string `json:"state,omitzero"`
	RetryAfterSeconds int32  `json:"retry_after_seconds,omitzero"`
	Deadline          string `json:"deadline,omitzero"`
	ApprovalRequestID string `json:"approval_request_id,omitzero"`
	Code              string `json:"code,omitzero"`
}

const txnID = "01920000-0000-7000-8000-000000000009"

func buildFace(t *testing.T) any {
	t.Helper()
	act := sdkAction(t)
	refund := `{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"}`
	f := FaceFile{
		header: head("sdk_face", "the /sdk/{connection} face of tracks S and C (internal/gateway/sdk; G0 M8, HR-200, HR-201), "+
			"internal/actionir for hashes and internal/gen protojson for the server exchanges",
			"How an SDK sends an agent's tool call to the gateway's /sdk face, what it concludes from each answer (only "+
				"allow, and observe for an unmapped built-in tool, let the call run), and how it renews its token and "+
				"waits at the server."),
		Gateway: gatewayURL, Server: issuer, Connection: "local", Servers: []string{"payments", "git__hub"},
	}
	call := func(name, tool, input, id, cwd, class, body string) FaceCall {
		c := FaceCall{Name: name, Tool: tool, Input: jsontext.Value(input), ToolUseID: id, Cwd: cwd, Class: class}
		if body != "" {
			c.Path, c.Body = "/sdk/local", jsontext.Value(body)
		}
		return c
	}
	f.Calls = []FaceCall{
		call("an MCP tool", "mcp__payments__create_refund", refund, "toolu_01", "", "mapped",
			`{"tool":"mcp__payments__create_refund","server":"payments","input":`+refund+`,"tool_use_id":"toolu_01"}`),
		call("an MCP server whose name has a double underscore", "mcp__git__hub__merge_pull_request", `{"pull_number":"7"}`, "toolu_02", "", "mapped",
			`{"tool":"mcp__git__hub__merge_pull_request","server":"git__hub","input":{"pull_number":"7"},"tool_use_id":"toolu_02"}`),
		call("a shell tool", "Bash", `{"command":"go test ./...","description":"Run the tests"}`, "toolu_03", "/home/dev/repo", "mapped",
			`{"tool":"Bash","input":{"command":"go test ./...","description":"Run the tests"},"tool_use_id":"toolu_03","cwd":"/home/dev/repo"}`),
		call("PowerShell", "PowerShell", `{"command":"Get-ChildItem"}`, "toolu_04", `C:\Users\dev\repo`, "mapped",
			`{"tool":"PowerShell","input":{"command":"Get-ChildItem"},"tool_use_id":"toolu_04","cwd":"C:\\Users\\dev\\repo"}`),
		call("a built-in tool", "Read", `{"file_path":"/etc/hosts"}`, "toolu_05", "", "builtin",
			`{"tool":"Read","input":{"file_path":"/etc/hosts"},"tool_use_id":"toolu_05"}`),
		call("an MCP server the agent is not configured with", "mcp__other__run", `{}`, "toolu_06", "", "refused", ""),
		call("an MCP name without a tool", "mcp__payments__", `{}`, "toolu_07", "", "refused", ""),
	}
	hash, ir := act.HashHex(), b64(act.Canonical)
	base := faceAnswer{
		ActionID: actionID, ActionHash: hash, ActionIR: ir, TransactionID: txnID, Mode: "enforce", Coverage: "PARTIAL",
	}
	held := &faceWait{
		Handle: txnID, State: "PENDING", RetryAfterSeconds: 5, Deadline: issuedAt.Add(time.Hour).Format(time.RFC3339),
		ApprovalRequestID: "01920000-0000-7000-8000-00000000000a",
	}
	answer := func(name, outcome string, edit func(*faceAnswer)) FaceAnswer {
		a := base
		edit(&a)
		b, err := json.Marshal(a, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		return FaceAnswer{Name: name, Status: http.StatusOK, Body: string(b), ActionID: actionID, Outcome: outcome}
	}
	other := b64([]byte(strings.Replace(string(act.Canonical), `"ch_1"`, `"ch_2"`, 1)))
	f.Answers = []FaceAnswer{
		answer("allowed and recorded as delegated", "allow", func(a *faceAnswer) { a.Decision, a.Reason = "allow", "PantherClaw allowed this call." }),
		answer("allowed without the action", "allow", func(a *faceAnswer) { a.Decision, a.ActionIR = "allow", "" }),
		answer("monitor mode: recorded, not decided", "allow", func(a *faceAnswer) { a.Decision, a.Mode = "allow", "monitor" }),
		answer("held for an approval", "hold", func(a *faceAnswer) { a.Decision, a.Wait, a.ErrorClass = "hold", held, "HELD" }),
		answer("denied", "deny", func(a *faceAnswer) {
			a.Decision, a.ErrorClass, a.Code, a.Reasons = "deny", "DENIED", "GRANT_AMOUNT_EXCEEDED", []string{"GRANT_AMOUNT_EXCEEDED"}
		}),
		answer("a tool the package does not map", "deny", func(a *faceAnswer) {
			a.Decision, a.ErrorClass, a.Code, a.ActionHash, a.ActionIR, a.TransactionID = "deny", "CANNOT_AUTHORIZE", "unknown_tool", "", "", ""
		}),
		answer("an unmapped built-in tool is observed", "observe", func(a *faceAnswer) {
			*a = faceAnswer{Decision: "allow", Mode: "monitor", Coverage: "OBSERVE_ONLY", Reason: "PantherClaw does not map the Read tool."}
		}),
		answer("an allow whose action does not hash to its hash", "cannot_decide", func(a *faceAnswer) { a.Decision, a.ActionIR = "allow", other }),
		answer("an allow for another action id", "cannot_decide", func(a *faceAnswer) {
			a.Decision, a.ActionID = "allow", "01920000-0000-7000-8000-00000000000b"
		}),
		answer("an allow without an action hash", "cannot_decide", func(a *faceAnswer) { a.Decision, a.ActionHash, a.ActionIR = "allow", "", "" }),
		answer("an allow that is not labeled", "cannot_decide", func(a *faceAnswer) { a.Decision, a.Coverage = "allow", "" }),
		answer("an observed call that is not monitored", "cannot_decide", func(a *faceAnswer) {
			*a = faceAnswer{Decision: "allow", Mode: "enforce", Coverage: "OBSERVE_ONLY"}
		}),
		answer("a hold without a wait handle", "cannot_decide", func(a *faceAnswer) { a.Decision = "hold" }),
		answer("an unknown decision", "cannot_decide", func(a *faceAnswer) { a.Decision = "maybe" }),
	}
	same := answer("a resubmission of the same action", "allow", func(a *faceAnswer) { a.Decision = "allow" })
	same.FirstHash = hash
	changed := answer("a resubmission that mapped to another action", "cannot_decide", func(a *faceAnswer) { a.Decision = "allow" })
	changed.FirstHash = sha256Hex([]byte("the first action"))
	deny := func(code string) string {
		return `{"code":"` + code + `","coverage":"PARTIAL","decision":"deny","error_class":"CANNOT_AUTHORIZE","mode":"enforce","reason":"…"}`
	}
	papErr := func(code string) map[string]string { return map[string]string{"PAP-Error": code, "PAP-Nonce": nonce} }
	f.Answers = append(f.Answers, same, changed,
		FaceAnswer{Name: "not JSON", Status: http.StatusOK, Body: "<html>proxy error</html>", ActionID: actionID, Outcome: "cannot_decide"},
		FaceAnswer{Name: "a gateway error", Status: http.StatusBadGateway, Body: "", ActionID: actionID, Outcome: "cannot_decide"},
		FaceAnswer{Name: "a malformed request", Status: http.StatusBadRequest, Body: deny("invalid_request"), ActionID: actionID, Outcome: "cannot_decide"},
		FaceAnswer{Name: "an unknown connection", Status: http.StatusNotFound, Body: deny("unknown_connection"), ActionID: actionID, Outcome: "cannot_decide"},
		FaceAnswer{Name: "a fresh nonce", Status: http.StatusUnauthorized, Headers: papErr("use_nonce"), Body: deny("use_nonce"), ActionID: actionID, Outcome: "retry_nonce"},
		FaceAnswer{Name: "an expired workload token", Status: http.StatusUnauthorized, Headers: papErr("token_expired"), Body: deny("token_expired"), ActionID: actionID, Outcome: "refresh_token"},
		FaceAnswer{Name: "a replayed proof", Status: http.StatusUnauthorized, Headers: papErr("proof_replay"), Body: deny("proof_replay"), ActionID: actionID, Outcome: "cannot_decide"},
	)
	f.Exchanges = exchanges(t)
	return f
}

// exchanges are the server calls: IssueToken and Wait over Connect JSON
// (protojson, members in lowerCamelCase) and the SSE wait stream.
func exchanges(t *testing.T) []FaceExchange {
	t.Helper()
	pj := func(m proto.Message) string {
		b, err := protojson.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return string(canon(t, b))
	}
	tok := issue(t, tokenSpec{level: 1})
	exp := issuedAt.Add(10 * time.Minute)
	pending := &pantherclawv1.WaitInfo{
		Handle: txnID, RetryAfterSeconds: 5, State: pantherclawv1.WaitState_WAIT_STATE_PENDING,
		DeadlineTime: timestamppb.New(issuedAt.Add(time.Hour)), ApprovalRequestId: "01920000-0000-7000-8000-00000000000a",
	}
	ready := proto.CloneOf(pending)
	ready.State, ready.ConsumeByTime = pantherclawv1.WaitState_WAIT_STATE_READY, timestamppb.New(issuedAt.Add(15*time.Minute))
	declined := proto.CloneOf(pending)
	declined.State, declined.Code = pantherclawv1.WaitState_WAIT_STATE_DECLINED, "APPROVAL_DECLINED"
	waitReq := jsontext.Value(pj(&pantherclawv1.WaitRequest{RunId: runID, Handle: txnID, KnownState: pantherclawv1.WaitState_WAIT_STATE_PENDING, TimeoutSeconds: 30}))
	issueReq := jsontext.Value(pj(&pantherclawv1.IssueTokenRequest{Identifier: identifier()}))
	event := func(state string) string {
		return `event: state` + "\n" + `data: {"handle":"` + txnID + `","state":"` + state + `","deadline":"` +
			issuedAt.Add(time.Hour).Format(time.RFC3339) + `","approval_request_id":"01920000-0000-7000-8000-00000000000a","retry_after_seconds":5}` + "\n\n"
	}
	const issuePath, waitPath = "/pantherclaw.v1.WorkloadService/IssueToken", "/pantherclaw.v1.WorkloadService/Wait"
	return []FaceExchange{
		{
			Name: "token issuance", Method: http.MethodPost, Path: issuePath, Request: issueReq, Status: http.StatusOK,
			Body:  pj(&pantherclawv1.IssueTokenResponse{WorkloadToken: tok, ExpireTime: timestamppb.New(exp), AttestationLevel: 1}),
			Token: tok, ExpiresAt: exp.Unix(), Outcome: "token",
		},
		{
			Name: "token issuance asks for a nonce", Method: http.MethodPost, Path: issuePath, Request: issueReq, Status: http.StatusUnauthorized,
			Headers: map[string]string{"PAP-Error": "use_nonce", "PAP-Nonce": nonce}, Body: `{"code":"unauthenticated","message":"PAP/1: use_nonce"}`,
			Outcome: "retry_nonce",
		},
		{
			Name: "a long-poll that timed out", Method: http.MethodPost, Path: waitPath, Request: waitReq, Status: http.StatusOK,
			Body: pj(&pantherclawv1.WaitResponse{Wait: pending, TimedOut: true}), States: []string{"PENDING"}, Outcome: "wait",
		},
		{
			Name: "a long-poll that ends ready", Method: http.MethodPost, Path: waitPath, Request: waitReq, Status: http.StatusOK,
			Body: pj(&pantherclawv1.WaitResponse{Wait: ready}), States: []string{"READY"}, Outcome: "resubmit",
		},
		{
			Name: "a long-poll that ends declined", Method: http.MethodPost, Path: waitPath, Request: waitReq, Status: http.StatusOK,
			Body: pj(&pantherclawv1.WaitResponse{Wait: declined}), States: []string{"DECLINED"}, Outcome: "deny",
		},
		{
			Name: "the SSE stream until ready", Method: http.MethodGet, Path: "/v1/wait/" + txnID, Status: http.StatusOK,
			Headers: map[string]string{"Content-Type": "text/event-stream"}, Body: event("PENDING") + ": heartbeat\n\n" + event("READY"),
			States: []string{"PENDING", "READY"}, Outcome: "resubmit",
		},
	}
}
