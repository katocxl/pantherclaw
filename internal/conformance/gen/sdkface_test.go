// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gen_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"regexp"
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
	// Tool, Input and ToolUseID are the call as the agent made it.
	Tool      string         `json:"tool"`
	Input     jsontext.Value `json:"input"`
	ToolUseID string         `json:"tool_use_id"`
	// Path and Body are the request (credentials aside: see proofs.json).
	// Class is "mapped" (an MCP tool PantherClaw decides, sent to the
	// connection named after its server), "builtin" (a name on the built-in
	// list, sent so PantherClaw records it and answered observe), or
	// "refused" (a name the SDK cannot route: denied, never sent).
	Path  string         `json:"path,omitzero"`
	Body  jsontext.Value `json:"body,omitzero"`
	Class string         `json:"class"`
}

// FaceSend is the request an SDK sends to a target-enforced connection's
// target: dispatch decoded, byte for byte (HR-201).
type FaceSend struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// FaceAnswer is one gateway answer to a call of a class, and the outcome
// an SDK reaches.
type FaceAnswer struct {
	Name string `json:"name"`
	// Class is the class of the call answered: mapped or builtin.
	Class   string            `json:"class"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitzero"`
	Body    string            `json:"body"`
	// ActionID is the PC-Action-Id the SDK sent; FirstHash, when set, the
	// action hash of the first answer for that action.
	ActionID  string `json:"action_id"`
	FirstHash string `json:"first_hash,omitzero"`
	// Outcome: allow, observe, hold, deny, cannot_decide, retry_nonce or
	// refresh_token. Send is, for an allow with dispatch, what the SDK
	// sends to the target.
	Outcome string    `json:"outcome"`
	Send    *FaceSend `json:"send,omitzero"`
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
	// Connection is the http or mcp connection that records the built-in
	// tools' calls, and Servers the MCP servers the agent is configured
	// with. A connection governs the one MCP server named after it, so an
	// MCP tool's call goes to /sdk/<server>; a server whose name is no
	// connection's name (ConnectionName), and a tool whose name two
	// servers' names fit, are refused.
	Connection     string   `json:"connection"`
	Servers        []string `json:"servers"`
	ConnectionName string   `json:"connection_name"`
	// Builtins are the tool names the agent SDK has built in (the Claude
	// Agent SDK's): the only names an SDK sends as built-ins, and the only
	// calls an observe answer lets run.
	Builtins []string `json:"builtins"`
	// MaxBody is the largest request body the face reads.
	MaxBody   int            `json:"max_body"`
	Calls     []FaceCall     `json:"calls"`
	Answers   []FaceAnswer   `json:"answers"`
	Exchanges []FaceExchange `json:"exchanges"`
}

// faceAnswer is the gateway's answer (internal/gateway/sdk Answer).
type faceAnswer struct {
	Decision      string        `json:"decision"`
	Reason        string        `json:"reason"`
	ErrorClass    string        `json:"error_class,omitzero"`
	Code          string        `json:"code,omitzero"`
	Reasons       []string      `json:"reasons,omitzero"`
	ActionID      string        `json:"action_id,omitzero"`
	ActionHash    string        `json:"action_hash,omitzero"`
	ActionIR      string        `json:"action_ir,omitzero"`
	TransactionID string        `json:"transaction_id,omitzero"`
	Mode          string        `json:"mode"`
	Coverage      string        `json:"coverage"`
	Wait          *faceWait     `json:"wait,omitzero"`
	Dispatch      *faceDispatch `json:"dispatch,omitzero"`
}

type faceWait struct {
	Handle            string `json:"handle"`
	State             string `json:"state,omitzero"`
	RetryAfterSeconds int32  `json:"retry_after_seconds,omitzero"`
	Deadline          string `json:"deadline,omitzero"`
	ApprovalRequestID string `json:"approval_request_id,omitzero"`
	Code              string `json:"code,omitzero"`
}

type faceDispatch struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ActionToken string            `json:"action_token"`
}

const txnID = "01920000-0000-7000-8000-000000000009"

// builtins are the Claude Agent SDK's built-in tools: the one list the
// SDKs, the integrations and the face (internal/gateway/sdk builtIns)
// load. Any other name is never observed.
var builtins = []string{
	"Agent", "AskUserQuestion", "Bash", "CronCreate", "CronDelete", "CronList", "Edit", "EnterPlanMode", "EnterWorktree",
	"ExitPlanMode", "ExitWorktree", "Glob", "Grep", "ListMcpResourcesTool", "LSP", "Monitor", "NotebookEdit", "PowerShell", "Read",
	"ReadMcpResourceTool", "Skill", "Task", "TaskCreate", "TaskGet", "TaskList", "TaskOutput", "TaskStop", "TaskUpdate", "TodoWrite",
	"ToolSearch", "WaitForMcpServers", "WebFetch", "WebSearch", "Write",
}

// connectionName is the rule for a connection's name (migration 00041):
// the only MCP server names an SDK routes.
const connectionName = `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`

func buildFace(t *testing.T) any {
	t.Helper()
	act := sdkAction(t)
	refund := `{"amount":"30.00","charge":"ch_1","currency":"USD","reason":"duplicate"}`
	f := FaceFile{
		header: head("sdk_face", "the /sdk/{connection} face of tracks S and C (internal/gateway/sdk; G0 M8 decision 19, HR-200, HR-201), "+
			"internal/actionir for hashes, internal/authority/finalize for the action token and internal/gen protojson for the server exchanges",
			"How an SDK sends an agent's tool call to the gateway's /sdk face, what it concludes from each answer (only "+
				"allow, and observe for a built-in tool, let the call run), what it sends a target-enforced connection's "+
				"target, and how it renews its token and waits at the server."),
		Gateway: gatewayURL, Server: issuer, Connection: "payments", ConnectionName: connectionName, Builtins: builtins,
		MaxBody: 64 << 10,
	}
	long, longer := strings.Repeat("s", 63), strings.Repeat("s", 64)
	f.Servers = []string{"payments", "github", "git__hub", "Wiki", "notes", "notes__v2", long, longer}
	// call is a call of a class; a mapped or builtin one is sent to the
	// connection conn.
	call := func(name, tool, input, id, class, conn string) FaceCall {
		c := FaceCall{Name: name, Tool: tool, Input: jsontext.Value(input), ToolUseID: id, Class: class}
		switch class {
		case "mapped":
			c.Path, c.Body = "/sdk/"+conn, jsontext.Value(`{"tool":"`+tool+`","server":"`+conn+`","input":`+input+`,"tool_use_id":"`+id+`"}`)
		case "builtin":
			c.Path, c.Body = "/sdk/"+conn, jsontext.Value(`{"tool":"`+tool+`","input":`+input+`,"tool_use_id":"`+id+`"}`)
		}
		return c
	}
	f.Calls = []FaceCall{
		call("an MCP tool", "mcp__payments__create_refund", refund, "toolu_01", "mapped", "payments"),
		call("an MCP tool of another server goes to the connection named after that server", "mcp__github__merge_pull_request",
			`{"pull_number":"7"}`, "toolu_02", "mapped", "github"),
		call("Bash, observed as a built-in", "Bash", `{"command":"go test ./...","description":"Run the tests"}`, "toolu_03", "builtin", "payments"),
		call("PowerShell, observed as a built-in", "PowerShell", `{"command":"Get-ChildItem"}`, "toolu_04", "builtin", "payments"),
		call("a built-in tool", "Read", `{"file_path":"/etc/hosts"}`, "toolu_05", "builtin", "payments"),
		call("an MCP server the agent is not configured with", "mcp__other__run", `{}`, "toolu_06", "refused", ""),
		call("an MCP name without a tool", "mcp__payments__", `{}`, "toolu_07", "refused", ""),
		call("a name neither MCP nor built in", "deploy", `{"env":"production"}`, "toolu_08", "refused", ""),
		call("a built-in name in another case", "bash", `{"command":"ls"}`, "toolu_09", "refused", ""),
		call("an MCP server whose name has a double underscore, which no connection's name has", "mcp__git__hub__merge_pull_request",
			`{"pull_number":"7"}`, "toolu_10", "refused", ""),
		call("an MCP server whose name has capitals, which no connection's name has", "mcp__Wiki__search", `{"q":"refunds"}`, "toolu_11", "refused", ""),
		call("an MCP server whose name is longer than a connection's", "mcp__"+longer+"__run", `{}`, "toolu_12", "refused", ""),
		call("an MCP server whose name is as long as a connection's may be", "mcp__"+long+"__run", `{}`, "toolu_13", "mapped", long),
		call("an MCP tool whose name two configured servers' names fit", "mcp__notes__v2__search", `{"q":"refunds"}`, "toolu_14", "refused", ""),
		call("an MCP tool whose name only one of two similar servers' names fits", "mcp__notes__search", `{"q":"refunds"}`, "toolu_15", "mapped", "notes"),
	}
	name := regexp.MustCompile(connectionName)
	for _, c := range f.Calls {
		if server := strings.TrimPrefix(c.Path, "/sdk/"); c.Class != "refused" && !name.MatchString(server) {
			t.Fatalf("%s: %s is no connection's name", c.Name, server)
		}
	}
	hash, ir := act.HashHex(), b64(act.Canonical)
	// variant is the action changed after mapping, with its own matching
	// hash, so only the SDK's checks of the action itself can refuse it.
	variant := func(from, to string) (string, string) {
		c := strings.Replace(string(act.Canonical), from, to, 1)
		if c == string(act.Canonical) {
			t.Fatalf("%q not in the action", from)
		}
		return sha256Hex([]byte(c)), b64([]byte(c))
	}
	base := faceAnswer{
		ActionID: actionID, ActionHash: hash, ActionIR: ir, TransactionID: txnID, Mode: "enforce", Coverage: "PARTIAL",
	}
	held := &faceWait{
		Handle: txnID, State: "PENDING", RetryAfterSeconds: 5, Deadline: issuedAt.Add(time.Hour).Format(time.RFC3339),
		ApprovalRequestID: "01920000-0000-7000-8000-00000000000a",
	}
	tok := mintActionToken(t)
	send := &FaceSend{
		Method: http.MethodPost, URL: "https://payments.example.test/v1/refunds", Body: refundBody,
		Headers: map[string]string{"Content-Type": "application/json", "PAP-Action": tok},
	}
	dispatch := func(body string, headers map[string]string, token string) *faceDispatch {
		return &faceDispatch{Method: send.Method, URL: send.URL, Headers: headers, Body: b64([]byte(body)), ActionToken: token}
	}
	answer := func(name, class, outcome string, edit func(*faceAnswer)) FaceAnswer {
		a := base
		edit(&a)
		b, err := json.Marshal(a, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		return FaceAnswer{Name: name, Class: class, Status: http.StatusOK, Body: string(b), ActionID: actionID, Outcome: outcome}
	}
	allow := func(a *faceAnswer) { a.Decision, a.Reason = "allow", "PantherClaw allowed this call." }
	observed := faceAnswer{Decision: "allow", Mode: "monitor", Coverage: "OBSERVE_ONLY", Reason: "PantherClaw does not map the Read tool."}
	enforced := answer("allowed on a target-enforced connection, with the request to send", "mapped", "allow", func(a *faceAnswer) {
		allow(a)
		a.Dispatch = dispatch(refundBody, send.Headers, tok)
	})
	enforced.Send = send
	f.Answers = []FaceAnswer{
		answer("allowed and recorded as delegated", "mapped", "allow", allow),
		enforced,
		answer("monitor mode: recorded, not decided", "mapped", "allow", func(a *faceAnswer) { a.Decision, a.Mode = "allow", "monitor" }),
		answer("held for an approval", "mapped", "hold", func(a *faceAnswer) { a.Decision, a.Wait, a.ErrorClass = "hold", held, "held" }),
		answer("denied", "mapped", "deny", func(a *faceAnswer) {
			a.Decision, a.ErrorClass, a.Code, a.Reasons = "deny", "policy_denied", "GRANT_AMOUNT_EXCEEDED", []string{"GRANT_AMOUNT_EXCEEDED"}
		}),
		answer("a tool the package does not map", "mapped", "deny", func(a *faceAnswer) {
			a.Decision, a.ErrorClass, a.Code, a.ActionHash, a.ActionIR, a.TransactionID = "deny", "cannot_authorize", "unknown_tool", "", "", ""
		}),
		answer("a connection whose credential PantherClaw holds", "mapped", "deny", func(a *faceAnswer) {
			*a = faceAnswer{Decision: "deny", ErrorClass: "cannot_authorize", Code: "use_gateway_face", Mode: "enforce", Coverage: "PARTIAL"}
		}),
		answer("a built-in tool is observed", "builtin", "observe", func(a *faceAnswer) { *a = observed }),
		answer("an observe answer to an MCP tool", "mapped", "cannot_decide", func(a *faceAnswer) { *a = observed }),
		answer("an observe answer carrying an action", "builtin", "cannot_decide", func(a *faceAnswer) {
			*a = observed
			a.ActionID, a.ActionHash, a.ActionIR = actionID, hash, ir
		}),
		answer("an observed call that is not monitored", "builtin", "cannot_decide", func(a *faceAnswer) {
			*a = observed
			a.Mode = "enforce"
		}),
		answer("a decided allow to a built-in tool", "builtin", "allow", allow),
		answer("an allow without the action", "mapped", "cannot_decide", func(a *faceAnswer) { allow(a); a.ActionIR = "" }),
		answer("a hold without the action", "mapped", "cannot_decide", func(a *faceAnswer) {
			a.Decision, a.Wait, a.ErrorClass, a.ActionIR = "hold", held, "held", ""
		}),
		answer("an allow whose action does not hash to its hash", "mapped", "cannot_decide", func(a *faceAnswer) {
			allow(a)
			_, a.ActionIR = variant(`"ch_1"`, `"ch_2"`)
		}),
		answer("an allow for another action id", "mapped", "cannot_decide", func(a *faceAnswer) {
			allow(a)
			a.ActionID = "01920000-0000-7000-8000-00000000000b"
		}),
		answer("an allow whose action carries another action id", "mapped", "cannot_decide", func(a *faceAnswer) {
			allow(a)
			a.ActionHash, a.ActionIR = variant(`"action_id":"`+actionID+`"`, `"action_id":"01920000-0000-7000-8000-00000000000b"`)
		}),
		answer("an allow whose action came through another channel", "mapped", "cannot_decide", func(a *faceAnswer) {
			allow(a)
			a.ActionHash, a.ActionIR = variant(`"channel":"sdk"`, `"channel":"mcp"`)
		}),
		answer("an allow whose action names no connection", "mapped", "cannot_decide", func(a *faceAnswer) {
			allow(a)
			a.ActionHash, a.ActionIR = variant(`"connection":"01920000-0000-7000-8000-000000000007",`, ``)
		}),
		answer("an allow whose action is not an ActionIR", "mapped", "cannot_decide", func(a *faceAnswer) {
			allow(a)
			a.ActionHash, a.ActionIR = sha256Hex([]byte(`{}`)), b64([]byte(`{}`))
		}),
		answer("an allow without an action hash", "mapped", "cannot_decide", func(a *faceAnswer) { allow(a); a.ActionHash = "" }),
		answer("an allow that is not labeled", "mapped", "cannot_decide", func(a *faceAnswer) { allow(a); a.Coverage = "" }),
		answer("a dispatch whose body is not the one its token binds", "mapped", "cannot_decide", func(a *faceAnswer) {
			allow(a)
			a.Dispatch = dispatch(strings.Replace(refundBody, "30.00", "31.00", 1), send.Headers, tok)
		}),
		answer("a dispatch without its action token", "mapped", "cannot_decide", func(a *faceAnswer) {
			allow(a)
			a.Dispatch = dispatch(refundBody, map[string]string{"Content-Type": "application/json"}, "")
		}),
		answer("a dispatch whose PAP-Action header is not its token", "mapped", "cannot_decide", func(a *faceAnswer) {
			allow(a)
			a.Dispatch = dispatch(refundBody, map[string]string{"Content-Type": "application/json", "PAP-Action": "x"}, tok)
		}),
		answer("a hold carrying a dispatch", "mapped", "cannot_decide", func(a *faceAnswer) {
			a.Decision, a.Wait, a.ErrorClass = "hold", held, "held"
			a.Dispatch = dispatch(refundBody, send.Headers, tok)
		}),
		answer("a hold without a wait handle", "mapped", "cannot_decide", func(a *faceAnswer) { a.Decision = "hold" }),
		answer("an unknown decision", "mapped", "cannot_decide", func(a *faceAnswer) { a.Decision = "maybe" }),
	}
	same := answer("a resubmission of the same action", "mapped", "allow", allow)
	same.FirstHash = hash
	changed := answer("a resubmission that mapped to another action", "mapped", "cannot_decide", allow)
	changed.FirstHash = sha256Hex([]byte("the first action"))
	deny := func(code string) string {
		return `{"code":"` + code + `","coverage":"PARTIAL","decision":"deny","error_class":"cannot_authorize","mode":"enforce","reason":"…"}`
	}
	authn := func(code string) string {
		return `{"code":"` + code + `","coverage":"PARTIAL","decision":"deny","error_class":"authentication_failed","mode":"enforce","reason":"PAP/1: ` +
			code + `"}`
	}
	papErr := func(code string) map[string]string { return map[string]string{"PAP-Error": code, "PAP-Nonce": nonce} }
	plain := func(name string, status int, headers map[string]string, body, outcome string) FaceAnswer {
		return FaceAnswer{Name: name, Class: "mapped", Status: status, Headers: headers, Body: body, ActionID: actionID, Outcome: outcome}
	}
	duplicate := `{"action_hash":"` + hash + `","action_id":"` + actionID + `","action_ir":"` + ir +
		`","coverage":"PARTIAL","decision":"deny","decision":"allow","mode":"enforce","reason":"…"}`
	f.Answers = append(f.Answers, same, changed,
		plain("not JSON", http.StatusOK, nil, "<html>proxy error</html>", "cannot_decide"),
		plain("a duplicate decision member", http.StatusOK, nil, duplicate, "cannot_decide"),
		plain("a gateway error", http.StatusBadGateway, nil, "", "cannot_decide"),
		plain("a malformed request", http.StatusBadRequest, nil, deny("invalid_request"), "cannot_decide"),
		plain("an unknown connection", http.StatusNotFound, nil, deny("unknown_connection"), "cannot_decide"),
		plain("a request too large", http.StatusRequestEntityTooLarge, nil, deny("request_too_large"), "cannot_decide"),
		plain("a fresh nonce", http.StatusUnauthorized, papErr("use_nonce"), authn("use_nonce"), "retry_nonce"),
		plain("an expired workload token", http.StatusUnauthorized, papErr("token_expired"), authn("token_expired"), "refresh_token"),
		plain("a replayed proof", http.StatusUnauthorized, papErr("proof_replay"), authn("proof_replay"), "cannot_decide"),
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
