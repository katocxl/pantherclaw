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
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// The framework wrappers' contract (M14 PN-016.3; HR-328, HR-329): how a
// LangChain, OpenAI Agents, CrewAI, Vercel AI or MCP TypeScript wrapper
// turns the /sdk face's answers (sdk_face.json) into a tool that ran or a
// refusal the model reads. Every wrapper replays every case against a fake
// gateway.

// WrapperAnswer is one gateway answer to a /sdk request.
type WrapperAnswer struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// WrapperWait is what the server answers while a call is held: the SSE
// stream at /v1/wait/{handle}, and every long-poll Wait once the stream
// ended without a final state.
type WrapperWait struct {
	Stream   string `json:"stream"`
	LongPoll string `json:"long_poll"`
	// Gated: the server answers no wait before every call of the case made
	// its first /sdk request (a concurrent case).
	Gated bool `json:"gated,omitzero"`
}

// WrapperOptions are the wrapper's options in a case; a member left out
// is the wrapper's default.
type WrapperOptions struct {
	ObserveUnmapped bool `json:"observe_unmapped,omitzero"`
	RaiseOnRefusal  bool `json:"raise_on_refusal,omitzero"`
	// Wait is how long a hold is waited on, in seconds.
	Wait int `json:"wait,omitzero"`
	// OnDispatch: the wrapper has an on_dispatch handler, which returns
	// "dispatched" (M14 D53).
	OnDispatch bool `json:"on_dispatch,omitzero"`
}

// WrapperCall is one call of the wrapped tool and what it must come to.
type WrapperCall struct {
	// Input is the call's input; one that is not an object is refused
	// (wrapper_error), and so is one with a key outside the parameters
	// (undecided_args), both without a request.
	Input jsontext.Value `json:"input"`
	// Requests is the number of /sdk requests the call makes, every one
	// with the same PC-Action-Id, and Resumes how many of them resubmitted
	// a held call after a wait (Requests - 1, or 0). ActionID is "new" (an
	// id no earlier call of the case sent) or "same" (the previous call's,
	// or in a concurrent case the other calls'); without a request it is
	// left out.
	Requests int    `json:"requests"`
	Resumes  int    `json:"resumes,omitzero"`
	ActionID string `json:"action_id,omitzero"`
	// Ran: the tool's own function ran, with Input. Otherwise the tool
	// returns Refusal to the model, or raises (Raises) with it.
	Ran         bool   `json:"ran"`
	Code        string `json:"code,omitzero"`
	Transaction string `json:"transaction,omitzero"`
	Refusal     string `json:"refusal,omitzero"`
	Raises      bool   `json:"raises,omitzero"`
	// Dispatched: the tool did not run; the on_dispatch handler was called
	// once with the call's id and the request to send (sdk_face.json's
	// send), and the tool returned its result, "dispatched".
	Dispatched bool `json:"dispatched,omitzero"`
}

// WrapperCase is a sequence of calls of one wrapped tool, in one wrapper
// instance, against a gateway that answers the /sdk requests with Answers
// in order and every wait with Wait. In a Concurrent case the calls start
// at once, and their outcomes match the calls' expectations in some order.
type WrapperCase struct {
	Name       string         `json:"name"`
	Options    WrapperOptions `json:"options,omitzero"`
	Answers    []string       `json:"answers"`
	Wait       string         `json:"wait,omitzero"`
	Concurrent bool           `json:"concurrent,omitzero"`
	Calls      []WrapperCall  `json:"calls"`
}

// WrapperFile is wrappers.json.
type WrapperFile struct {
	header
	// The wrapped tool is Tool on connection Connection; its call is sent
	// to Path with SDKTool as the tool and Connection as the server (the
	// face takes an MCP tool's name or a built-in's, and the connection's
	// package maps Tool).
	Connection string `json:"connection"`
	Tool       string `json:"tool"`
	SDKTool    string `json:"sdk_tool"`
	Path       string `json:"path"`
	// Parameters are the arguments the tool's schema declares.
	Parameters []string `json:"parameters"`
	// ActionID is the action id the answers were made for (rewritten by
	// the fake gateway, see the description).
	ActionID string `json:"action_id"`
	// Codes are the refusal codes (M14 D47) and when each applies; a deny
	// answer's own code is used verbatim.
	Codes   map[string]string        `json:"codes"`
	Answers map[string]WrapperAnswer `json:"answers"`
	Waits   map[string]WrapperWait   `json:"waits"`
	Cases   []WrapperCase            `json:"cases"`
}

// refusal is the text a refused call returns to the model.
func refusal(code, txn string) string {
	if txn == "" {
		return "PantherClaw refused this call: " + code
	}
	return "PantherClaw refused this call: " + code + " (transaction " + txn + ")"
}

// wrapperDeadline is a hold's deadline far enough ahead that no replay
// reaches it: the wait option ends every wait in the cases.
var wrapperDeadline = time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC)

func buildWrappers(t *testing.T) any {
	t.Helper()
	act := sdkAction(t)
	hash, ir := act.HashHex(), b64(act.Canonical)
	f := WrapperFile{
		header: head("wrappers", "the framework wrappers' contract (M14 PN-016.3, HR-328, HR-329) over the /sdk face answers of "+
			"sdk_face.json (internal/gateway/sdk), internal/actionir for hashes, internal/authority/finalize for the action token "+
			"and internal/gen protojson for the waits",
			"How a framework wrapper (LangChain/LangGraph, OpenAI Agents SDK, CrewAI, Vercel AI SDK, MCP TypeScript SDK) "+
				"decides each call of a wrapped tool through the /sdk face: only allow lets the tool run, a hold is waited on "+
				"and the identical call resubmitted, an identical call reuses the action id of an earlier one only while that "+
				"call is unresolved, in flight or held (M14 D68), a call is decided on the arguments the tool's function "+
				"receives and refused with arguments outside its schema (D69), and every other "+
				"outcome returns a refusal to the model (or raises, with raise_on_refusal) without running the tool. The fake "+
				"gateway answers each /sdk request with the case's next answer, rewritten for the PC-Action-Id it received: "+
				"action_id and every occurrence of the file's action_id in the decoded action_ir are replaced, and action_hash "+
				"becomes the SHA-256 of the rewritten action_ir when it was the SHA-256 of the original."),
		Connection: "payments", Tool: "create_refund", SDKTool: "mcp__payments__create_refund", Path: "/sdk/payments",
		Parameters: []string{"amount", "charge", "currency", "reason"}, ActionID: actionID,
		Codes: map[string]string{
			"<code>": "a deny answer with a code: that code, verbatim (GRANT_AMOUNT_EXCEEDED, unknown_tool, use_gateway_face, " +
				"duplicate_action, …)",
			"denied":            "a deny answer without a code",
			"hold_declined":     "a hold that ended in PantherClaw without an allow (declined, expired): the client's resume answered deny",
			"hold_timeout":      "a hold not allowed within the wait: the client's resume answered cannot_decide",
			"cannot_decide":     "any other cannot_decide answer of the client (a gateway error, an answer that fails its checks)",
			"dispatch_required": "an allow carrying a request to send, with no on_dispatch handler",
			"wrapper_error":     "an exception inside the wrapper, or input that is not an object",
			"undecided_args":    "an argument outside the tool's schema (after alias normalisation), which PantherClaw would not decide (M14 D69)",
		},
	}
	base := faceAnswer{ActionID: actionID, ActionHash: hash, ActionIR: ir, TransactionID: txnID, Mode: "enforce", Coverage: "PARTIAL"}
	held := &faceWait{
		Handle: txnID, State: "PENDING", RetryAfterSeconds: 1, Deadline: wrapperDeadline.Format(time.RFC3339),
		ApprovalRequestID: "01920000-0000-7000-8000-00000000000a",
	}
	tok := mintActionToken(t)
	body := func(edit func(*faceAnswer)) WrapperAnswer {
		a := base
		edit(&a)
		b, err := json.Marshal(a, json.Deterministic(true))
		if err != nil {
			t.Fatal(err)
		}
		return WrapperAnswer{Status: http.StatusOK, Body: string(b)}
	}
	allow := func(a *faceAnswer) { a.Decision, a.Reason = "allow", "PantherClaw allowed this call." }
	f.Answers = map[string]WrapperAnswer{
		"allow":   body(allow),
		"monitor": body(func(a *faceAnswer) { a.Decision, a.Mode = "allow", "monitor" }),
		"hold":    body(func(a *faceAnswer) { a.Decision, a.Wait, a.ErrorClass = "hold", held, "held" }),
		"deny": body(func(a *faceAnswer) {
			a.Decision, a.ErrorClass, a.Code, a.Reasons = "deny", "policy_denied", "GRANT_AMOUNT_EXCEEDED", []string{"GRANT_AMOUNT_EXCEEDED"}
			a.Reason = "PantherClaw denied this call."
		}),
		"unmapped": body(func(a *faceAnswer) {
			a.Decision, a.ErrorClass, a.Code, a.ActionHash, a.ActionIR, a.TransactionID = "deny", "cannot_authorize", "unknown_tool", "", "", ""
			a.Reason = "PantherClaw cannot decide this call: the connection's reviewed package does not map mcp__payments__create_refund"
		}),
		"use_gateway_face": body(func(a *faceAnswer) {
			*a = faceAnswer{
				Decision: "deny", ErrorClass: "cannot_authorize", Code: "use_gateway_face", Mode: "enforce", Coverage: "PARTIAL",
				Reason: "PantherClaw holds this connection's credential: use the gateway's MCP or HTTP face.",
			}
		}),
		"send": body(func(a *faceAnswer) {
			allow(a)
			a.Dispatch = &faceDispatch{
				Method: http.MethodPost, URL: "https://payments.example.test/v1/refunds", Body: b64([]byte(refundBody)), ActionToken: tok,
				Headers: map[string]string{"Content-Type": "application/json", "PAP-Action": tok},
			}
		}),
		"tampered": body(func(a *faceAnswer) {
			allow(a)
			a.ActionIR = b64([]byte(strings.Replace(string(act.Canonical), `"ch_1"`, `"ch_2"`, 1)))
		}),
		"deny_without_code": body(func(a *faceAnswer) {
			a.Decision, a.ErrorClass, a.Reason = "deny", "policy_denied", "PantherClaw denied this call."
		}),
		"duplicate": body(func(a *faceAnswer) {
			// A resubmission of an action already finalized: the stored decision, never a second permit (HR-005).
			a.Decision, a.ErrorClass, a.Code = "deny", "cannot_authorize", "duplicate_action"
			a.Reason = "PantherClaw denied this call: cannot_authorize (duplicate_action). Transaction " + txnID + "."
		}),
		"gateway_error": {Status: http.StatusBadGateway},
	}
	f.Waits = wrapperWaits(t, held)
	in := jsontext.Value(refundBody)
	other := jsontext.Value(strings.Replace(refundBody, "30.00", "31.00", 1))
	resumes := func(requests int) int { return max(requests-1, 0) }
	ran := func(requests int, id string) WrapperCall {
		return WrapperCall{Input: in, Requests: requests, Resumes: resumes(requests), ActionID: id, Ran: true}
	}
	refused := func(input jsontext.Value, requests int, id, code, txn string) WrapperCall {
		return WrapperCall{
			Input: input, Requests: requests, Resumes: resumes(requests), ActionID: id, Code: code, Transaction: txn,
			Refusal: refusal(code, txn),
		}
	}
	extra := jsontext.Value(strings.Replace(refundBody, `"reason"`, `"memo":"approved by finance","reason"`, 1))
	raised := refused(in, 1, "new", "GRANT_AMOUNT_EXCEEDED", txnID)
	raised.Raises = true
	changed := ran(1, "new")
	changed.Input = other
	f.Cases = []WrapperCase{
		{Name: "allowed: the tool runs", Answers: []string{"allow"}, Calls: []WrapperCall{ran(1, "new")}},
		{Name: "a monitor route: recorded and run", Answers: []string{"monitor"}, Calls: []WrapperCall{ran(1, "new")}},
		{
			Name: "held, then allowed: the identical call is resubmitted and runs", Answers: []string{"hold", "allow"}, Wait: "ready",
			Calls: []WrapperCall{ran(2, "new")},
		},
		{
			Name: "held, then declined in PantherClaw", Answers: []string{"hold"}, Wait: "declined",
			Calls: []WrapperCall{refused(in, 1, "new", "hold_declined", txnID)},
		},
		{
			Name: "held past the wait, then retried identically: the retry reuses the action id", Options: WrapperOptions{Wait: 1},
			Answers: []string{"hold", "allow"}, Wait: "pending",
			Calls: []WrapperCall{refused(in, 1, "new", "hold_timeout", txnID), ran(1, "same")},
		},
		{
			Name: "held past the wait, then called with changed input: a new decision", Options: WrapperOptions{Wait: 1},
			Answers: []string{"hold", "allow"}, Wait: "pending",
			Calls: []WrapperCall{refused(in, 1, "new", "hold_timeout", txnID), changed},
		},
		{
			Name: "held, then a resubmission PantherClaw cannot decide: hold_timeout", Answers: []string{"hold", "gateway_error"}, Wait: "ready",
			Calls: []WrapperCall{refused(in, 2, "new", "hold_timeout", txnID)},
		},
		{
			Name: "allowed, then the identical call again: a new decision", Answers: []string{"allow", "allow"},
			Calls: []WrapperCall{ran(1, "new"), ran(1, "new")},
		},
		{
			Name: "two identical calls at once while held: one runs, the other is a duplicate", Concurrent: true,
			Answers: []string{"hold", "hold", "allow", "duplicate"}, Wait: "gated",
			Calls: []WrapperCall{ran(2, "new"), refused(in, 2, "same", "duplicate_action", txnID)},
		},
		{Name: "denied", Answers: []string{"deny"}, Calls: []WrapperCall{refused(in, 1, "new", "GRANT_AMOUNT_EXCEEDED", txnID)}},
		{
			Name: "denied without a code", Answers: []string{"deny_without_code"},
			Calls: []WrapperCall{refused(in, 1, "new", "denied", txnID)},
		},
		{
			Name: "input that is not an object: refused without a request", Answers: []string{"allow"},
			Calls: []WrapperCall{refused(jsontext.Value(`["30.00","ch_1"]`), 0, "", "wrapper_error", "")},
		},
		{
			Name: "an argument outside the schema: refused without a request", Answers: []string{"allow"},
			Calls: []WrapperCall{refused(extra, 0, "", "undecided_args", "")},
		},
		{Name: "denied, raising", Options: WrapperOptions{RaiseOnRefusal: true}, Answers: []string{"deny"}, Calls: []WrapperCall{raised}},
		{Name: "a gateway error: cannot decide", Answers: []string{"gateway_error"}, Calls: []WrapperCall{refused(in, 1, "new", "cannot_decide", "")}},
		{
			Name: "an answer whose action does not hash to its hash: cannot decide", Answers: []string{"tampered"},
			Calls: []WrapperCall{refused(in, 1, "new", "cannot_decide", "")},
		},
		{
			Name: "a tool the package does not map is refused", Answers: []string{"unmapped"},
			Calls: []WrapperCall{refused(in, 1, "new", "unknown_tool", "")},
		},
		{
			Name: "a tool the package does not map runs with observe_unmapped", Options: WrapperOptions{ObserveUnmapped: true},
			Answers: []string{"unmapped"}, Calls: []WrapperCall{ran(1, "new")},
		},
		{
			Name: "a connection whose credential PantherClaw holds", Answers: []string{"use_gateway_face"},
			Calls: []WrapperCall{refused(in, 1, "new", "use_gateway_face", "")},
		},
		{
			Name: "an allow with a request to send and no on_dispatch handler", Answers: []string{"send"},
			Calls: []WrapperCall{refused(in, 1, "new", "dispatch_required", txnID)},
		},
		{
			Name:    "an allow with a request to send and an on_dispatch handler: the handler sends it, the tool does not run",
			Options: WrapperOptions{OnDispatch: true}, Answers: []string{"send"},
			Calls: []WrapperCall{{Input: in, Requests: 1, ActionID: "new", Dispatched: true}},
		},
	}
	return f
}

// wrapperWaits are the waits of the cases: ready (the stream ends READY),
// declined (DECLINED), pending (the stream and every long-poll stay
// PENDING) and gated (ready, once every call of the case started).
func wrapperWaits(t *testing.T, held *faceWait) map[string]WrapperWait {
	t.Helper()
	event := func(state, code string) string {
		c := ""
		if code != "" {
			c = `,"code":"` + code + `"`
		}
		return `event: state` + "\n" + `data: {"handle":"` + txnID + `","state":"` + state + `","deadline":"` + held.Deadline +
			`","approval_request_id":"` + held.ApprovalRequestID + `","retry_after_seconds":1` + c + "}\n\n"
	}
	poll := func(state pantherclawv1.WaitState, code string, timedOut bool) string {
		w := &pantherclawv1.WaitInfo{
			Handle: txnID, RetryAfterSeconds: 1, State: state, DeadlineTime: timestamppb.New(wrapperDeadline),
			ApprovalRequestId: held.ApprovalRequestID, Code: code,
		}
		b, err := protojson.Marshal(&pantherclawv1.WaitResponse{Wait: w, TimedOut: timedOut})
		if err != nil {
			t.Fatal(err)
		}
		return string(canon(t, b))
	}
	return map[string]WrapperWait{
		"ready": {Stream: event("PENDING", "") + event("READY", ""), LongPoll: poll(pantherclawv1.WaitState_WAIT_STATE_READY, "", false)},
		"declined": {
			Stream:   event("DECLINED", "APPROVAL_DECLINED"),
			LongPoll: poll(pantherclawv1.WaitState_WAIT_STATE_DECLINED, "APPROVAL_DECLINED", false),
		},
		"pending": {Stream: event("PENDING", ""), LongPoll: poll(pantherclawv1.WaitState_WAIT_STATE_PENDING, "", true)},
		"gated": {
			Stream: event("PENDING", "") + event("READY", ""), LongPoll: poll(pantherclawv1.WaitState_WAIT_STATE_READY, "", false),
			Gated: true,
		},
	}
}
