// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"strings"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// fail answers an error in the binding the agent used.
func (h *Handler) fail(w http.ResponseWriter, c call, e *faceError) {
	w.Header().Set("Cache-Control", "private, no-store")
	if c.binding == wire.BindingJSONRPC {
		resp := map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": e.rpc, "message": e.message, "data": errorData(e)}}
		if len(c.id) > 0 {
			resp["id"] = c.id
		}
		status := http.StatusOK
		if e.status == http.StatusUnauthorized || e.status == http.StatusMethodNotAllowed || e.status == http.StatusRequestEntityTooLarge {
			status = e.status
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.MarshalWrite(w, resp, json.Deterministic(true))
		return
	}
	w.Header().Set("Content-Type", wire.ContentType)
	w.WriteHeader(e.status)
	_ = json.MarshalWrite(w, map[string]any{"error": map[string]any{
		"code": e.status, "status": statusName(e.status), "message": e.message,
		"details": []any{map[string]any{
			"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": e.reason, "domain": errorDomain, "metadata": stringFacts(e.facts),
		}},
	}}, json.Deterministic(true))
}

func errorData(e *faceError) map[string]any {
	d := map[string]any{"reason": e.reason, "domain": errorDomain}
	for k, v := range e.facts {
		d[k] = v
	}
	return d
}

// stringFacts are the facts as ErrorInfo metadata (a map of strings).
func stringFacts(facts map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range facts {
		switch t := v.(type) {
		case string:
			out[k] = t
		default:
			if b, err := json.Marshal(t); err == nil {
				out[k] = string(b)
			}
		}
	}
	return out
}

func statusName(status int) string {
	switch status {
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusUnauthorized:
		return "UNAUTHENTICATED"
	case http.StatusForbidden:
		return "PERMISSION_DENIED"
	case http.StatusServiceUnavailable:
		return "UNAVAILABLE"
	case http.StatusGatewayTimeout:
		return "DEADLINE_EXCEEDED"
	case http.StatusBadGateway, http.StatusInternalServerError:
		return "INTERNAL"
	case http.StatusRequestEntityTooLarge, http.StatusMethodNotAllowed:
		return "INVALID_ARGUMENT"
	}
	return "INVALID_ARGUMENT"
}

// refusal is a call PantherClaw refused or could not complete, with the
// facts an agent needs (F642), as the MCP face gives them.
func refusal(res dispatch.Result) *faceError {
	facts := map[string]any{"error_class": string(res.Class), "error": res.Code}
	if res.Decision != pb.Decision_DECISION_UNSPECIFIED {
		facts["decision"] = strings.TrimPrefix(res.Decision.String(), "DECISION_")
	}
	if len(res.Reasons) > 0 {
		facts["reasons"] = res.Reasons
	}
	if res.TransactionID != "" {
		facts["transaction_id"] = res.TransactionID
	}
	if res.Receipt != "" {
		facts["receipt"] = res.Receipt
	}
	if res.Outcome != pb.Outcome_OUTCOME_UNSPECIFIED {
		facts["outcome"] = strings.TrimPrefix(res.Outcome.String(), "OUTCOME_")
	}
	if res.Wait != nil {
		facts["wait"] = map[string]any{"handle": res.Wait.GetHandle()}
	}
	msg := "PantherClaw did not send this call: " + string(res.Class)
	if res.Code != "" {
		msg += " (" + res.Code + ")"
	}
	e := &faceError{status: http.StatusForbidden, rpc: codeRefused, reason: reasonRefused, message: msg, facts: facts}
	switch res.Class {
	case dispatch.Held:
		e.reason = reasonHeld
		e.message += ". It is held for approval or step-up; once granted, send the same request again with the same PC-Action-Id."
	case dispatch.AuthenticationFailed:
		e.status, e.rpc, e.reason = http.StatusUnauthorized, codeAuthenticate, reasonAuthn
	case dispatch.EnforcementFailed, dispatch.ToolFailed:
		e.status, e.reason = http.StatusBadGateway, reasonFailed
	case dispatch.Uncertain:
		e.status, e.reason = http.StatusGatewayTimeout, reasonFailed
	case dispatch.PolicyDenied, dispatch.CannotAuthorize:
		// 403, as set.
	}
	return e
}

// answer relays a dispatched call's answer, recording the tasks and
// contexts the peer gave this run, or answers the refusal.
func (h *Handler) answer(w http.ResponseWriter, c call, res dispatch.Result) {
	if res.Class == dispatch.AuthenticationFailed {
		h.refusePAP(w, c, res.PAPError, res.Nonce)
		return
	}
	if res.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, res.Nonce)
	}
	if res.Class != "" || res.Response == nil {
		if res.Class == "" {
			res.Class, res.Code = dispatch.EnforcementFailed, "no_answer"
		}
		h.fail(w, c, refusal(res))
		return
	}
	body, ok := h.result(c, res.Response.Body)
	if !ok {
		h.fail(w, c, refusal(dispatch.Result{Class: dispatch.EnforcementFailed, Code: "a2a_answer_invalid", TransactionID: res.TransactionID, Receipt: res.Receipt}))
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	if res.TransactionID != "" {
		w.Header().Set("PC-Transaction-Id", res.TransactionID)
	}
	if c.binding == wire.BindingJSONRPC {
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, map[string]any{"jsonrpc": "2.0", "id": c.id, "result": jsontext.Value(body)}, json.Deterministic(true))
		return
	}
	w.Header().Set("Content-Type", wire.ContentType)
	_, _ = w.Write(body)
}

// result checks a peer's answer (the A2A result object, whichever binding
// carried it), notes the tasks and contexts it gives this run and, for a
// listing, keeps only this run's tasks. The answer is untrusted: it must
// decode as what the method answers, or nothing of it is relayed.
func (h *Handler) result(c call, body []byte) ([]byte, bool) {
	o := c.owner()
	switch c.method {
	case wire.MethodSendMessage:
		var r wire.SendMessageResponse
		if json.Unmarshal(body, &r) != nil || (r.Task == nil) == (r.Message == nil) {
			return nil, false
		}
		if r.Task != nil {
			if !wire.ValidID(r.Task.ID) {
				return nil, false
			}
			h.owned.record(o, r.Task.ID, r.Task.ContextID)
		} else if r.Message.ContextID != "" {
			h.owned.record(o, "", r.Message.ContextID)
		}
		return body, true
	case wire.MethodGetTask, wire.MethodCancelTask:
		var t wire.Task
		if json.Unmarshal(body, &t) != nil || t.ID != c.taskID {
			return nil, false
		}
		return body, true
	case wire.MethodListTasks:
		var l wire.ListTasksResponse
		if json.Unmarshal(body, &l) != nil {
			return nil, false
		}
		kept := l.Tasks[:0]
		for _, t := range l.Tasks {
			if _, ok := h.owned.task(o, t.ID); ok {
				kept = append(kept, t)
			}
		}
		l.Tasks = kept
		l.TotalSize, l.NextPageToken = int32(len(kept)), "" //nolint:gosec // G115: bounded by the answer size
		out, err := json.Marshal(l, json.Deterministic(true))
		return out, err == nil
	}
	return nil, false
}
