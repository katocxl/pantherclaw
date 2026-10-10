// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"maps"
	"net/http"
	"strings"
	"testing"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// legacyRPC is a 2025-11-25 JSON-RPC request body: no _meta version.
func legacyRPC(method, params string) string {
	return `{"jsonrpc":"2.0","id":9,"method":"` + method + `","params":{` + params + `}}`
}

const initParams = `"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}`

// openSession initializes a 2025-11-25 session in run and returns its id.
func (h *harness) openSession(t *testing.T, run string) string {
	t.Helper()
	r := h.mcpCall(t, http.MethodPost, mcpPath, legacyRPC("initialize", initParams),
		map[string]string{HeaderRunID: run, "MCP-Protocol-Version": "", "Mcp-Method": ""})
	sid := r.hdr.Get("Mcp-Session-Id")
	if r.code != http.StatusOK || r.body.Result.ProtocolVersion != "2025-11-25" || len(sid) != 43 {
		t.Fatalf("initialize = %d %+v %+v %q", r.code, r.body.Error, r.body.Result, sid)
	}
	return sid
}

// inSession posts body in session sid and run, as the test workload;
// hdr overrides headers ("" deletes).
func (h *harness) inSession(t *testing.T, method, sid, run, body string, hdr map[string]string) mcpReply {
	t.Helper()
	all := map[string]string{"MCP-Protocol-Version": "2025-11-25", "Mcp-Session-Id": sid, HeaderRunID: run}
	maps.Copy(all, hdr)
	return h.mcpCall(t, method, mcpPath, body, all)
}

func (f *fakeAuthority) endRun(run string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.endedRuns == nil {
		f.endedRuns = map[string]bool{}
	}
	f.endedRuns[run] = true
}

func (f *fakeAuthority) verifyCount() (int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	last := ""
	if n := len(f.verifiedRuns); n > 0 {
		last = f.verifiedRuns[n-1]
	}
	return f.verifies, last
}

// TestHR083_SessionsAreBoundToTheirWorkload: initialize opens a session in
// the request's run, verified by the Authority with that run. Every later
// request is verified again in the session's run. The session id with
// another instance, another key, another run, or an unknown id is "session
// not found" and reaches no Authority; a missing id is 400. A tools/call in
// the session goes down the dispatch path; list results are private and
// say a call may be a task. DELETE ends it, for its own workload only, and
// GET is 405.
func TestHR083_SessionsAreBoundToTheirWorkload(t *testing.T) {
	h := setup(t)
	run := ids.NewV7().String()
	sid := h.openSession(t, run)
	if _, last := h.auth.verifyCount(); last != run {
		t.Fatalf("initialize verified run %q, want %q", last, run)
	}
	before, _ := h.auth.verifyCount()
	r := h.inSession(t, http.MethodPost, sid, run, legacyRPC("tools/list", ""), nil)
	if n, last := h.auth.verifyCount(); r.code != http.StatusOK || len(r.body.Result.Tools) != 2 || n != before+1 || last != run ||
		r.hdr.Get("Cache-Control") != "private, no-store" || r.body.Result.Tools[0].Execution["taskSupport"] != "optional" {
		t.Fatalf("tools/list = %d %+v %+v, verified %d %q", r.code, r.body.Error, r.body.Result, n-before, last)
	}
	before, _ = h.auth.verifyCount()
	authorized := h.auth.snap().authorize
	// An id one character away from the real one; a random id starts with
	// "A" one time in 64, so pick a first character it does not have.
	unknown := "A" + sid[1:]
	if sid[0] == 'A' {
		unknown = "B" + sid[1:]
	}
	for name, hdr := range map[string]map[string]string{
		"another instance": {"Authorization": "PAP " + workloadTokenFor(ids.NewV7().String())},
		"another key":      {"Authorization": "PAP " + workloadTokenWith(testAgent, "another-key-thumbprint-0000000000000000000")},
		"another run":      {HeaderRunID: ids.NewV7().String()},
		"unknown session":  {"Mcp-Session-Id": unknown},
	} {
		for _, body := range []string{legacyRPC("tools/list", ""), legacyRPC("tools/call", refundArgs)} {
			if r := h.inSession(t, http.MethodPost, sid, run, body, hdr); r.code != http.StatusNotFound {
				t.Errorf("%s: %d %+v", name, r.code, r.body.Error)
			}
		}
	}
	if r := h.inSession(t, http.MethodPost, sid, run, legacyRPC("tools/list", ""), map[string]string{"Mcp-Session-Id": ""}); r.code != http.StatusBadRequest {
		t.Errorf("no session id: %d", r.code)
	}
	if n, _ := h.auth.verifyCount(); n != before || h.auth.snap().authorize != authorized {
		t.Fatal("a request outside its session reached the Authority")
	}
	if r := h.inSession(t, http.MethodPost, sid, run, legacyRPC("ping", ""), map[string]string{HeaderRunID: ""}); r.code != http.StatusOK {
		t.Fatalf("ping without the run header: %d %+v", r.code, r.body.Error)
	}
	r = h.inSession(t, http.MethodPost, sid, run, legacyRPC("tools/call", refundArgs), nil)
	if r.code != http.StatusOK || r.body.Result.IsError || r.body.Result.ResultType != "" || h.target.calls() != 1 ||
		h.auth.snap().actions[0].Action.RunID != run {
		t.Fatalf("tools/call = %d %+v %+v", r.code, r.body.Error, r.body.Result)
	}
	other := map[string]string{"Authorization": "PAP " + workloadTokenFor(ids.NewV7().String())}
	if r := h.inSession(t, http.MethodDelete, sid, run, "", other); r.code != http.StatusNotFound {
		t.Fatalf("DELETE by another instance: %d", r.code)
	}
	if r := h.inSession(t, http.MethodDelete, sid, run, "", nil); r.code != http.StatusNoContent {
		t.Fatalf("DELETE: %d %+v", r.code, r.body.Error)
	}
	if r := h.inSession(t, http.MethodPost, sid, run, legacyRPC("tools/list", ""), nil); r.code != http.StatusNotFound {
		t.Fatalf("after DELETE: %d", r.code)
	}
	if r := h.inSession(t, http.MethodGet, h.openSession(t, run), run, "", nil); r.code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", r.code)
	}
}

// TestHR083_SessionsEndWithTheirRun: initialize needs a run the instance
// may use; a session whose run ended is gone; a request whose workload
// does not verify is refused without ending the session.
func TestHR083_SessionsEndWithTheirRun(t *testing.T) {
	h := setup(t)
	initBody := legacyRPC("initialize", initParams)
	noVersion := map[string]string{"MCP-Protocol-Version": "", "Mcp-Method": ""}
	if r := h.mcpCall(t, http.MethodPost, mcpPath, initBody, map[string]string{"MCP-Protocol-Version": "", "Mcp-Method": "", HeaderRunID: ""}); r.code != http.StatusBadRequest ||
		r.hdr.Get("Mcp-Session-Id") != "" {
		t.Errorf("initialize without a run: %d", r.code)
	}
	ended := ids.NewV7().String()
	h.auth.endRun(ended)
	withRun := maps.Clone(noVersion)
	withRun[HeaderRunID] = ended
	if r := h.mcpCall(t, http.MethodPost, mcpPath, initBody, withRun); r.code != http.StatusUnauthorized || r.hdr.Get(HeaderError) != "run_mismatch" ||
		r.hdr.Get("Mcp-Session-Id") != "" {
		t.Errorf("initialize in an ended run: %d %v", r.code, r.hdr)
	}
	run := ids.NewV7().String()
	sid := h.openSession(t, run)
	h.auth.setIdentity("invalid_proof")
	if r := h.inSession(t, http.MethodPost, sid, run, legacyRPC("tools/list", ""), nil); r.code != http.StatusUnauthorized {
		t.Fatalf("unverified workload: %d", r.code)
	}
	h.auth.setIdentity("")
	if r := h.inSession(t, http.MethodPost, sid, run, legacyRPC("tools/list", ""), nil); r.code != http.StatusOK {
		t.Fatalf("after an unverified request: %d", r.code)
	}
	h.auth.endRun(run)
	for range 2 {
		if r := h.inSession(t, http.MethodPost, sid, run, legacyRPC("tools/list", ""), nil); r.code != http.StatusNotFound {
			t.Fatalf("run ended: %d %+v", r.code, r.body.Error)
		}
	}
}

// TestHR185_TaskAugmentedCallsInSessions: a task-augmented tools/call
// always answers with a task. A held one is working: tasks/get resubmits
// it with the poll's credentials, tasks/result while it is held answers
// the held tool error, and once allowed the task completes with the
// target's answer, which tasks/result returns with the related task; a
// completed task cannot be canceled. A denied call's task has failed; a
// working task can be canceled. Another run's session finds none of them.
func TestHR185_TaskAugmentedCallsInSessions(t *testing.T) {
	h := setup(t, func(h *harness) { h.auth.decision = pb.Decision_DECISION_REQUIRE_APPROVAL })
	run := ids.NewV7().String()
	sid := h.openSession(t, run)
	post := func(method, params string) mcpReply {
		t.Helper()
		return h.inSession(t, http.MethodPost, sid, run, legacyRPC(method, params), nil)
	}
	augmented := refundArgs + `,"task":{"ttl":60000}`
	r := post("tools/call", augmented)
	tk := r.body.Result.Task
	if r.code != http.StatusOK || tk == nil || tk.Status != "working" || len(tk.TaskID) != 43 || tk.TTL != 3_600_000 || tk.PollInterval != 5000 ||
		r.body.Result.Meta["io.modelcontextprotocol/model-immediate-response"] == nil || h.target.calls() != 0 {
		t.Fatalf("held augmented call = %d %+v %+v", r.code, r.body.Error, r.body.Result)
	}
	id := `"taskId":"` + tk.TaskID + `"`
	orun := ids.NewV7().String()
	osid := h.openSession(t, orun)
	for _, m := range []string{"tasks/get", "tasks/result", "tasks/cancel"} {
		if r := h.inSession(t, http.MethodPost, osid, orun, legacyRPC(m, id), nil); r.errCode() != -32602 {
			t.Errorf("%s from another run's session: %+v", m, r.body.Result)
		}
	}
	n := h.auth.snap().authorize
	if r := post("tasks/get", id); r.body.Result.Status != "working" || h.auth.snap().authorize != n+1 {
		t.Fatalf("held poll = %+v", r.body.Result)
	}
	r = post("tasks/result", id)
	if !r.body.Result.IsError || r.body.Result.Meta["io.pantherclaw/hold"] == nil ||
		!strings.Contains(string(r.body.Result.Meta["io.modelcontextprotocol/related-task"]), tk.TaskID) {
		t.Fatalf("result while held = %+v", r.body.Result)
	}
	h.auth.decide(pb.Decision_DECISION_ALLOW)
	if r := post("tasks/get", id); r.body.Result.Status != "completed" || h.target.calls() != 1 {
		t.Fatalf("allowed poll = %+v, target %d", r.body.Result, h.target.calls())
	}
	r = post("tasks/result", id)
	if r.body.Result.IsError || len(r.body.Result.Content) != 1 || !strings.Contains(r.body.Result.Content[0].Text, `"re_1"`) ||
		!strings.Contains(string(r.body.Result.Meta["io.modelcontextprotocol/related-task"]), tk.TaskID) || r.body.Result.ResultType != "" {
		t.Fatalf("result = %+v", r.body.Result)
	}
	if r := post("tasks/cancel", id); r.errCode() != -32602 || !strings.Contains(r.body.Error.Message, "completed") {
		t.Fatalf("cancel completed = %+v", r.body.Error)
	}
	h.auth.decide(pb.Decision_DECISION_DENY)
	r = post("tools/call", strings.Replace(augmented, `"30.00"`, `"31.00"`, 1))
	if tk := r.body.Result.Task; tk == nil || tk.Status != "failed" {
		t.Fatalf("denied augmented call = %+v", r.body.Result)
	}
	if r := post("tasks/result", `"taskId":"`+r.body.Result.Task.TaskID+`"`); !r.body.Result.IsError ||
		!strings.Contains(string(r.body.Result.Meta["io.pantherclaw/error"]), "policy_denied") {
		t.Fatalf("denied result = %+v", r.body.Result)
	}
	h.auth.decide(pb.Decision_DECISION_REQUIRE_APPROVAL)
	r = post("tools/call", strings.Replace(augmented, `"30.00"`, `"32.00"`, 1))
	held := `"taskId":"` + r.body.Result.Task.TaskID + `"`
	if r := post("tasks/cancel", held); r.body.Result.Status != "cancelled" { //nolint:misspell // the 2025-11-25 status
		t.Fatalf("cancel working = %+v %+v", r.body.Error, r.body.Result)
	}
	if r := post("tasks/get", held); r.errCode() != -32602 {
		t.Fatalf("get after cancel = %+v", r.body.Result)
	}
}
