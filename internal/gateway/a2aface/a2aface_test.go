// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2aface

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

type fixedConfig struct{ cfg *control.Config }

func (f fixedConfig) Current() *control.Config { return f.cfg }

const run = "0190f3b4-7c2e-7aaa-8bbb-000000000001"

func testFace(t *testing.T) (*Handler, *control.Connection, *int) {
	t.Helper()
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c-1", Name: "peer", Kind: "a2a"}}
	cfg := &control.Config{ByName: map[string]*control.Connection{"peer": conn}, ByID: map[string]*control.Connection{"c-1": conn}}
	peerOf := func(c *control.Connection) (Peer, bool) {
		return Peer{Card: []byte(`{"name":"p","supportedInterfaces":[{"url":"https://p","protocolBinding":"JSONRPC"}]}`), Binding: wire.BindingJSONRPC, Skills: []string{"refunds", "echo"}}, c == conn
	}
	h := New(nil, fixedConfig{cfg}, peerOf, "https://gw.example", nil)
	sent := 0
	h.send = func(call, dispatch.A2ASink) dispatch.Result {
		sent++
		return dispatch.Result{Class: dispatch.CannotAuthorize, Code: "test"}
	}
	return h, conn, &sent
}

func serve(h *Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestPath(t *testing.T) {
	for p, want := range map[string][2]string{
		"/a2a/peer":                             {"peer", ""},
		"/a2a/peer/message:send":                {"peer", "/message:send"},
		"/a2a/peer/.well-known/agent-card.json": {"peer", "/.well-known/agent-card.json"},
	} {
		name, rest, ok := Path(p)
		if !ok || name != want[0] || rest != want[1] {
			t.Errorf("Path(%q) = %q %q %v", p, name, rest, ok)
		}
	}
	for _, p := range []string{"/a2a/", "/mcp/peer", "/a2ab/peer"} {
		if _, _, ok := Path(p); ok {
			t.Errorf("Path(%q) matched", p)
		}
	}
}

// TestHR323_PushAndExtendedCardNeverRelayed: push configuration methods
// and the extended card are refused in both bindings, before anything is
// decided or sent.
func TestHR323_PushAndExtendedCardNeverRelayed(t *testing.T) {
	h, _, sent := testFace(t)
	for _, m := range []string{wire.MethodCreatePushConfig, wire.MethodGetPushConfig, wire.MethodListPushConfigs, wire.MethodDeletePushConfig, wire.MethodGetExtendedCard} {
		w := serve(h, http.MethodPost, "/a2a/peer", `{"jsonrpc":"2.0","id":1,"method":"`+m+`","params":{}}`)
		if !strings.Contains(w.Body.String(), CodePushNot) {
			t.Errorf("%s: %s", m, w.Body.String())
		}
	}
	for _, rq := range [][2]string{
		{http.MethodPost, "/a2a/peer/tasks/t1/pushNotificationConfigs"},
		{http.MethodGet, "/a2a/peer/tasks/t1/pushNotificationConfigs/c1"},
		{http.MethodDelete, "/a2a/peer/tasks/t1/pushNotificationConfigs/c1"},
		{http.MethodGet, "/a2a/peer/extendedAgentCard"},
	} {
		w := serve(h, rq[0], rq[1], `{}`)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), CodePushNot) {
			t.Errorf("%s %s: %d %s", rq[0], rq[1], w.Code, w.Body.String())
		}
	}
	if *sent != 0 {
		t.Fatalf("%d calls sent", *sent)
	}
}

func TestRequestsRefusedBeforeAuthentication(t *testing.T) {
	h, _, sent := testFace(t)
	for name, c := range map[string]struct {
		method, path, body, want string
	}{
		"unknown connection": {http.MethodPost, "/a2a/other", `{"jsonrpc":"2.0","id":1,"method":"SendMessage"}`, "unknown connection"},
		"batch":              {http.MethodPost, "/a2a/peer", `[{"jsonrpc":"2.0","id":1,"method":"SendMessage"}]`, "batches"},
		"duplicate members":  {http.MethodPost, "/a2a/peer", `{"jsonrpc":"2.0","id":1,"method":"SendMessage","method":"GetTask"}`, "parse error"},
		"no id":              {http.MethodPost, "/a2a/peer", `{"jsonrpc":"2.0","method":"SendMessage"}`, "id must be"},
		"get on jsonrpc":     {http.MethodGet, "/a2a/peer", ``, "POST only"},
		"unknown path":       {http.MethodPost, "/a2a/peer/message:delete", `{}`, "no such A2A method"},
	} {
		w := serve(h, c.method, c.path, c.body)
		if !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/a2a/peer", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}`))
	req.Header.Set(wire.HeaderVersion, "0.3")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "-32009") {
		t.Errorf("version 0.3: %s", w.Body.String())
	}
	if *sent != 0 {
		t.Fatalf("%d calls sent", *sent)
	}
}

func sendCall(h *Handler, conn *control.Connection) call {
	peer, _ := h.peerOf(conn)
	return call{conn: conn, peer: peer, in: dispatch.Inbound{Run: run}, binding: wire.BindingJSONRPC, method: wire.MethodSendMessage}
}

// TestHR323_OnlyTextPartsAndOwnedIDsAreRelayed: a message is rebuilt from
// its text parts; data, file, raw and url parts, push configurations,
// extensions, references, a tenant and unknown fields are refused; a task
// or context id must be one the peer answered to this run.
func TestHR323_OnlyTextPartsAndOwnedIDsAreRelayed(t *testing.T) {
	h, conn, _ := testFace(t)
	c := sendCall(h, conn)
	h.owned.record(c.owner(), "task-1", "ctx-1")
	other := owner{conn: conn.GetId(), run: "0190f3b4-7c2e-7aaa-8bbb-000000000002"}
	h.owned.record(other, "task-9", "ctx-9")
	msg := func(extra string) string {
		return `{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"refund ch_1"}],"metadata":{"skill":"refunds"}` + extra + `}}`
	}
	for name, c2 := range map[string]struct {
		params, reason string
	}{
		"data part":         {`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"data":{"a":1}}]}}`, CodePartNot},
		"url part":          {`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"url":"https://x","mediaType":"text/plain"}]}}`, CodePartNot},
		"raw part":          {`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"raw":"AAAA"}]}}`, CodePartNot},
		"text and file":     {`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"x","filename":"a.pdf"}]}}`, CodePartNot},
		"no parts":          {`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[]}}`, CodePartNot},
		"two parts":         {`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"a"},{"text":"b"}]}}`, CodePartNot},
		"skill not allowed": {`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"a"}],"metadata":{"skill":"transfers"}}}`, CodeSkillNot},
		"push config":       {`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"x"}]},"configuration":{"pushNotificationConfig":{"url":"https://evil"}}}`, CodePushNot},
		"extensions":        {msg(`,"extensions":["urn:x"]`), CodeFieldNot},
		"references":        {msg(`,"referenceTaskIds":["task-9"]`), CodeFieldNot},
		"unknown field":     {msg(`,"sneaky":1`), CodeFieldNot},
		"tenant":            {`{"tenant":"t","message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"x"}]}}`, CodeFieldNot},
		"agent role":        {`{"message":{"messageId":"m1","role":"ROLE_AGENT","parts":[{"text":"x"}]}}`, CodeBadRequest},
		"other run task":    {msg(`,"taskId":"task-9"`), CodeTaskUnknown},
		"other run ctx":     {msg(`,"contextId":"ctx-9"`), CodeTaskUnknown},
		"unknown task":      {msg(`,"taskId":"task-404"`), CodeTaskUnknown},
		"task in wrong c":   {msg(`,"taskId":"task-1","contextId":"ctx-9"`), CodeTaskUnknown},
	} {
		if _, ferr := h.readSend(c, jsontext.Value(c2.params)); ferr == nil || ferr.reason != c2.reason {
			t.Errorf("%s: %+v, want %s", name, ferr, c2.reason)
		}
	}
	req, ferr := h.readSend(c, jsontext.Value(`{"message":{"messageId":"m2","role":"ROLE_USER","taskId":"task-1",`+
		`"parts":[{"text":"a","mediaType":"text/plain","metadata":{"x":1}}],"metadata":{"skill":"refunds","https://pantherclaw.dev/a2a/peer-run/v1":"forged"}},`+
		`"metadata":{"forged":true}}`))
	if ferr != nil {
		t.Fatalf("owned task: %+v", ferr)
	}
	out, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"message":{"messageId":"m2","contextId":"ctx-1","taskId":"task-1","role":"ROLE_USER","parts":[{"text":"a"}]}}`
	if string(out) != want {
		t.Fatalf("rebuilt request:\n got %s\nwant %s", out, want)
	}
}

// TestHR323_TaskReadsAndListsAreThisRunsOnly: GetTask, CancelTask and
// SubscribeToTask name a task of this run; ListTasks names a context of
// this run and answers only this run's tasks.
func TestHR323_TaskReadsAndListsAreThisRunsOnly(t *testing.T) {
	h, conn, _ := testFace(t)
	c := sendCall(h, conn)
	h.owned.record(c.owner(), "task-1", "ctx-1")
	for _, m := range []string{wire.MethodGetTask, wire.MethodCancelTask, wire.MethodSubscribeToTask} {
		c.method = m
		if ferr := h.read(&c, jsontext.Value(`{"id":"task-2"}`)); ferr == nil || ferr.reason != CodeTaskUnknown {
			t.Errorf("%s other task: %+v", m, ferr)
		}
		if ferr := h.read(&c, jsontext.Value(`{"id":"task-1"}`)); ferr != nil {
			t.Errorf("%s own task: %+v", m, ferr)
		}
	}
	c.method = wire.MethodListTasks
	for _, p := range []string{`{}`, `{"contextId":"ctx-2"}`} {
		if ferr := h.read(&c, jsontext.Value(p)); ferr == nil || ferr.reason != CodeTaskUnknown {
			t.Errorf("list %s: %+v", p, ferr)
		}
	}
	if ferr := h.read(&c, jsontext.Value(`{"contextId":"ctx-1"}`)); ferr != nil {
		t.Fatalf("list own context: %+v", ferr)
	}
	body, ok := h.result(c, []byte(`{"tasks":[{"id":"task-1","contextId":"ctx-1","status":{"state":"TASK_STATE_WORKING"}},`+
		`{"id":"task-7","contextId":"ctx-1","status":{"state":"TASK_STATE_COMPLETED"}}],"totalSize":2,"pageSize":50,"nextPageToken":"n"}`))
	if !ok {
		t.Fatal("listing refused")
	}
	var l wire.ListTasksResponse
	if err := json.Unmarshal(body, &l); err != nil || len(l.Tasks) != 1 || l.Tasks[0].ID != "task-1" || l.TotalSize != 1 || l.NextPageToken != "" {
		t.Fatalf("listing shows another run's task: %s", body)
	}
}

// TestHR327_PeerAnswersAreChecked: an answer that is not what the method
// answers is not relayed, and the ids the peer answers become this run's.
func TestHR327_PeerAnswersAreChecked(t *testing.T) {
	h, conn, _ := testFace(t)
	c := sendCall(h, conn)
	for _, bad := range []string{`{}`, `{"task":{"id":"t"},"message":{"messageId":"m","role":"ROLE_AGENT","parts":[]}}`, `[]`, `{"task":{"id":"a/b","status":{"state":"x"}}}`} {
		if _, ok := h.result(c, []byte(bad)); ok {
			t.Errorf("answer %s relayed", bad)
		}
	}
	if _, ok := h.result(c, []byte(`{"task":{"id":"task-5","contextId":"ctx-5","status":{"state":"TASK_STATE_WORKING"}}}`)); !ok {
		t.Fatal("task answer refused")
	}
	if ctx, ok := h.owned.task(c.owner(), "task-5"); !ok || ctx != "ctx-5" || !h.owned.context(c.owner(), "ctx-5") {
		t.Fatal("answered task not recorded for the run")
	}
	other := owner{conn: conn.GetId(), run: "0190f3b4-7c2e-7aaa-8bbb-000000000002"}
	if _, ok := h.owned.task(other, "task-5"); ok {
		t.Fatal("another run owns the task")
	}
	c.method, c.taskID = wire.MethodGetTask, "task-5"
	if _, ok := h.result(c, []byte(`{"id":"task-6","status":{"state":"TASK_STATE_WORKING"}}`)); ok {
		t.Fatal("an answer about another task was relayed")
	}
}

func TestOwnedForgetsOldestFirst(t *testing.T) {
	o := newOwned(2)
	w := owner{conn: "c", run: "r"}
	o.record(w, "t1", "")
	o.record(w, "t2", "")
	o.record(w, "t3", "")
	if _, ok := o.task(w, "t1"); ok {
		t.Fatal("t1 kept beyond the bound")
	}
	for _, id := range []string{"t2", "t3"} {
		if _, ok := o.task(w, id); !ok {
			t.Fatalf("%s forgotten", id)
		}
	}
}

func TestRefusalFacts(t *testing.T) {
	e := refusal(dispatch.Result{Class: dispatch.Held, Code: "approval_required", TransactionID: "tx", Decision: pb.Decision_DECISION_REQUIRE_APPROVAL})
	if e.reason != reasonHeld || e.facts["transaction_id"] != "tx" || e.facts["decision"] != "REQUIRE_APPROVAL" || e.status != http.StatusForbidden {
		t.Fatalf("held: %+v", e)
	}
	if e := refusal(dispatch.Result{Class: dispatch.Uncertain}); e.status != http.StatusGatewayTimeout {
		t.Fatalf("uncertain: %+v", e)
	}
}

// TestHR323_SkillsDefaultToTheCards (D96 L6): a connection listing no
// skills allows only the pinned card's skills, never any skill.
func TestHR323_SkillsDefaultToTheCards(t *testing.T) {
	h, conn, _ := testFace(t)
	c := sendCall(h, conn)
	c.peer = Peer{Card: []byte(`{"name":"p","supportedInterfaces":[{"url":"https://p","protocolBinding":"JSONRPC"}],` +
		`"skills":[{"id":"refunds","name":"Refunds","description":"r"}]}`), Binding: wire.BindingJSONRPC}
	ask := func(skill string) *faceError {
		_, ferr := h.readSend(c, jsontext.Value(`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"x"}],"metadata":{"skill":"`+skill+`"}}}`))
		return ferr
	}
	if ferr := ask("refunds"); ferr != nil {
		t.Fatalf("a card skill: %+v", ferr)
	}
	for _, s := range []string{"transfers", ""} {
		if ferr := ask(s); ferr == nil || ferr.reason != CodeSkillNot {
			t.Errorf("skill %q: %+v", s, ferr)
		}
	}
}
