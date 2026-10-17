// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	a2asim "github.com/katocxl/pantherclaw/internal/sim/a2a"
	pca2a "github.com/katocxl/pantherclaw/packages/pc-a2a"
)

var a2aTC = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005", Connection: "01920000-0000-7000-8000-000000000006",
}

func a2aMapped(t *testing.T, method, params string) (*defs.Definition, actionir.ActionIR) {
	t.Helper()
	p, err := manifest.Decode(pca2a.Package)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.A2A(t.Context(), a2aTC, method, []byte(params))
	if err != nil {
		t.Fatal(err)
	}
	def, ok := p.Definition(got.Action.Operation)
	if !ok {
		t.Fatal("no definition")
	}
	return def, got.Action
}

func sendRaw(t *testing.T, r a2aRequest, binding string) (int, []byte, string) {
	t.Helper()
	req, err := r.httpRequest(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b, res.Header.Get("Content-Type")
}

// TestHR323_A2ARequestIsRebuiltFromTheAction: the outbound request carries
// the action's text as its one text part, the transaction as message id,
// and nothing the agent sent beyond the mapped params; it reaches a real
// A2A agent over either binding, and the answer reads as the A2A result.
func TestHR323_A2ARequestIsRebuiltFromTheAction(t *testing.T) {
	sim := a2asim.New(a2asim.Options{}, a2asim.Faults{}, nil)
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	msg := `{"message":{"messageId":"agent-chosen","role":"ROLE_USER","parts":[{"text":"refund ch_1","metadata":{"x":1}}],` +
		`"metadata":{"skill":"refunds","https://pantherclaw.dev/a2a/peer-run/v1":"forged"}}}`
	def, a := a2aMapped(t, wire.MethodSendMessage, msg)
	for _, peer := range []A2APeer{
		{Binding: wire.BindingJSONRPC, URL: ts.URL + a2asim.JSONRPCPath},
		{Binding: wire.BindingHTTPJSON, URL: ts.URL + a2asim.RESTPath},
	} {
		out, err := buildA2A(def, a, "txn-1", peer)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out.body, []byte("forged")) || bytes.Contains(out.body, []byte("agent-chosen")) || bytes.Contains(out.body, []byte(`"x"`)) {
			t.Fatalf("%s: the request carries what the agent sent: %s", peer.Binding, out.body)
		}
		status, body, _ := sendRaw(t, out, peer.Binding)
		result, code, ok := a2aAnswer(peer.Binding, status, body)
		var r wire.SendMessageResponse
		if !ok || code != "" || json.Unmarshal(result, &r) != nil || r.Task == nil || r.Task.Status.State != wire.StateCompleted {
			t.Fatalf("%s: %d %s (%s %v)", peer.Binding, status, body, code, ok)
		}
	}
	got := sim.Received()
	if len(got) != 2 || got[0].Message.MessageID != "txn-1" || got[0].Metadata != nil || got[0].Message.Metadata != nil ||
		len(got[0].Message.Parts) != 1 || got[0].Message.Text() != "refund ch_1" {
		t.Fatalf("the peer received %+v", got)
	}
}

func TestA2AMethodFollowsTheRoute(t *testing.T) {
	sim := a2asim.New(a2asim.Options{}, a2asim.Faults{}, nil)
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	peer := A2APeer{Binding: wire.BindingHTTPJSON, URL: ts.URL + a2asim.RESTPath}
	for method, want := range map[string]string{
		wire.MethodGetTask:         http.MethodGet + " " + peer.URL + "/tasks/task-1",
		wire.MethodSubscribeToTask: http.MethodPost + " " + peer.URL + "/tasks/task-1:subscribe",
		wire.MethodCancelTask:      http.MethodPost + " " + peer.URL + "/tasks/task-1:cancel",
	} {
		def, a := a2aMapped(t, method, `{"id":"task-1"}`)
		out, err := buildA2A(def, a, "txn", peer)
		if err != nil || out.httpMethod+" "+out.url != want {
			t.Errorf("%s: %s %s %v", method, out.httpMethod, out.url, err)
		}
	}
	def, a := a2aMapped(t, wire.MethodListTasks, `{"contextId":"ctx-1"}`)
	if out, err := buildA2A(def, a, "txn", peer); err != nil || out.url != peer.URL+"/tasks?contextId=ctx-1" || out.body != nil {
		t.Errorf("ListTasks: %s %v", out.url, err)
	}
	def, a = a2aMapped(t, wire.MethodSendStreamingMessage, `{"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"x"}],"metadata":{"skill":"echo"}}}`)
	if out, err := buildA2A(def, a, "txn", peer); err != nil || !out.stream || !strings.HasSuffix(out.url, "/message:stream") {
		t.Errorf("SendStreamingMessage: %+v %v", out, err)
	}
	if _, err := buildA2A(def, a, "txn", A2APeer{Binding: wire.BindingGRPC, URL: peer.URL}); !errors.Is(err, egress.ErrBuild) {
		t.Errorf("gRPC binding: %v", err)
	}
}

// TestHR327_A2AStreamsAreReadEventByEvent: a stream yields one checked
// StreamResponse per event, unwrapped from JSON-RPC; a broken event stops
// it.
func TestHR327_A2AStreamsAreReadEventByEvent(t *testing.T) {
	sim := a2asim.New(a2asim.Options{}, a2asim.Faults{}, nil)
	ts := httptest.NewServer(sim.Handler())
	t.Cleanup(ts.Close)
	def, a := a2aMapped(t, wire.MethodSendStreamingMessage, `{"message":{"messageId":"m","role":"ROLE_USER","parts":[{"text":"x"}],"metadata":{"skill":"echo"}}}`)
	for _, peer := range []A2APeer{
		{Binding: wire.BindingJSONRPC, URL: ts.URL + a2asim.JSONRPCPath},
		{Binding: wire.BindingHTTPJSON, URL: ts.URL + a2asim.RESTPath},
	} {
		out, err := buildA2A(def, a, "txn-s", peer)
		if err != nil {
			t.Fatal(err)
		}
		status, body, ct := sendRaw(t, out, peer.Binding)
		if status != http.StatusOK || ct != "text/event-stream" {
			t.Fatalf("%s: %d %s", peer.Binding, status, ct)
		}
		next := sseEvents(bytes.NewReader(body))
		n := 0
		for {
			ev, code, err := nextA2AEvent(next, peer.Binding)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil || code != "" || bytes.HasPrefix(ev, []byte(`{"jsonrpc"`)) {
				t.Fatalf("%s event %d: %s %s %v", peer.Binding, n, ev, code, err)
			}
			n++
		}
		if n != 4 {
			t.Fatalf("%s: %d events", peer.Binding, n)
		}
	}
	bad := sseEvents(strings.NewReader("data: {\"task\":{\"id\":\"t\"},\"message\":{\"messageId\":\"m\"}}\n\n"))
	if _, _, err := nextA2AEvent(bad, wire.BindingHTTPJSON); err == nil {
		t.Fatal("an event with two members was read")
	}
}

func TestA2AAnswerCodes(t *testing.T) {
	for name, c := range map[string]struct {
		binding string
		status  int
		body    string
		code    string
		ok      bool
	}{
		"rpc error":     {wire.BindingJSONRPC, 200, `{"jsonrpc":"2.0","id":"t","error":{"code":-32001,"message":"nope"}}`, "a2a_32001", true},
		"rpc result":    {wire.BindingJSONRPC, 200, `{"jsonrpc":"2.0","id":"t","result":{"id":"x"}}`, "", true},
		"rpc both":      {wire.BindingJSONRPC, 200, `{"jsonrpc":"2.0","id":"t","result":{},"error":{"code":1,"message":""}}`, "", false},
		"rpc 401":       {wire.BindingJSONRPC, 401, `unauthorized`, "a2a_http_401", true},
		"rpc 502":       {wire.BindingJSONRPC, 502, ``, "", false},
		"rest status":   {wire.BindingHTTPJSON, 404, `{"error":{"code":404,"details":[{"reason":"TASK_NOT_FOUND"}]}}`, "a2a_task_not_found", true},
		"rest 2xx junk": {wire.BindingHTTPJSON, 200, `[1]`, "", false},
	} {
		_, code, ok := a2aAnswer(c.binding, c.status, []byte(c.body))
		if code != c.code || ok != c.ok {
			t.Errorf("%s: %q %v", name, code, ok)
		}
	}
}
