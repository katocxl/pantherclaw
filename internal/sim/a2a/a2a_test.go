// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package a2a

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
)

func start(t *testing.T, o Options, f Faults) (*Server, *httptest.Server) {
	t.Helper()
	s := New(o, f, nil)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func post(t *testing.T, url, token string, body any) (*http.Response, []byte) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.HeaderVersion, wire.Version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func rpc(method string, params any) wire.RPCRequest {
	return wire.RPCRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params}
}

func userMessage(id, text string) wire.Message {
	return wire.Message{MessageID: id, Role: wire.RoleUser, Parts: []wire.Part{wire.TextPart(text)}}
}

type rpcAnswer struct {
	Result jsontext.Value `json:"result"`
	Error  *wire.RPCError `json:"error"`
}

func decodeRPC(t *testing.T, b []byte) rpcAnswer {
	t.Helper()
	var a rpcAnswer
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return a
}

func TestCardSignedAndDrift(t *testing.T) {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, ts := start(t, Options{SigningKey: k, KeyID: "peer-1"}, Faults{})
	get := func() []byte {
		resp, err := http.Get(ts.URL + wire.CardPath) //nolint:noctx // test
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b
	}
	raw := get()
	jwks, err := wire.PublicJWKS(map[string]crypto.PublicKey{"peer-1": k.Public()})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := wire.ParseKeys(jwks)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := wire.CheckPin(raw, keys, wire.BindingJSONRPC, ts.URL+JSONRPCPath, []string{"refunds"})
	if err != nil {
		t.Fatalf("pin: %v", err)
	}
	s.SetFaults(Faults{Description: "Now handles transfers too"})
	drifted := get()
	d2, err := wire.Digest(drifted)
	if err != nil || d2 == digest {
		t.Fatalf("drifted card has the pinned digest (%v)", err)
	}
	if err := wire.VerifySignatures(drifted, keys); err != nil {
		t.Fatalf("the simulator re-signs a drifted card: %v", err)
	}
}

func TestJSONRPCSendGetCancel(t *testing.T) {
	s, ts := start(t, Options{Token: "tok"}, Faults{CompleteAfter: time.Hour})
	url := ts.URL + JSONRPCPath
	if resp, _ := post(t, url, "", rpc(wire.MethodSendMessage, wire.SendMessageRequest{Message: userMessage("m1", "hi")})); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
	_, b := post(t, url, "tok", rpc(wire.MethodSendMessage, wire.SendMessageRequest{Message: userMessage("m1", "refund ch_1")}))
	var sent wire.SendMessageResponse
	if err := json.Unmarshal(decodeRPC(t, b).Result, &sent); err != nil || sent.Task == nil {
		t.Fatalf("send: %v %s", err, b)
	}
	if sent.Task.Status.State != wire.StateWorking {
		t.Fatalf("state %s", sent.Task.Status.State)
	}
	_, b = post(t, url, "tok", rpc(wire.MethodGetTask, wire.GetTaskRequest{ID: sent.Task.ID}))
	var got wire.Task
	if err := json.Unmarshal(decodeRPC(t, b).Result, &got); err != nil || got.ID != sent.Task.ID {
		t.Fatalf("get: %v %s", err, b)
	}
	_, b = post(t, url, "tok", rpc(wire.MethodCancelTask, wire.TaskIDRequest{ID: got.ID}))
	if err := json.Unmarshal(decodeRPC(t, b).Result, &got); err != nil || got.Status.State != wire.StateCanceled {
		t.Fatalf("cancel: %v %s", err, b)
	}
	_, b = post(t, url, "tok", rpc(wire.MethodCancelTask, wire.TaskIDRequest{ID: got.ID}))
	if a := decodeRPC(t, b); a.Error == nil || a.Error.Code != wire.CodeTaskNotCancelable {
		t.Fatalf("cancel twice: %s", b)
	}
	_, b = post(t, url, "tok", rpc(wire.MethodGetTask, wire.GetTaskRequest{ID: "task-404"}))
	if a := decodeRPC(t, b); a.Error == nil || a.Error.Code != wire.CodeTaskNotFound {
		t.Fatalf("unknown task: %s", b)
	}
	// A task of another context is not found.
	m := userMessage("m2", "more")
	m.TaskID, m.ContextID = sent.Task.ID, "ctx-other"
	_, b = post(t, url, "tok", rpc(wire.MethodSendMessage, wire.SendMessageRequest{Message: m}))
	if a := decodeRPC(t, b); a.Error == nil || a.Error.Code != wire.CodeTaskNotFound {
		t.Fatalf("other context: %s", b)
	}
	_, b = post(t, url, "tok", rpc(wire.MethodCreatePushConfig, map[string]any{"taskId": got.ID}))
	if a := decodeRPC(t, b); a.Error == nil || a.Error.Code != wire.CodePushNotSupported {
		t.Fatalf("push: %s", b)
	}
	if n := len(s.Received()); n != 1 {
		t.Fatalf("received %d messages, want 1", n)
	}
}

func TestRESTSendCompletesAndLists(t *testing.T) {
	_, ts := start(t, Options{}, Faults{})
	resp, b := post(t, ts.URL+RESTPath+"/message:send", "", wire.SendMessageRequest{Message: userMessage("m1", "hi")})
	var sent wire.SendMessageResponse
	if err := json.Unmarshal(b, &sent); err != nil || resp.StatusCode != http.StatusOK || sent.Task == nil {
		t.Fatalf("send: %d %s", resp.StatusCode, b)
	}
	if sent.Task.Status.State != wire.StateCompleted || len(sent.Task.Artifacts) != 1 ||
		!strings.Contains(*sent.Task.Artifacts[0].Parts[0].Text, "SIMULATED") {
		t.Fatalf("task: %s", b)
	}
	r, err := http.Get(ts.URL + RESTPath + "/tasks?contextId=" + sent.Task.ContextID) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	var list wire.ListTasksResponse
	if err := json.UnmarshalRead(r.Body, &list); err != nil || len(list.Tasks) != 1 {
		t.Fatalf("list: %v %+v", err, list)
	}
	r2, err := http.Get(ts.URL + RESTPath + "/tasks/nope") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown task: %d", r2.StatusCode)
	}
}

func TestStreamEvents(t *testing.T) {
	for _, binding := range []string{wire.BindingJSONRPC, wire.BindingHTTPJSON} {
		t.Run(binding, func(t *testing.T) {
			_, ts := start(t, Options{}, Faults{CompleteAfter: 50 * time.Millisecond})
			var url string
			var body any
			req := wire.SendMessageRequest{Message: userMessage("m1", "stream please")}
			if binding == wire.BindingJSONRPC {
				url, body = ts.URL+JSONRPCPath, rpc(wire.MethodSendStreamingMessage, req)
			} else {
				url, body = ts.URL+RESTPath+"/message:stream", req
			}
			resp, b := post(t, url, "", body)
			if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
				t.Fatalf("content type %q: %s", ct, b)
			}
			var events []wire.StreamResponse
			sc := bufio.NewScanner(bytes.NewReader(b))
			for sc.Scan() {
				data, ok := strings.CutPrefix(sc.Text(), "data: ")
				if !ok {
					continue
				}
				var ev wire.StreamResponse
				if binding == wire.BindingJSONRPC {
					var a rpcAnswer
					if err := json.Unmarshal([]byte(data), &a); err != nil {
						t.Fatal(err)
					}
					data = string(a.Result)
				}
				if err := json.Unmarshal([]byte(data), &ev); err != nil {
					t.Fatal(err)
				}
				events = append(events, ev)
			}
			if len(events) != 4 || events[0].Task == nil || events[1].StatusUpdate == nil || events[2].ArtifactUpdate == nil ||
				events[3].StatusUpdate == nil || events[3].StatusUpdate.Status.State != wire.StateCompleted {
				t.Fatalf("events: %s", b)
			}
		})
	}
}

func TestRequireActionAndVersion(t *testing.T) {
	s, ts := start(t, Options{RequireAction: func(r *http.Request, _ []byte) error {
		if r.Header.Get("PAP-Action") == "" {
			return errors.New("action_token_required")
		}
		return nil
	}}, Faults{})
	_, b := post(t, ts.URL+JSONRPCPath, "", rpc(wire.MethodSendMessage, wire.SendMessageRequest{Message: userMessage("m1", "hi")}))
	if a := decodeRPC(t, b); a.Error == nil || !strings.Contains(a.Error.Message, "action_token_required") {
		t.Fatalf("no action token: %s", b)
	}
	if len(s.Received()) != 0 {
		t.Fatal("a refused message was recorded")
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, ts.URL+JSONRPCPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"x"}}`))
	req.Header.Set(wire.HeaderVersion, "0.3")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if a := decodeRPC(t, out); a.Error == nil || a.Error.Code != wire.CodeVersionNotSupported {
		t.Fatalf("version 0.3: %s", out)
	}
}

func TestFaultStates(t *testing.T) {
	s, ts := start(t, Options{}, Faults{AuthRequired: true})
	send := func() wire.Task {
		_, b := post(t, ts.URL+RESTPath+"/message:send", "", wire.SendMessageRequest{Message: userMessage("m", "x")})
		var r wire.SendMessageResponse
		if err := json.Unmarshal(b, &r); err != nil || r.Task == nil {
			t.Fatalf("%v %s", err, b)
		}
		return *r.Task
	}
	if st := send().Status.State; st != wire.StateAuthRequired {
		t.Fatalf("auth required: %s", st)
	}
	s.SetFaults(Faults{Fail: true})
	if st := send().Status.State; st != wire.StateFailed {
		t.Fatalf("fail: %s", st)
	}
	s.SetFaults(Faults{OversizeBytes: 4096})
	if tk := send(); len(*tk.Artifacts[0].Parts[0].Text) != 4096 {
		t.Fatalf("oversize: %d", len(*tk.Artifacts[0].Parts[0].Text))
	}
}
