// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package client_test

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"testing"

	"github.com/katocxl/pantherclaw/sdk/go/client"
	"github.com/katocxl/pantherclaw/sdk/go/internal/vectors"
	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

type faceFile struct {
	Connection string   `json:"connection"`
	Servers    []string `json:"servers"`
	Builtins   []string `json:"builtins"`
	Calls      []struct {
		Name      string         `json:"name"`
		Tool      string         `json:"tool"`
		Input     jsontext.Value `json:"input"`
		ToolUseID string         `json:"tool_use_id"`
		Class     string         `json:"class"`
		Path      string         `json:"path"`
		Body      jsontext.Value `json:"body"`
	} `json:"calls"`
	Answers []struct {
		Name      string            `json:"name"`
		Class     string            `json:"class"`
		Status    int               `json:"status"`
		Headers   map[string]string `json:"headers"`
		Body      string            `json:"body"`
		ActionID  string            `json:"action_id"`
		FirstHash string            `json:"first_hash"`
		Outcome   string            `json:"outcome"`
		Send      *struct {
			Method  string            `json:"method"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Body    string            `json:"body"`
		} `json:"send"`
	} `json:"answers"`
}

// TestHR201_ConformanceAnswers: every answer of the /sdk contract gets its
// outcome. The SDK checks the action id, the hash against the canonical
// sdk-channel action and a resubmission's hash against the first, lets an
// observe answer run only a built-in, and sends a target-enforced
// connection's request exactly; anything unreadable or unchecked is
// cannot_decide (HR-200).
func TestHR201_ConformanceAnswers(t *testing.T) {
	var f faceFile
	vectors.Load(t, "sdk_face.json", &f)
	for _, a := range f.Answers {
		h := http.Header{}
		for k, v := range a.Headers {
			h.Set(k, v)
		}
		got := client.Retry(a.Status, h)
		var res client.Result
		if got == "" {
			res = client.Evaluate(a.Status, h, []byte(a.Body), client.Class(a.Class), a.ActionID, a.FirstHash)
			got = string(res.Outcome)
		}
		if got != a.Outcome {
			t.Errorf("%s: %s (%s), want %s", a.Name, got, res.Why, a.Outcome)
			continue
		}
		switch {
		case a.Send == nil && res.Send != nil:
			t.Errorf("%s: a request to send", a.Name)
		case a.Send != nil && res.Send == nil:
			t.Errorf("%s: no request to send", a.Name)
		case a.Send != nil:
			s := res.Send
			if s.Method != a.Send.Method || s.URL != a.Send.URL || string(s.Body) != a.Send.Body || len(s.Header) != len(a.Send.Headers) {
				t.Errorf("%s: sends %s %s %q %v", a.Name, s.Method, s.URL, s.Body, s.Header)
			}
			for k, v := range a.Send.Headers {
				if s.Header.Get(k) != v {
					t.Errorf("%s: header %s is %q, want %q", a.Name, k, s.Header.Get(k), v)
				}
			}
		}
	}
}

// TestHR200_ConformanceCalls: an MCP tool of a configured server is sent
// with its server to the connection named after it, a built-in without one
// to the connection that records it, and any other name is refused without
// a request; the request body is the raw call, {tool, server, input,
// tool_use_id}, nothing the SDK computed (HR-201).
func TestHR200_ConformanceCalls(t *testing.T) {
	var f faceFile
	vectors.Load(t, "sdk_face.json", &f)
	fk := newFake(t)
	var path string
	var body []byte
	fk.sdk = func(w http.ResponseWriter, r *http.Request, b []byte) {
		path, body = r.URL.Path, b
		answer(w, map[string]any{"decision": "deny", "reason": "recorded", "mode": "enforce", "coverage": "PARTIAL"})
	}
	k := fk.key
	k.Server = fk.srv.URL
	cl, err := client.New(client.Config{Key: k, Gateway: fk.srv.URL, RunID: runID, Builtins: f.Builtins})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Calls {
		server, class := client.Classify(c.Tool, f.Servers, f.Builtins)
		if string(class) != c.Class {
			t.Errorf("%s: %s, want %s", c.Name, class, c.Class)
			continue
		}
		path, body = "", nil
		call := client.ToolCall{Tool: c.Tool, Server: server, Input: c.Input, ToolUseID: c.ToolUseID}
		res := cl.Authorize(context.Background(), f.Connection, call, client.NewActionID())
		if class == client.Refused {
			if path != "" || res.Outcome != client.CannotDecide {
				t.Errorf("%s: sent to %q (%s)", c.Name, path, res.Outcome)
			}
			continue
		}
		a, err1 := pap.Canonical(body)
		b, err2 := pap.Canonical(c.Body)
		if path != c.Path || err1 != nil || err2 != nil || string(a) != string(b) {
			t.Errorf("%s: sends %s to %s, want %s to %s", c.Name, body, path, c.Body, c.Path)
		}
	}
}

// TestHR201_ADispatchInClearTextIsRefused: the request to send must use
// https, or http only to this machine, as the client's own URLs must.
func TestHR201_ADispatchInClearTextIsRefused(t *testing.T) {
	var f faceFile
	vectors.Load(t, "sdk_face.json", &f)
	for _, a := range f.Answers {
		if a.Send == nil {
			continue
		}
		for u, want := range map[string]client.Outcome{
			"http://payments.example.test/v1/refunds": client.CannotDecide,
			"http://127.0.0.1:8080/v1/refunds":        client.Allow,
		} {
			var body map[string]any
			if err := json.Unmarshal([]byte(a.Body), &body); err != nil {
				t.Fatal(err)
			}
			body["dispatch"].(map[string]any)["url"] = u
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if got := client.Evaluate(a.Status, http.Header{}, b, client.Class(a.Class), a.ActionID, a.FirstHash); got.Outcome != want {
				t.Errorf("%s: %s (%s), want %s", u, got.Outcome, got.Why, want)
			}
		}
	}
}
