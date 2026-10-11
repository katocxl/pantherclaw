// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

package client_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"testing"

	"github.com/katocxl/pantherclaw/sdk/go/client"
	"github.com/katocxl/pantherclaw/sdk/go/internal/vectors"
	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

type faceFile struct {
	Calls []struct {
		Name  string         `json:"name"`
		Class string         `json:"class"`
		Body  jsontext.Value `json:"body"`
	} `json:"calls"`
	Answers []struct {
		Name      string            `json:"name"`
		Status    int               `json:"status"`
		Headers   map[string]string `json:"headers"`
		Body      string            `json:"body"`
		ActionID  string            `json:"action_id"`
		FirstHash string            `json:"first_hash"`
		Outcome   string            `json:"outcome"`
	} `json:"answers"`
}

// TestHR201_ConformanceAnswers: every answer of the /sdk contract gets its
// outcome. The SDK checks the action id, the hash against the canonical
// action and a resubmission's hash against the first; anything unreadable
// or unchecked is cannot_decide (HR-200).
func TestHR201_ConformanceAnswers(t *testing.T) {
	var f faceFile
	vectors.Load(t, "sdk_face.json", &f)
	for _, a := range f.Answers {
		h := http.Header{}
		for k, v := range a.Headers {
			h.Set(k, v)
		}
		got := client.Retry(a.Status, h)
		if got == "" {
			got = string(client.Evaluate(a.Status, h, []byte(a.Body), a.ActionID, a.FirstHash).Outcome)
		}
		if got != a.Outcome {
			t.Errorf("%s: %s, want %s", a.Name, got, a.Outcome)
		}
	}
}

// TestHR201_ConformanceCallBodies: the request body is the raw call,
// {tool, server, input, tool_use_id, cwd}, nothing the SDK computed.
func TestHR201_ConformanceCallBodies(t *testing.T) {
	var f faceFile
	vectors.Load(t, "sdk_face.json", &f)
	for _, c := range f.Calls {
		if c.Class == "refused" {
			continue
		}
		var call client.ToolCall
		if err := json.Unmarshal(c.Body, &call, json.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		out, err := json.Marshal(call)
		if err != nil {
			t.Fatal(err)
		}
		a, err1 := pap.Canonical(out)
		b, err2 := pap.Canonical(c.Body)
		if err1 != nil || err2 != nil || string(a) != string(b) {
			t.Errorf("%s: sends %s, want %s", c.Name, out, c.Body)
		}
	}
}
