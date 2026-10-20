// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pca2a_test

import (
	"encoding/json/v2"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	pca2a "github.com/katocxl/pantherclaw/packages/pc-a2a"
)

var tc = mapping.Context{
	Org: "01920000-0000-7000-8000-000000000001", Env: "01920000-0000-7000-8000-000000000002",
	RunID: "01920000-0000-7000-8000-000000000003", ActionID: "01920000-0000-7000-8000-000000000004",
	AgentInstance: "01920000-0000-7000-8000-000000000005", Connection: "01920000-0000-7000-8000-000000000006",
}

// TestPackageMapsEveryMethodToItsRoute (G0 M14 D32): the package decodes,
// each A2A method maps to its own route and operation, and the message
// text is a disclosure content param, never untrusted text (D70, HR-023).
func TestPackageMapsEveryMethodToItsRoute(t *testing.T) {
	p, err := manifest.Decode(pca2a.Package)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != pca2a.Name || p.Version != pca2a.Version {
		t.Fatalf("package %s %s", p.Name, p.Version)
	}
	send, ok := p.Definition("a2a.message.send")
	if !ok || send.Params["text"].Type != "content" || !send.Params["text"].Disclosure || send.Params["text"].MaxBytes != 32768 {
		t.Fatalf("message text: %+v", send.Params["text"])
	}
	// Reading a peer's task is a read, which never consults the peer check
	// (D111); sending and cancelling are writes it decides.
	for op, access := range map[string]string{"a2a.message.send": "write", "a2a.task.read": "read", "a2a.task.cancel": "write"} {
		if d, ok := p.Definition(op); !ok || string(d.Access) != access {
			t.Errorf("%s: access %v, want %s", op, d, access)
		}
	}
	m, err := mapping.New(p, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	msg := `{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"refund ch_1"}],"metadata":{"skill":"refunds"},"contextId":"ctx-1"}}`
	for _, c := range []struct{ method, params, op, route, want string }{
		{"SendMessage", msg, "a2a.message.send", "a2a-send", `{"context_id":"ctx-1","skill":"refunds","text":"refund ch_1"}`},
		{"SendStreamingMessage", msg, "a2a.message.send", "a2a-stream", `{"context_id":"ctx-1","skill":"refunds","text":"refund ch_1"}`},
		{"GetTask", `{"id":"task-1"}`, "a2a.task.read", "a2a-task-get", `{"task_id":"task-1"}`},
		{"SubscribeToTask", `{"id":"task-1"}`, "a2a.task.read", "a2a-task-subscribe", `{"task_id":"task-1"}`},
		{"ListTasks", `{"contextId":"ctx-1"}`, "a2a.task.read", "a2a-task-list", `{"context_id":"ctx-1"}`},
		{"CancelTask", `{"id":"task-1"}`, "a2a.task.cancel", "a2a-task-cancel", `{"task_id":"task-1"}`},
	} {
		got, err := m.A2A(t.Context(), tc, c.method, []byte(c.params))
		if err != nil {
			t.Errorf("%s: %v", c.method, err)
			continue
		}
		a := got.Action
		params, _ := json.Marshal(a.Params)
		if a.Operation != c.op || a.Route != c.route || a.Channel != "a2a" || a.Target.ID != "peer" || string(params) != c.want {
			t.Errorf("%s: %s %s %s %s %s", c.method, a.Operation, a.Route, a.Channel, a.Target.ID, params)
		}
	}
	// A message without a skill does not map.
	if _, err := m.A2A(t.Context(), tc, "SendMessage", []byte(`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"x"}]}}`)); err == nil {
		t.Error("a message without a skill mapped")
	}
}
