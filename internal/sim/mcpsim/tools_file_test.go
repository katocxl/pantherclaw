// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mcpsim

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ticketsFile = `{"tools": [{
  "name": "close_ticket", "description": "Close a ticket.",
  "inputSchema": {"type": "object", "properties": {"ticket": {"type": "string"}}},
  "results": [
    {"when": {"ticket": "T-1"}, "result": {"status": "closed", "simulated": false}},
    {"when": {"ticket": "T-2", "note": {"b": 1, "a": 2}}, "result": {"status": "closed"}, "echo_args": true}
  ],
  "default": {"result": {"error": "not_found"}, "is_error": true}
}, {
  "name": "list_tickets", "description": "", "inputSchema": {"type": "object"}
}]}`

func structured(t *testing.T, res map[string]any) map[string]jsontext.Value {
	t.Helper()
	var out map[string]jsontext.Value
	if err := json.Unmarshal(res["structuredContent"].(jsontext.Value), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestHR468_ToolsFileIsDataAndEveryAnswerIsSimulated: a tools file is
// strict data within limits; a call is answered only by an exact match of
// its arguments (in canonical form) or the default, with nothing computed
// but an echo of the arguments; every answer is marked simulated, even one
// the file says is not (G0 M17 D126).
// Covers: PN-009.6
func TestHR468_ToolsFileIsDataAndEveryAnswerIsSimulated(t *testing.T) {
	tools, err := ParseToolsFile([]byte(ticketsFile))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Faults{Tools: tools})
	var listed []string
	for _, v := range s.Tools() {
		var n struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(v, &n)
		listed = append(listed, n.Name)
	}
	if strings.Join(listed, ",") != "create_refund,get_refund,close_ticket,list_tickets" {
		t.Fatalf("tools/list = %v", listed)
	}

	call := func(args string) map[string]any {
		t.Helper()
		res, rpcErr := s.call(t.Context(), jsontext.Value(`{"name":"close_ticket","arguments":`+args+`}`))
		if rpcErr != nil {
			t.Fatalf("%s: %v", args, rpcErr)
		}
		return res
	}
	res := call(`{"ticket":"T-1"}`)
	if got := structured(t, res); res["isError"] != false || string(got["status"]) != `"closed"` || string(got["simulated"]) != "true" {
		t.Fatalf("T-1: %v", res)
	}
	// Member order and spacing do not matter; the arguments come back as given.
	res = call(`{ "note": {"a": 2, "b": 1}, "ticket": "T-2" }`)
	if got := structured(t, res); string(got["args"]) != `{"note":{"a":2,"b":1},"ticket":"T-2"}` || string(got["simulated"]) != "true" {
		t.Fatalf("T-2: %v", res)
	}
	// No match: the default, still simulated; nothing is templated in.
	res = call(`{"ticket":"T-3"}`)
	if got := structured(t, res); res["isError"] != true || string(got["error"]) != `"not_found"` || got["args"] != nil || string(got["simulated"]) != "true" {
		t.Fatalf("T-3: %v", res)
	}
	// A tool without results or default fails, simulated.
	res, _ = s.call(t.Context(), jsontext.Value(`{"name":"list_tickets"}`))
	if got := structured(t, res); res["isError"] != true || string(got["error"]) != `"no_simulated_result"` || string(got["simulated"]) != "true" {
		t.Fatalf("list_tickets: %v", res)
	}
	if s.Calls() != 4 {
		t.Fatalf("calls = %d", s.Calls())
	}

	many := make([]string, MaxFileTools+1)
	for i := range many {
		many[i] = fmt.Sprintf(`{"name":"t%d","description":"","inputSchema":{}}`, i)
	}
	for name, doc := range map[string]string{
		"unknown member":     `{"tools":[{"name":"a","description":"","inputSchema":{},"run":"sh"}]}`,
		"no tools":           `{"tools":[]}`,
		"too many tools":     `{"tools":[` + strings.Join(many, ",") + `]}`,
		"too large":          `{"tools":[{"name":"a","description":"` + strings.Repeat("x", MaxToolsFileBytes) + `","inputSchema":{}}]}`,
		"a built-in":         `{"tools":[{"name":"create_refund","description":"","inputSchema":{}}]}`,
		"twice":              `{"tools":[{"name":"a","description":"","inputSchema":{}},{"name":"a","description":"","inputSchema":{}}]}`,
		"bad name":           `{"tools":[{"name":"a b","description":"","inputSchema":{}}]}`,
		"schema not object":  `{"tools":[{"name":"a","description":"","inputSchema":"x"}]}`,
		"result not object":  `{"tools":[{"name":"a","description":"","inputSchema":{},"results":[{"when":{},"result":"ok"}]}]}`,
		"when not object":    `{"tools":[{"name":"a","description":"","inputSchema":{},"results":[{"when":[1],"result":{}}]}]}`,
		"duplicate when":     `{"tools":[{"name":"a","description":"","inputSchema":{},"results":[{"when":{"x":1},"result":{}},{"when":{ "x" : 1 },"result":{}}]}]}`,
		"default not object": `{"tools":[{"name":"a","description":"","inputSchema":{},"default":{"result":1}}]}`,
	} {
		if _, err := ParseToolsFile([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A tools file on disk is a regular file.
	dir := t.TempDir()
	path := filepath.Join(dir, "tools.json")
	if err := os.WriteFile(path, []byte(ticketsFile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToolsFile(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadToolsFile(dir); err == nil {
		t.Error("a directory was loaded as a tools file")
	}
}
