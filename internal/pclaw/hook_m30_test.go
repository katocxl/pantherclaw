// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeEvent is Claude Code's PreToolUse input for a write tool.
func writeEvent(tool, file, cwd, id string) string {
	key := "file_path"
	if tool == "NotebookEdit" {
		key = "notebook_path"
	}
	b, _ := json.Marshal(map[string]any{
		"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd, "tool_use_id": id,
		"tool_input": map[string]any{key: file, "content": "x"},
	})
	return string(b)
}

// TestHR712_ProtectedWritesAskTheGatewayOrdinaryWritesDoNot: a write to a
// listed configuration or memory file is posted to /hook/{connection} as
// agent_config op write with its project-relative path, class, base and
// tool call id, and the gateway's refusal (no grant names
// agent_config.write) blocks it. A write to any other file is answered
// locally: nothing is sent and nothing is printed, so Claude Code's own
// rules decide it (G0 M30 D943).
func TestHR712_ProtectedWritesAskTheGatewayOrdinaryWritesDoNot(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		req["path"] = r.URL.Path
		mu.Lock()
		bodies = append(bodies, req)
		mu.Unlock()
		_, _ = io.WriteString(w, `{"decision":"deny","reason":"PantherClaw denied this call: not_granted. Transaction t-9.","mode":"enforce"}`)
	}))
	t.Cleanup(gw.Close)
	env := hookEnv(t, gw.URL)
	dir := t.TempDir()
	final, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	code, out, errs := runHook(t, env, writeEvent("Edit", filepath.Join(dir, "CLAUDE.md"), dir, "toolu_07"))
	if code != 2 || out != "" || !strings.Contains(errs, "not_granted") {
		t.Fatalf("protected write: %d %q %q", code, out, errs)
	}
	mu.Lock()
	if len(bodies) != 1 {
		mu.Unlock()
		t.Fatalf("%d requests", len(bodies))
	}
	got := bodies[0]
	mu.Unlock()
	in, _ := got["input"].(map[string]any)
	if got["path"] != "/hook/shell" || got["tool"] != "agent_config" || in["op"] != "write" || in["path"] != "CLAUDE.md" ||
		in["class"] != "memory" || in["cwd"] != final || in["call"] != "toolu_07" {
		t.Fatalf("request %v", got)
	}

	for _, file := range []string{filepath.Join(dir, "main.go"), filepath.Join(dir, "docs", "CLAUDE.md.bak")} {
		code, out, errs = runHook(t, env, writeEvent("Write", file, dir, "toolu_08"))
		if code != 0 || out != "" || errs != "" {
			t.Errorf("ordinary write %s: %d %q %q", file, code, out, errs)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("an ordinary write asked the gateway: %d requests", len(bodies))
	}
}
