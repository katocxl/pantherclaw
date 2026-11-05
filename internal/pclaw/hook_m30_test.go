// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

// TestHR712_CaseAndUserScopeWritesAskTheGateway (G0 M30 D1215): a project
// file named in another case (claude.md, .Claude/Settings.json), the
// user's memory (~/.claude/CLAUDE.md), the user's Claude Code settings
// (~/.claude.json) and a configuration-directory entry
// (Claude/claude_desktop_config.json) each ask the gateway with their path
// relative to their own base, and the gateway's refusal blocks them.
func TestHR712_CaseAndUserScopeWritesAskTheGateway(t *testing.T) {
	var mu sync.Mutex
	var asked []map[string]any
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		in, _ := req["input"].(map[string]any)
		mu.Lock()
		asked = append(asked, in)
		mu.Unlock()
		_, _ = io.WriteString(w, `{"decision":"deny","reason":"PantherClaw denied this call: not_granted. Transaction t-9.","mode":"enforce"}`)
	}))
	t.Cleanup(gw.Close)
	env := hookEnv(t, gw.URL)
	home, project := t.TempDir(), t.TempDir()
	for _, k := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(k, home)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData", "Roaming"))
	config, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "CLAUDE.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ file, path, class string }{
		{filepath.Join(project, "claude.md"), "claude.md", "memory"},
		{filepath.Join(project, ".Claude", "Settings.json"), ".Claude/Settings.json", "settings"},
		{filepath.Join(home, ".claude", "CLAUDE.md"), ".claude/CLAUDE.md", "memory"},
		{filepath.Join(home, ".claude.json"), ".claude.json", "settings"},
		{filepath.Join(config, "Claude", "claude_desktop_config.json"), "Claude/claude_desktop_config.json", "mcp"},
	}
	for i, c := range cases {
		code, out, errs := runHook(t, env, writeEvent("Write", c.file, project, "toolu_2"+itoa(int64(i))))
		if code != 2 || out != "" || !strings.Contains(errs, "not_granted") {
			t.Errorf("%s: %d %q %q", c.file, code, out, errs)
			continue
		}
		mu.Lock()
		in := asked[len(asked)-1]
		mu.Unlock()
		if !strings.EqualFold(in["path"].(string), c.path) || in["class"] != c.class {
			t.Errorf("%s: asked %v, want %s %s", c.file, in, c.path, c.class)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(asked) != len(cases) {
		t.Fatalf("%d asks for %d writes", len(asked), len(cases))
	}
}

// TestHR712_AnExistingFileTakesItsOnDiskSpelling (G0 M30 D1215): the
// spelling macOS resolution uses takes each existing name as its directory
// spells it and keeps the names that do not exist yet.
func TestHR712_AnExistingFileTakesItsOnDiskSpelling(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := onDiskSpelling(filepath.Join(dir, ".Claude", "Settings.json")), filepath.Join(dir, ".claude", "settings.json"); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if got, want := onDiskSpelling(filepath.Join(dir, ".Claude", "New", "x.json")), filepath.Join(dir, ".claude", "New", "x.json"); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
