// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func (f *initFixture) mcpJSON() string { return filepath.Join(f.project, ".mcp.json") }

func (f *initFixture) state() string { return filepath.Join(f.home, ".claude.json") }

// member reads a value under the given members of a JSON file.
func member(t *testing.T, path string, at ...string) any {
	t.Helper()
	v := any(readJSON(t, path))
	for _, k := range at {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	return v
}

// githubToken is a literal token in an MCP server's environment.
var githubToken = "ghp_" + strings.Repeat("0123456789ab", 3) // built at run time: no token-like literal in the source

// claudeState is ~/.claude.json with the project's own GitHub server,
// holding a token in its environment, as Claude Code writes it.
func (f *initFixture) claudeState() string {
	project, _ := json.Marshal(f.project)
	return `{
  "numStartups": 3,
  "projects": {
    ` + string(project) + `: {
      "allowedTools": [],
      "mcpServers": {
        "github": {
          "type": "stdio",
          "command": "npx",
          "args": [
            "-y",
            "@modelcontextprotocol/server-github"
          ],
          "env": {
            "GITHUB_PERSONAL_ACCESS_TOKEN": "` + githubToken + `"
          }
        }
      }
    }
  }
}`
}

// TestHR208_InitGovernsAnMCPServerWithANewEntryAndADenyRule: --mcp leaves
// the original entry as it is, byte for byte, adds the governed entry
// pantherclaw-NAME that runs pclaw mcp proxy to the connection, and adds
// the deny rule mcp__NAME__* to the scope's settings; both files are
// backed up and their diffs shown. The token in the original's
// environment is reported by name as a route and never copied or shown.
// A second run changes nothing.
func TestHR208_InitGovernsAnMCPServerWithANewEntryAndADenyRule(t *testing.T) {
	f := newInitFixture(t)
	f.write(t, f.state(), f.claudeState())
	f.write(t, f.local(), existingLocal)
	original := member(t, f.state(), "projects", f.project, "mcpServers", "github")
	code, out, errs := f.run(t, "--mcp", "github=github-sdk")
	if code != 0 {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	if got := member(t, f.state(), "projects", f.project, "mcpServers", "github"); !reflect.DeepEqual(got, original) {
		t.Fatalf("the original entry changed: %v", got)
	}
	governed, _ := member(t, f.state(), "projects", f.project, "mcpServers", "pantherclaw-github").(map[string]any)
	want := []any{"mcp", "proxy", "--gateway", "https://gw.example.test", "--connection", "github-sdk", "--key-file", f.key}
	if governed["command"] != "pclaw" || !reflect.DeepEqual(governed["args"], want) || len(governed) != 3 {
		t.Fatalf("governed entry %v", governed)
	}
	if deny, _ := member(t, f.local(), "permissions", "deny").([]any); !slices.Equal(deny, []any{"Bash(curl:*)", "Read(./.env)", "mcp__github__*"}) {
		t.Fatalf("deny rules %v", deny)
	}
	for _, p := range []string{f.state(), f.local()} {
		if len(backups(t, p)) != 1 || !strings.Contains(out, "--- "+p) {
			t.Errorf("%s: not backed up or no diff", p)
		}
	}
	if !strings.Contains(out, "GITHUB_PERSONAL_ACCESS_TOKEN") || strings.Contains(out, githubToken[4:]) {
		t.Errorf("the token is not reported by name only:\n%s", out)
	}
	if state, _ := os.ReadFile(f.state()); bytes.Count(state, []byte(githubToken)) != 1 {
		t.Error("the token was copied")
	}
	before, _ := os.ReadFile(f.state())
	if code, out, _ := f.run(t, "--mcp", "github=github-sdk"); code != 0 || !strings.Contains(out, "Nothing to change.") {
		t.Fatalf("second run: %d %s", code, out)
	}
	if after, _ := os.ReadFile(f.state()); !bytes.Equal(after, before) || len(backups(t, f.state())) != 1 {
		t.Fatal("the second run changed ~/.claude.json")
	}
}

// TestHR208_InitNeverReplacesAServerEntry: a different entry with the
// governed name, in any scope, is a failure that changes nothing; a
// project Claude Code has not run in gets no invented entry; --scope
// project and user write .mcp.json and ~/.claude.json's top level; and a
// file init only read keeps its layout.
func TestHR208_InitNeverReplacesAServerEntry(t *testing.T) {
	f := newInitFixture(t)
	const docs = "{\n    \"mcpServers\": {\"pantherclaw-docs\": {\"command\": \"docs-server\"}}\n}\n"
	f.write(t, f.mcpJSON(), docs)
	code, out, errs := f.run(t, "--scope", "user", "--mcp", "docs=docs-sdk")
	if after, _ := os.ReadFile(f.mcpJSON()); code == 0 || !strings.Contains(errs, "never replaces") || string(after) != docs {
		t.Fatalf("a different governed entry: %d %s %s", code, out, errs)
	}
	if _, err := os.Stat(f.state()); err == nil {
		t.Fatal("a refused init wrote ~/.claude.json")
	}
	f.write(t, f.state(), `{"numStartups": 3, "projects": {}}`)
	if code, _, errs := f.run(t, "--mcp", "jira=jira-sdk"); code == 0 || !strings.Contains(errs, "no place for this project") {
		t.Fatalf("an unknown project: %d %s", code, errs)
	}
	if code, out, errs := f.run(t, "--scope", "project", "--mcp", "jira=jira-sdk"); code != 0 ||
		member(t, f.mcpJSON(), "mcpServers", "pantherclaw-jira") == nil || member(t, f.mcpJSON(), "mcpServers", "pantherclaw-docs") == nil {
		t.Fatalf("project: %d %s %s", code, out, errs)
	}
	if code, out, errs := f.run(t, "--scope", "user", "--mcp", "slack=slack-sdk"); code != 0 || member(t, f.state(), "mcpServers", "pantherclaw-slack") == nil {
		t.Fatalf("user: %d %s %s", code, out, errs)
	}
	for _, bad := range []string{"github", "git hub=x", "github=../x", strings.Repeat("a", 53) + "=x"} {
		if code, _, _ := f.run(t, "--mcp", bad); code == 0 {
			t.Errorf("--mcp %q accepted", bad)
		}
	}
}

// TestHR208_InitRefusesMCPServersClaudeCodeWouldNotRun: a deny list in any
// settings, or an allowlist that leaves the governed server out (managed
// only, when managed settings say so), and managed settings that ignore
// every other scope's permission rules fail without writing.
func TestHR208_InitRefusesMCPServersClaudeCodeWouldNotRun(t *testing.T) {
	for name, tc := range map[string]struct {
		managed, local string
		ok             bool
	}{
		"denied by name":    {local: `{"deniedMcpServers": [{"serverName": "pantherclaw-github"}]}`},
		"denied by managed": {managed: `{"deniedMcpServers": [{"serverName": "pantherclaw-github"}]}`},
		"left out":          {local: `{"allowedMcpServers": [{"serverName": "docs"}]}`},
		"managed only":      {managed: `{"allowManagedMcpServersOnly": true, "allowedMcpServers": [{"serverName": "docs"}]}`},
		"managed rules":     {managed: `{"allowManagedPermissionRulesOnly": true}`},
		"allowed":           {managed: `{"allowedMcpServers": [{"serverName": "pantherclaw-github"}]}`, ok: true},
		"managed denies it": {managed: `{"allowManagedPermissionRulesOnly": true, "permissions": {"deny": ["mcp__github"]}}`, ok: true},
		"managed overrides": {
			managed: `{"allowManagedMcpServersOnly": true, "allowedMcpServers": [{"serverName": "pantherclaw-github"}]}`,
			local:   `{"allowedMcpServers": []}`, ok: true,
		},
	} {
		f := newInitFixture(t)
		if tc.managed != "" {
			f.write(t, f.managed, tc.managed)
		}
		if tc.local != "" {
			f.write(t, f.local(), tc.local)
		}
		code, out, errs := f.run(t, "--scope", "project", "--mcp", "github=github-sdk")
		_, err := os.Stat(f.mcpJSON())
		if (code == 0) != tc.ok || (err == nil) != tc.ok {
			t.Errorf("%s: %d, .mcp.json written %v: %s %s", name, code, err == nil, out, errs)
		}
	}
}

// TestT084_InitPrintsTheAgentSDKSnippetAndWritesNoCode: an Agent SDK
// project gets the integration's snippet on stdout, with the gateway, key
// file and shell connection filled in; its code is not touched.
func TestT084_InitPrintsTheAgentSDKSnippetAndWritesNoCode(t *testing.T) {
	f := newInitFixture(t)
	const pkg = `{"dependencies": {"@anthropic-ai/claude-agent-sdk": "^0.2.0"}}`
	const req = "claude-agent-sdk>=0.1\n"
	f.write(t, filepath.Join(f.project, "app", "package.json"), pkg)
	f.write(t, filepath.Join(f.project, "bot", "requirements.txt"), req)
	code, out, errs := f.run(t)
	if code != 0 || !strings.Contains(out, `PantherClaw.fromKeyFile(`) || !strings.Contains(out, "PantherClaw.from_key_file(") ||
		!strings.Contains(out, "pc.options(") || strings.Contains(out, "pc.hooks") ||
		!strings.Contains(out, `shellConnection: "shell"`) || !strings.Contains(out, `gateway="https://gw.example.test"`) {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(f.project, "app", "package.json")); string(b) != pkg {
		t.Error("package.json changed")
	}
	if b, _ := os.ReadFile(filepath.Join(f.project, "bot", "requirements.txt")); string(b) != req {
		t.Error("requirements.txt changed")
	}
}
