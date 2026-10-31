// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"encoding/json/v2"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// kitEnv points the platform's managed settings at an empty directory, which
// it returns, so the machine's own are never read.
func kitEnv(t *testing.T) (Env, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "platform")
	old := managedSettingsDir
	managedSettingsDir = dir
	t.Cleanup(func() { managedSettingsDir = old })
	return envOf(map[string]string{}), dir
}

const kitAllow = `{"servers":[
	{"name":"docs","url":"https://mcp.example.test/docs"},
	{"name":"pw","command":["npx","@playwright/mcp@1.2.3"]},
	{"name":"tickets","command":"tickets-mcp"}
]}`

func writeAllow(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "allow.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func parsed(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return v
}

// TestF850_ClaudeCodeKit: the files use the vendor's key names, and what they
// hold is the hook init recognises, which managed settings allowing only
// managed hooks leave running.
//
// Covers: F850
func TestF850_ClaudeCodeKit(t *testing.T) {
	env, _ := kitEnv(t)
	out := filepath.Join(t.TempDir(), "kit")
	code, stdout, errs := run(t, env, "managed-settings", "generate", "--client", "claude-code", "--allow-file", writeAllow(t, kitAllow), "--out", out)
	if code != 0 {
		t.Fatalf("generate = %d %q %q", code, stdout, errs)
	}
	s, err := readSettings("managed", filepath.Join(out, "managed-settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.doc.get("allowManagedHooksOnly").bool() || !hookRuns(s.doc) {
		t.Fatalf("hook not pinned: %s", s.raw)
	}
	if err := managedBlocked([]claudeSettings{s}); err != nil {
		t.Fatalf("the kit blocks its own hook: %v", err)
	}
	if managedState([]claudeSettings{s}) != managedPresent {
		t.Fatal("the kit's file is not present")
	}
	wantAllow := parsed(t, []byte(`[{"serverUrl":"https://mcp.example.test/docs"},
		{"serverCommand":["npx","@playwright/mcp@1.2.3"]},{"serverCommand":["tickets-mcp"]}]`))
	if got := parsed(t, s.raw).(map[string]any)["allowedMcpServers"]; !reflect.DeepEqual(got, wantAllow) {
		t.Fatalf("allowedMcpServers = %v", got)
	}
	want := parsed(t, []byte(`{"mcpServers":{
		"docs":{"type":"http","url":"https://mcp.example.test/docs"},
		"pw":{"type":"stdio","command":"npx","args":["@playwright/mcp@1.2.3"]},
		"tickets":{"type":"stdio","command":"tickets-mcp"}}}`))
	raw, err := os.ReadFile(filepath.Join(out, "managed-mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed(t, raw); !reflect.DeepEqual(got, want) {
		t.Fatalf("managed-mcp.json = %v", got)
	}
	if !strings.Contains(errs, "PANTHERCLAW_GATEWAY") || !strings.Contains(errs, "no coverage state") {
		t.Fatalf("notes: %q", errs)
	}
}

// TestF850_CopilotKit: one managed-settings.json with an allow and a deny
// list, on stdout when no --out is given; stdout is the file alone.
//
// Covers: F850
func TestF850_CopilotKit(t *testing.T) {
	env, _ := kitEnv(t)
	code, stdout, errs := run(t, env, "managed-settings", "generate", "--client", "copilot", "--allow-file", writeAllow(t, kitAllow))
	if code != 0 {
		t.Fatalf("generate = %d %q %q", code, stdout, errs)
	}
	want := parsed(t, []byte(`{"allowedMcpServers":[{"serverUrl":"https://mcp.example.test/docs"},
		{"serverCommand":["npx","@playwright/mcp@1.2.3"]},{"serverCommand":["tickets-mcp"]}],"deniedMcpServers":[]}`))
	if got := parsed(t, []byte(stdout)); !reflect.DeepEqual(got, want) {
		t.Fatalf("stdout = %v", got)
	}
}

// TestF850_NoAllowFileAllowsNoServer: with no allow file the list is empty,
// not missing, which would allow every server, and the kit says what it does.
//
// Covers: F850
func TestF850_NoAllowFileAllowsNoServer(t *testing.T) {
	env, _ := kitEnv(t)
	code, stdout, errs := run(t, env, "managed-settings", "generate", "--client", "claude-code")
	if code != 0 || !strings.Contains(errs, "blocks every MCP server") {
		t.Fatalf("generate = %d %q %q", code, stdout, errs)
	}
	if !strings.Contains(stdout, "# managed-settings.json") || !strings.Contains(stdout, "# managed-mcp.json") ||
		!strings.Contains(stdout, `"allowedMcpServers": []`) {
		t.Fatalf("stdout: %s", stdout)
	}
}

// TestF850_RefusesWhatItCannotPin: a file or usage that would not pin the
// servers it names writes nothing.
//
// Covers: F850
func TestF850_RefusesWhatItCannotPin(t *testing.T) {
	env, _ := kitEnv(t)
	for name, content := range map[string]string{
		"unknown member": `{"servers":[{"name":"a","url":"https://a.test","env":{"K":"v"}}]}`,
		"both":           `{"servers":[{"name":"a","url":"https://a.test","command":"x"}]}`,
		"neither":        `{"servers":[{"name":"a"}]}`,
		"no name":        `{"servers":[{"url":"https://a.test"}]}`,
		"bad name":       `{"servers":[{"name":"a b","url":"https://a.test"}]}`,
		"twice":          `{"servers":[{"name":"a","url":"https://a.test"},{"name":"a","url":"https://b.test"}]}`,
		"credential":     `{"servers":[{"name":"a","url":"https://u:p@a.test"}]}`,
		"query":          `{"servers":[{"name":"a","url":"https://a.test/?token=x"}]}`,
		"wildcard":       `{"servers":[{"name":"a","url":"https://a.test/*"}]}`,
		"scheme":         `{"servers":[{"name":"a","url":"ftp://a.test"}]}`,
		"empty arg":      `{"servers":[{"name":"a","command":["x",""]}]}`,
		"number":         `{"servers":[{"name":"a","command":1}]}`,
		"not json":       `{`,
	} {
		out := filepath.Join(t.TempDir(), "kit")
		code, _, errs := run(t, env, "managed-settings", "generate", "--client", "copilot", "--allow-file", writeAllow(t, content), "--out", out)
		if code == 0 {
			t.Errorf("%s: accepted: %q", name, errs)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("%s: wrote to --out", name)
		}
	}
	for _, args := range [][]string{{"--client", "cursor"}, {}, {"--client", "copilot", "extra"}} {
		if code, _, _ := run(t, env, append([]string{"managed-settings", "generate"}, args...)...); code == 0 {
			t.Errorf("%v: accepted", args)
		}
	}
}

// TestHR567_TheKitNeverWritesAManagedLocation: --out in a managed location,
// under one, in another spelling of one, through a link to one, or over a
// file that links into one is refused and writes nothing.
//
// Covers: F850
func TestHR567_TheKitNeverWritesAManagedLocation(t *testing.T) {
	env, platform := kitEnv(t)
	if err := os.MkdirAll(platform, 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dirs := []string{
		platform,
		filepath.Join(platform, "managed-settings.d"),
		filepath.Join(platform, "sub", ".."),
		filepath.Join(root, ".github-private", "copilot"),
	}
	links := true
	dirLink, fileLink := filepath.Join(root, "link"), filepath.Join(root, "kit", "managed-settings.json")
	if err := os.Symlink(platform, dirLink); err != nil {
		links = false // Windows without the privilege to make links
		t.Log("no links here: ", err)
	} else {
		dirs = append(dirs, dirLink, filepath.Join(dirLink, "sub"))
	}
	for _, client := range []string{"claude-code", "copilot"} {
		for _, dir := range dirs {
			code, _, errs := run(t, env, "managed-settings", "generate", "--client", client, "--out", dir)
			if code == 0 || !strings.Contains(errs, "managed location") {
				t.Errorf("%s --out %s = %d %q", client, dir, code, errs)
			}
		}
	}
	if links {
		if err := os.MkdirAll(filepath.Dir(fileLink), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(platform, "managed-settings.json"), fileLink); err != nil {
			t.Fatal(err)
		}
		// The target does not exist yet, so the link cannot be followed either.
		if code, _, errs := run(t, env, "managed-settings", "generate", "--client", "copilot", "--out", filepath.Dir(fileLink)); code == 0 {
			t.Errorf("wrote through a link to a managed file: %q", errs)
		}
		if err := os.WriteFile(filepath.Join(platform, "managed-settings.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _, errs := run(t, env, "managed-settings", "generate", "--client", "copilot", "--out", filepath.Dir(fileLink)); code == 0 ||
			!strings.Contains(errs, "managed location") {
			t.Errorf("wrote through a link to a managed file: %q", errs)
		}
	}
	err := filepath.WalkDir(platform, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() != "managed-settings.json" {
			t.Errorf("wrote %s", p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(platform, "managed-settings.json")); links && (err != nil || string(b) != "{}") {
		t.Errorf("the managed file changed: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".github-private")); !os.IsNotExist(err) {
		t.Error("wrote into a checkout of the managed repository")
	}
	for _, dir := range vendorManagedDirs {
		if !(&app{env: envOf(nil)}).inManagedLocation(filepath.Join(dir, "sub")) {
			t.Errorf("%s is not a managed location", dir)
		}
	}
}

// TestHR567_NothingCoverageReadsTheManagedState: no coverage code reads the
// attribute or the kit's files, so generating or finding managed settings
// cannot raise a coverage state (F801). The server side is
// TestHR567_ManagedSettingsFindingsRaiseNoCoverage.
//
// Covers: F801, F852
func TestHR567_NothingCoverageReadsTheManagedState(t *testing.T) {
	err := filepath.WalkDir(filepath.Join("..", "coverage"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // G304: a file of this repository
		if err != nil {
			return err
		}
		for _, word := range []string{managedSettingsAttr, "managed-settings", "allowManagedHooksOnly"} {
			if strings.Contains(string(b), word) {
				t.Errorf("%s reads %s", p, word)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestF851_InitReportsTheManagedState: init names the state and what it
// cannot read, whichever the state is, and a conflict stays a refusal.
//
// Covers: F851
func TestF851_InitReportsTheManagedState(t *testing.T) {
	const limits = "registry, MDM and server-managed settings cannot be read here"
	hook := `{"allowManagedHooksOnly":true,"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"pclaw","args":["hook","claude-code"],"onFailure":"block"}]}]}}`
	for _, c := range []struct {
		name, content, state string
		code                 int
	}{
		{"none", "", "not_found", 0},
		{"plain", `{"permissions":{"deny":["Read(./.env)"]}}`, "present", 0},
		{"the hook", hook, "present", 0},
		{"hooks off", `{"disableAllHooks":true}`, "conflict", 1},
		{"only managed hooks", `{"allowManagedHooksOnly":true}`, "conflict", 1},
	} {
		f := newInitFixture(t)
		if c.content != "" {
			f.write(t, filepath.Join(f.platform, "managed-settings.json"), c.content)
		}
		code, out, errs := f.run(t, "--dry-run")
		if code != c.code && c.code != 0 {
			t.Errorf("%s: exit %d, want %d: %q", c.name, code, c.code, errs)
		}
		if !strings.Contains(out, "managed state: "+c.state+" (") || !strings.Contains(out, limits) || !strings.Contains(out, "not coverage") {
			t.Errorf("%s: %q", c.name, out)
		}
	}
}

// TestF852_ScanCarriesTheManagedState: every submitted finding has the
// attribute, the text says what it cannot read, and the state follows the
// machine.
//
// Covers: F852
func TestF852_ScanCarriesTheManagedState(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		".mcp.json":    `{"mcpServers": {"tickets": {"command": "python"}}}`,
		"package.json": `{"dependencies": {"@openai/agents": "1"}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rec := &recordScan{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterAgentServiceHandler(cs, rec)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	_, platform := kitEnv(t)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})
	for _, c := range []struct{ content, state string }{
		{"", managedNotFound},
		{`{"permissions":{}}`, managedPresent},
		{`{"disableAllHooks":true}`, managedConflict},
		{`not json`, managedConflict},
	} {
		if c.content != "" {
			if err := os.MkdirAll(platform, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(platform, "managed-settings.json"), []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		code, out, errs := run(t, env, "scan", "--path", dir, "--no-user-config", "--no-env", "--submit")
		if code != 0 || !strings.Contains(out, "Managed settings: "+c.state) || !strings.Contains(out, "cannot be read here") {
			t.Fatalf("scan = %d %q %q", code, out, errs)
		}
		if len(rec.req.GetFindings()) != 2 {
			t.Fatalf("%d findings", len(rec.req.GetFindings()))
		}
		for _, f := range rec.req.GetFindings() {
			if got := f.GetAttributes()[managedSettingsAttr]; got != c.state {
				t.Errorf("%s finding: managed_settings %q, want %q", f.GetKind(), got, c.state)
			}
		}
	}
}
