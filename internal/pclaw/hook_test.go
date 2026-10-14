// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHook is a gateway /hook/{connection} endpoint: it allows "ls",
// denies "rm", holds "deploy" and stalls on "slow".
type fakeHook struct {
	*httptest.Server
	mu   sync.Mutex
	reqs []*http.Request
	body []map[string]any
}

func newFakeHook(t *testing.T) *fakeHook {
	t.Helper()
	f := &fakeHook{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tool  string            `json:"tool"`
			Input map[string]string `json:"input"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		f.mu.Lock()
		f.reqs = append(f.reqs, r)
		f.body = append(f.body, map[string]any{"tool": req.Tool, "input": req.Input, "path": r.URL.Path})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch strings.Fields(req.Input["command"])[0] {
		case "ls":
			_, _ = io.WriteString(w, `{"decision":"allow","reason":"PantherClaw allowed this call. Transaction t-1.","transaction_id":"t-1","mode":"enforce"}`)
		case "deploy":
			_, _ = io.WriteString(w, `{"decision":"deny","held":true,"reason":"PantherClaw holds this call for an approval by an eligible person, not by you. Transaction t-2.","mode":"enforce"}`)
		case "slow":
			time.Sleep(time.Second)
			_, _ = io.WriteString(w, `{"decision":"allow","reason":"too late","mode":"enforce"}`)
		default:
			_, _ = io.WriteString(w, `{"decision":"deny","reason":"PantherClaw denied this call: policy_denied (SHELL_DESTRUCTIVE). Transaction t-3.","mode":"enforce"}`)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func hookEvent(tool, command, cwd, id string) string {
	b, _ := json.Marshal(map[string]any{
		"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd, "tool_use_id": id,
		"tool_input": map[string]any{"command": command, "description": "d"},
	})
	return string(b)
}

// runHook runs pclaw hook claude-code with stdin and the env.
func runHook(t *testing.T, env map[string]string, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(context.Background(), append([]string{"hook", "claude-code"}, args...), &out, &errb, envOf(env), Options{Stdin: strings.NewReader(stdin)})
	return code, out.String(), errb.String()
}

func hookEnv(t *testing.T, gateway string) map[string]string {
	t.Helper()
	keyFile, _, run := proxyFiles(t)
	// A cached token with ten minutes left, which the hook uses.
	enc := base64.RawURLEncoding.EncodeToString
	tok := enc([]byte(`{"alg":"EdDSA"}`)) + "." + enc([]byte(`{"exp":`+itoa(time.Now().Add(10*time.Minute).Unix())+`}`)) + ".sig"
	if err := os.WriteFile(keyFile+".token", []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"PANTHERCLAW_GATEWAY": gateway, "PANTHERCLAW_HOOK_CONNECTION": "shell", "PANTHERCLAW_WORKLOAD_KEY_FILE": keyFile, "PANTHERCLAW_RUN": run,
	}
}

// TestHR186_TheHookAllowsOnlyWhatPantherClawAllowed: an allowed command is
// answered with a PreToolUse allow and exit code 0; a denial and a hold
// block it (exit code 2, the reason on stderr), and a hold never asks the
// local user. The request is a PAP/1-signed shell call with the command
// as sent, the shell, the resolved working directory and the tool use id.
func TestHR186_TheHookAllowsOnlyWhatPantherClawAllowed(t *testing.T) {
	f := newFakeHook(t)
	env := hookEnv(t, f.URL)
	dir := t.TempDir()
	code, out, errs := runHook(t, env, hookEvent("Bash", "ls -la  'a b'", dir, "toolu_01"))
	var got struct {
		Out struct {
			Event    string `json:"hookEventName"`
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || got.Out.Event != "PreToolUse" || got.Out.Decision != "allow" ||
		!strings.Contains(got.Out.Reason, "t-1") {
		t.Fatalf("allow = %d %q %q", code, out, errs)
	}
	f.mu.Lock()
	r, b := f.reqs[0], f.body[0]
	f.mu.Unlock()
	in := b["input"].(map[string]string)
	final, _ := filepath.EvalSymlinks(dir)
	if b["path"] != "/hook/shell" || b["tool"] != "shell" || in["shell"] != "bash" || in["command"] != "ls -la  'a b'" ||
		in["cwd"] != final || in["call"] != "toolu_01" || r.Header.Get("PAP-Proof") == "" || r.Header.Get("PAP-Run-Id") != env["PANTHERCLAW_RUN"] ||
		!strings.HasPrefix(r.Header.Get("Authorization"), "PAP ") {
		t.Fatalf("request %v %v", b, r.Header)
	}
	for name, tc := range map[string]struct{ tool, command, want string }{
		"denied":     {"PowerShell", "rm -Recurse x", "SHELL_DESTRUCTIVE"},
		"held":       {"Bash", "deploy prod", "not by you"},
		"other tool": {"Write", "ls", "only the commands Bash, PowerShell and Monitor run"},
		"empty":      {"Bash", "", "empty"},
	} {
		code, out, errs := runHook(t, env, hookEvent(tc.tool, tc.command, dir, "toolu_02"))
		if code != 2 || out != "" || !strings.Contains(errs, tc.want) || strings.Contains(errs, `"ask"`) {
			t.Errorf("%s: %d %q %q", name, code, out, errs)
		}
	}
	// The cases run in map order: find the PowerShell call by its command.
	ps := "not sent"
	f.mu.Lock()
	for _, b := range f.body {
		if in := b["input"].(map[string]string); in["command"] == "rm -Recurse x" {
			ps = in["shell"]
		}
	}
	f.mu.Unlock()
	if ps != "powershell" {
		t.Fatalf("PowerShell sent as %q", ps)
	}
}

// TestHR187_TheHookSendsTheFinalDirectory: a working directory reached
// through a link (on Windows a directory junction, which any user can
// create; a symbolic link elsewhere) is sent as the directory it leads to,
// so a policy on that directory cannot be passed by another spelling of
// it. A directory that cannot be resolved blocks the command and nothing
// is sent.
func TestHR187_TheHookSendsTheFinalDirectory(t *testing.T) {
	f := newFakeHook(t)
	env := hookEnv(t, f.URL)
	dir := t.TempDir()
	forbidden := filepath.Join(dir, "forbidden")
	if err := os.MkdirAll(filepath.Join(forbidden, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "elsewhere")
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, forbidden).CombinedOutput(); err != nil {
			t.Skipf("cannot create a junction: %v %s", err, out)
		}
	} else if err := os.Symlink(forbidden, link); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(filepath.Join(forbidden, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cwd := range []string{filepath.Join(link, "sub"), link + string(filepath.Separator) + "sub" + string(filepath.Separator) + "."} {
		code, out, errs := runHook(t, env, hookEvent("Bash", "ls", cwd, "toolu_j"))
		f.mu.Lock()
		sent := f.body[len(f.body)-1]["input"].(map[string]string)["cwd"]
		f.mu.Unlock()
		if code != 0 || sent != want {
			t.Fatalf("cwd %q sent as %q, want %q (%d %q %q)", cwd, sent, want, code, out, errs)
		}
	}
	f.mu.Lock()
	before := len(f.body)
	f.mu.Unlock()
	code, out, errs := runHook(t, env, hookEvent("Bash", "ls", filepath.Join(dir, "missing"), "toolu_m"))
	f.mu.Lock()
	after := len(f.body)
	f.mu.Unlock()
	if code != 2 || out != "" || !strings.Contains(errs, "cannot be resolved") || after != before {
		t.Fatalf("missing directory: %d %q %q, %d requests sent", code, out, errs, after-before)
	}
}

// TestHR187_FinalPathsHaveAPlainForm: the final path Windows reports is
// turned into a drive or UNC path; a volume without a drive letter, or
// anything else, is refused.
func TestHR187_FinalPathsHaveAPlainForm(t *testing.T) {
	for in, want := range map[string]string{
		`\\?\C:\Users\dev\repo`:       `C:\Users\dev\repo`,
		`\\?\d:\`:                     `d:\`,
		`\\?\UNC\fileserver\share\x`:  `\\fileserver\share\x`,
		`\\?\UNC\fileserver\share`:    `\\fileserver\share`,
		`\\?\C:\Users\Jürgen\a b\..x`: `C:\Users\Jürgen\a b\..x`,
	} {
		if got, err := dosPath(in); err != nil || got != want {
			t.Errorf("dosPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", `C:\x`, `\\?\`, `\\?\C:`, `\\?\C:x`, `\\?\1:\x`, `\\?\UNC\`,
		`\\?\Volume{6f0c3f4e-0000-0000-0000-100000000000}\x`, `\\?\GLOBALROOT\Device\HarddiskVolume3\x`, `\\.\C:\x`,
	} {
		if got, err := dosPath(in); err == nil {
			t.Errorf("dosPath(%q) = %q, want an error", in, got)
		}
	}
}

// TestHR186_TheHookDecidesMonitorCommandsAsBashCommands: Monitor runs its
// command where Bash runs, so the hook sends a Monitor command to the
// gateway exactly as the same Bash command, and follows the answer: an
// allow is answered allow, a denial and a hold block it. A Monitor call
// without a command (its WebSocket form) is blocked without asking.
func TestHR186_TheHookDecidesMonitorCommandsAsBashCommands(t *testing.T) {
	f := newFakeHook(t)
	env := hookEnv(t, f.URL)
	dir := t.TempDir()
	sent := func() map[string]any {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.body[len(f.body)-1]
	}
	if code, out, errs := runHook(t, env, hookEvent("Bash", "ls -la", dir, "toolu_same")); code != 0 || !strings.Contains(out, `"allow"`) {
		t.Fatalf("bash: %d %q %q", code, out, errs)
	}
	bash := sent()
	code, out, errs := runHook(t, env, hookEvent("Monitor", "ls -la", dir, "toolu_same"))
	if code != 0 || !strings.Contains(out, `"permissionDecision":"allow"`) || !strings.Contains(out, "t-1") {
		t.Fatalf("monitor, allowed: %d %q %q", code, out, errs)
	}
	if monitor := sent(); !reflect.DeepEqual(monitor, bash) {
		t.Fatalf("Monitor sent %v, Bash %v", monitor, bash)
	}
	for name, tc := range map[string]struct{ command, want string }{
		"denied": {"rm -rf build", "SHELL_DESTRUCTIVE"},
		"held":   {"deploy prod", "not by you"},
	} {
		code, out, errs := runHook(t, env, hookEvent("Monitor", tc.command, dir, "toolu_m"))
		if in := sent()["input"].(map[string]string); code != 2 || out != "" || !strings.Contains(errs, tc.want) || in["shell"] != "bash" ||
			in["command"] != tc.command {
			t.Errorf("%s: %d %q %q, sent %v", name, code, out, errs, in)
		}
	}
	f.mu.Lock()
	asked := len(f.body)
	f.mu.Unlock()
	websocket, _ := json.Marshal(map[string]any{
		"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Monitor", "cwd": dir, "tool_use_id": "toolu_ws",
		"tool_input": map[string]any{"url": "wss://feed.example.test/events", "description": "d"},
	})
	code, out, errs = runHook(t, env, string(websocket))
	f.mu.Lock()
	now := len(f.body)
	f.mu.Unlock()
	if code != 2 || out != "" || !strings.Contains(errs, "PantherClaw could not decide this command, so it is blocked") ||
		!strings.Contains(errs, "without a command") || now != asked {
		t.Fatalf("monitor without a command: %d %q %q, %d requests", code, out, errs, now-asked)
	}
}

// TestHR186_TheHookFailsClosed: an unreachable or slow gateway, input that
// is not a PreToolUse event, missing configuration and even a help flag
// block the command with exit code 2, within the hook's own deadline.
func TestHR186_TheHookFailsClosed(t *testing.T) {
	f := newFakeHook(t)
	env := hookEnv(t, f.URL)
	old := hookDeadline
	hookDeadline = 200 * time.Millisecond
	t.Cleanup(func() { hookDeadline = old })
	dead := hookEnv(t, "http://127.0.0.1:1")
	missing := map[string]string{}
	for name, tc := range map[string]struct {
		env   map[string]string
		stdin string
		args  []string
	}{
		"unreachable":  {dead, hookEvent("Bash", "ls", t.TempDir(), "toolu_1"), nil},
		"slow":         {env, hookEvent("Bash", "slow", t.TempDir(), "toolu_1"), nil},
		"not json":     {env, "{", nil},
		"another hook": {env, strings.Replace(hookEvent("Bash", "ls", t.TempDir(), "x"), "PreToolUse", "PostToolUse", 1), nil},
		"no config":    {missing, hookEvent("Bash", "ls", t.TempDir(), "x"), nil},
		"help flag":    {env, hookEvent("Bash", "ls", t.TempDir(), "x"), []string{"-h"}},
	} {
		start := time.Now()
		code, out, errs := runHook(t, tc.env, tc.stdin, tc.args...)
		if code != 2 || out != "" || !strings.Contains(errs, "PantherClaw could not decide this command, so it is blocked") ||
			time.Since(start) > 900*time.Millisecond {
			t.Errorf("%s: %d %q %q after %s", name, code, out, errs, time.Since(start))
		}
	}
}

// TestHR186_ThePluginBlocksOnFailure: the plugin runs the hook for Bash,
// PowerShell and Monitor, with a timeout longer than the hook's own
// deadline, and blocks the call if the hook fails or times out anyway.
func TestHR186_ThePluginBlocksOnFailure(t *testing.T) {
	b, err := os.ReadFile("../../integrations/claude-code/hooks/hooks.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type      string   `json:"type"`
				Command   string   `json:"command"`
				Args      []string `json:"args"`
				Timeout   int      `json:"timeout"`
				OnFailure string   `json:"onFailure"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	pre := cfg.Hooks["PreToolUse"]
	if len(cfg.Hooks) != 1 || len(pre) != 1 || pre[0].Matcher != "Bash|PowerShell|Monitor" || len(pre[0].Hooks) != 1 {
		t.Fatalf("hooks %+v", cfg.Hooks)
	}
	h := pre[0].Hooks[0]
	if h.Type != "command" || h.Command != "pclaw" || strings.Join(h.Args, " ") != "hook claude-code" || h.OnFailure != "block" ||
		time.Duration(h.Timeout)*time.Second <= hookDeadline {
		t.Fatalf("hook %+v", h)
	}
	var plugin struct {
		Name string `json:"name"`
	}
	if b, err := os.ReadFile("../../integrations/claude-code/.claude-plugin/plugin.json"); err != nil || json.Unmarshal(b, &plugin) != nil ||
		plugin.Name != "pantherclaw" {
		t.Fatalf("plugin.json %+v %v", plugin, err)
	}
}

// TestHR092_TheHookReusesAFreshToken: a cached token with more than a
// minute left is used; an expiring one is not.
func TestHR092_TheHookReusesAFreshToken(t *testing.T) {
	tok := func(exp time.Time) string {
		enc := base64.RawURLEncoding.EncodeToString
		return enc([]byte(`{"alg":"EdDSA"}`)) + "." + enc([]byte(`{"exp":`+itoa(exp.Unix())+`}`)) + ".sig"
	}
	if d := time.Until(tokenExpiry(tok(time.Now().Add(5 * time.Minute)))); d < 4*time.Minute {
		t.Fatalf("expiry in %s", d)
	}
	if !tokenExpiry("not.a.token").IsZero() || !tokenExpiry("garbage").IsZero() {
		t.Fatal("an unreadable token has an expiry")
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
