// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
)

// initFixture is a home, a project, an enrolled-looking key file, the
// platform's managed settings directory (empty unless a test writes to
// it, so the machine's own are never read) and the answer init reads when
// it asks to confirm (from stdin, when a test sets it).
type initFixture struct {
	home, project, key, managed, platform, answer string
	env                                           map[string]string
	stdin                                         io.Reader
}

func newInitFixture(t *testing.T) *initFixture {
	t.Helper()
	root := t.TempDir()
	f := &initFixture{
		home: filepath.Join(root, "home"), project: filepath.Join(root, "proj"), managed: filepath.Join(root, "managed.json"),
		platform: filepath.Join(root, "platform"),
	}
	old := managedSettingsDir
	managedSettingsDir = f.platform
	t.Cleanup(func() { managedSettingsDir = old })
	for _, d := range []string{f.home, f.project} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	kf, _, err := workloadclient.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	kf.Identifier, kf.Server = "pc:org/o/agent/a/inst/i", "https://pantherclaw.example.test"
	f.key = filepath.Join(root, "workload.json")
	if err := workloadclient.WriteKeyFile(f.key, kf, false); err != nil {
		t.Fatal(err)
	}
	f.env, f.answer = map[string]string{"HOME": f.home}, "y\n"
	return f
}

func (f *initFixture) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *initFixture) local() string {
	return filepath.Join(f.project, ".claude", "settings.local.json")
}

func (f *initFixture) run(t *testing.T, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{
		"init", "--gateway", "https://gw.example.test", "--connection", "shell", "--key-file", f.key,
		"--project", f.project, "--managed-settings", f.managed,
	}, extra...)
	stdin := f.stdin
	if stdin == nil {
		stdin = strings.NewReader(f.answer)
	}
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, &out, &errb, envOf(f.env), Options{Stdin: stdin})
	return code, out.String(), errb.String()
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func backups(t *testing.T, path string) []string {
	t.Helper()
	m, err := filepath.Glob(path + ".pclaw-backup-*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// existingLocal has deny rules, hooks of the developer's own, an MCP
// approval and members pclaw init does not know, in the developer's order
// and laid out as Claude Code writes settings (two spaces, no final
// newline).
const existingLocal = `{
  "permissions": {
    "deny": [
      "Bash(curl:*)",
      "Read(./.env)"
    ],
    "allow": [
      "Bash(go test:*)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "lint-on-edit"
          }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "notify"
          }
        ]
      }
    ]
  },
  "env": {
    "GOFLAGS": "-mod=readonly"
  },
  "enabledMcpjsonServers": [
    "docs"
  ]
}`

// TestHR208_InitBacksUpShowsTheDiffAndOnlyAdds: init backs up the file it
// changes, shows the diff, writes the hook in exec form with the gateway,
// connection, key file and run and nothing else, and keeps every deny
// rule, hook and member it found, in their order. A second run changes
// nothing and backs up nothing.
func TestHR208_InitBacksUpShowsTheDiffAndOnlyAdds(t *testing.T) {
	f := newInitFixture(t)
	f.write(t, f.local(), existingLocal)
	code, out, errs := f.run(t, "--run", "01920000-0000-7000-8000-0000000000f1")
	if code != 0 {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	b := backups(t, f.local())
	if len(b) != 1 {
		t.Fatalf("backups %v", b)
	}
	if saved, _ := os.ReadFile(b[0]); string(saved) != existingLocal {
		t.Fatalf("the backup is not the original: %q", saved)
	}
	removed := strings.Contains(strings.ReplaceAll(out, "\n--- ", "\n"), "\n-")
	if !strings.Contains(out, "--- "+f.local()) || !strings.Contains(out, `+            "onFailure": "block"`) || removed {
		t.Fatalf("the diff does not show an addition only:\n%s", out)
	}
	got := readJSON(t, f.local())
	perm, _ := got["permissions"].(map[string]any)
	if deny, _ := perm["deny"].([]any); len(deny) != 2 || deny[0] != "Bash(curl:*)" || deny[1] != "Read(./.env)" {
		t.Fatalf("deny rules %v", perm["deny"])
	}
	hooks, _ := got["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	if len(pre) != 2 || hooks["Stop"] == nil || got["env"] == nil || got["enabledMcpjsonServers"] == nil {
		t.Fatalf("settings after init %v", got)
	}
	mine, _ := pre[1].(map[string]any)
	h, _ := mine["hooks"].([]any)
	entry, _ := h[0].(map[string]any)
	args, _ := entry["args"].([]any)
	want := []any{
		"hook", "claude-code", "--gateway", "https://gw.example.test", "--connection", "shell", "--key-file", f.key,
		"--run", "01920000-0000-7000-8000-0000000000f1",
	}
	if mine["matcher"] != "Bash|PowerShell|Monitor" || entry["command"] != "pclaw" || entry["onFailure"] != "block" || len(args) != len(want) {
		t.Fatalf("hook %v", mine)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("hook args %v, want %v", args, want)
		}
	}
	raw, _ := os.ReadFile(f.local())
	if i, j := bytes.Index(raw, []byte(`"permissions"`)), bytes.Index(raw, []byte(`"enabledMcpjsonServers"`)); i < 0 || j < i {
		t.Fatalf("members reordered:\n%s", raw)
	}

	code, out, _ = f.run(t, "--run", "01920000-0000-7000-8000-0000000000f1")
	if again, _ := os.ReadFile(f.local()); code != 0 || !strings.Contains(out, "already installed") || !bytes.Equal(again, raw) ||
		len(backups(t, f.local())) != 1 {
		t.Fatalf("second run: %d %s", code, out)
	}
}

// TestHR208_InitWritesNoSecret: the written settings name the key file and
// hold nothing from inside it.
func TestHR208_InitWritesNoSecret(t *testing.T) {
	f := newInitFixture(t)
	if code, out, errs := f.run(t); code != 0 {
		t.Fatalf("init: %d %s %s", code, out, errs)
	}
	key, err := os.ReadFile(f.key)
	if err != nil {
		t.Fatal(err)
	}
	var kf map[string]any
	if err := json.Unmarshal(key, &kf); err != nil {
		t.Fatal(err)
	}
	written, _ := os.ReadFile(f.local())
	for name, v := range kf {
		if s, ok := v.(string); ok && len(s) >= 16 && bytes.Contains(written, []byte(s)) {
			t.Errorf("the settings hold the key file's %s", name)
		}
	}
	if len(backups(t, f.local())) != 0 {
		t.Error("a new file was backed up")
	}
}

// TestHR208_InitRefusesWhatWouldKeepTheHookFromRunning: managed settings
// that allow only managed hooks or disable every hook, and a target file
// that disables its hooks, are failures that change nothing; managed
// settings that already run the hook need no change. A dry run shows the
// diff and writes nothing, and a file pclaw cannot parse is left alone.
func TestHR208_InitRefusesWhatWouldKeepTheHookFromRunning(t *testing.T) {
	for name, tc := range map[string]struct {
		managed, local string
		args           []string
		code           int
		want           string
	}{
		"managed hooks only": {managed: `{"allowManagedHooksOnly": true}`, code: 1, want: "allow only managed hooks"},
		"all hooks off":      {managed: `{"disableAllHooks": true}`, code: 1, want: "disable every hook"},
		"local hooks off":    {local: `{"disableAllHooks": true}`, code: 1, want: "never changes that setting"},
		"managed runs it": {
			managed: `{"allowManagedHooksOnly": true, "hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell|Monitor",
				"hooks": [{"type": "command", "command": "pclaw", "args": ["hook", "claude-code"], "onFailure": "block"}]}]}}`,
			want: "already installed",
		},
		"managed runs it failing open": {
			managed: `{"allowManagedHooksOnly": true, "hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell|Monitor",
				"hooks": [{"type": "command", "command": "pclaw", "args": ["hook", "claude-code"]}]}]}}`,
			code: 1, want: "allow only managed hooks",
		},
		"managed runs it without Monitor": {
			managed: `{"allowManagedHooksOnly": true, "hooks": {"PreToolUse": [{"matcher": "Bash|PowerShell",
				"hooks": [{"type": "command", "command": "pclaw", "args": ["hook", "claude-code"], "onFailure": "block"}]}]}}`,
			code: 1, want: "allow only managed hooks",
		},
		"dry run":        {local: existingLocal, args: []string{"--dry-run"}, want: "Dry run: nothing was changed."},
		"not json":       {local: `{"hooks": `, code: 1, want: "left as it is"},
		"hooks a list":   {local: `{"hooks": []}`, code: 1, want: "hooks is not an object"},
		"pre not a list": {local: `{"hooks": {"PreToolUse": {}}}`, code: 1, want: "PreToolUse is not a list"},
	} {
		f := newInitFixture(t)
		if tc.managed != "" {
			f.write(t, f.managed, tc.managed)
		}
		if tc.local != "" {
			f.write(t, f.local(), tc.local)
		}
		code, out, errs := f.run(t, tc.args...)
		if code != tc.code || !strings.Contains(out+errs, tc.want) {
			t.Errorf("%s: %d %s %s", name, code, out, errs)
		}
		if now, err := os.ReadFile(f.local()); (tc.local == "" && err == nil) || (tc.local != "" && string(now) != tc.local) {
			t.Errorf("%s: the settings changed: %q", name, now)
		}
		if len(backups(t, f.local())) != 0 {
			t.Errorf("%s: backed up", name)
		}
	}
}

// TestHR208_InitCountsOnlyAFailClosedPantherClawHook: an existing hook is
// PantherClaw's only when it runs `pclaw hook claude-code` before Bash,
// PowerShell and Monitor and blocks the command when it cannot run; in a
// shell, only that command and its own flags count, since anything more
// (|| true, ; true, && x, a redirection) can change what its exit code
// says. Beside a pclaw hook that fails open, runs another command or more
// than the hook's, leaves out Monitor or names BashOutput instead of Bash,
// init adds its own and keeps the other as it was.
func TestHR208_InitCountsOnlyAFailClosedPantherClawHook(t *testing.T) {
	const run = "01920000-0000-7000-8000-0000000000f1"
	shell := func(command string) string {
		return `{"type": "command", "command": "` + command + `", "onFailure": "block"}`
	}
	exec := `{"type": "command", "command": "pclaw", "args": ["hook", "claude-code"], "onFailure": "block"}`
	for name, tc := range map[string]struct {
		hook, matcher string
		installed     bool
	}{
		"without Monitor": {hook: exec, matcher: "Bash|PowerShell"},
		"BashOutput":      {hook: exec, matcher: "BashOutput|PowerShell|Monitor"},
		"shell form with its flags": {
			hook: shell("pclaw hook claude-code --gateway=https://gw.example.test  --connection shell -run " + run), installed: true,
		},
		"or true":              {hook: shell("pclaw hook claude-code || true")},
		"then true":            {hook: shell("pclaw hook claude-code; true")},
		"and more":             {hook: shell("pclaw hook claude-code --connection shell && x")},
		"a redirection":        {hook: shell("pclaw hook claude-code --connection shell 2>/dev/null")},
		"a newline":            {hook: shell(`pclaw hook claude-code --run\ntrue`)},
		"another flag":         {hook: shell("pclaw hook claude-code --yes")},
		"a substitution":       {hook: shell("pclaw hook claude-code --connection $(x)")},
		"a flag with no value": {hook: shell("pclaw hook claude-code --run")},
		"not a command hook":   {hook: `{"type": "prompt", "command": "pclaw", "args": ["hook", "claude-code"], "onFailure": "block"}`},
		"fails closed": {
			hook: `{"type": "command", "command": "/usr/local/bin/pclaw", "args": ["hook", "claude-code"], "onFailure": "block"}`, installed: true,
		},
		"shell form": {
			hook: `{"type": "command", "command": "pclaw hook claude-code --connection shell", "onFailure": "block"}`, installed: true,
		},
		"no onFailure":    {hook: `{"type": "command", "command": "pclaw", "args": ["hook", "claude-code"]}`},
		"fails open":      {hook: `{"type": "command", "command": "pclaw", "args": ["hook", "claude-code"], "onFailure": "continue"}`},
		"another command": {hook: `{"type": "command", "command": "pclaw hook claude-code-lite", "onFailure": "block"}`},
		"another hook":    {hook: `{"type": "command", "command": "pclaw", "args": ["hook", "other"], "onFailure": "block"}`},
	} {
		f := newInitFixture(t)
		if tc.matcher == "" {
			tc.matcher = "Bash|PowerShell|Monitor"
		}
		local := `{"hooks": {"PreToolUse": [{"matcher": "` + tc.matcher + `", "hooks": [` + tc.hook + `]}]}}`
		f.write(t, f.local(), local)
		var before map[string]any
		if err := json.Unmarshal([]byte(local), &before); err != nil {
			t.Fatal(err)
		}
		code, out, errs := f.run(t)
		if code != 0 || strings.Contains(out, "already installed") != tc.installed {
			t.Errorf("%s: %d %s %s", name, code, out, errs)
			continue
		}
		now, _ := os.ReadFile(f.local())
		if tc.installed {
			if string(now) != local {
				t.Errorf("%s: changed to %s", name, now)
			}
			continue
		}
		hooks, _ := readJSON(t, f.local())["hooks"].(map[string]any)
		pre, _ := hooks["PreToolUse"].([]any)
		hooks, _ = before["hooks"].(map[string]any)
		kept, _ := hooks["PreToolUse"].([]any)
		if len(pre) != 2 || !reflect.DeepEqual(pre[0], kept[0]) || !hookRunsIn(t, f.local()) {
			t.Errorf("%s: hooks after init %v", name, pre)
		}
	}
}

// TestHR208_TheHookCoversEachShellToolByItsExactName: PantherClaw's hook
// covers a tool only under a matcher that names it exactly among names
// joined by |, or that matches every tool (missing, empty or *); Bash,
// PowerShell and Monitor may be covered by different groups. A name that
// only contains one (BashOutput), names with spaces, a regular expression
// and a matcher that is not a string cover nothing, and a group whose
// pclaw hook fails open covers nothing either.
func TestHR208_TheHookCoversEachShellToolByItsExactName(t *testing.T) {
	const closed = `[{"type": "command", "command": "pclaw", "args": ["hook", "claude-code"], "onFailure": "block"}]`
	const open = `[{"type": "command", "command": "pclaw", "args": ["hook", "claude-code"]}]`
	group := func(matcher, hooks string) string { return `{` + matcher + `"hooks": ` + hooks + `}` }
	for name, tc := range map[string]struct {
		groups []string
		runs   bool
	}{
		"no matcher":       {[]string{group(``, closed)}, true},
		"an empty matcher": {[]string{group(`"matcher": "", `, closed)}, true},
		"every tool":       {[]string{group(`"matcher": "*", `, closed)}, true},
		"the three":        {[]string{group(`"matcher": "Monitor|Bash|PowerShell", `, closed)}, true},
		"in two groups":    {[]string{group(`"matcher": "Bash|PowerShell", `, closed), group(`"matcher": "Monitor", `, closed)}, true},
		"BashOutput":       {[]string{group(`"matcher": "BashOutput|PowerShell|Monitor", `, closed)}, false},
		"MonitorX":         {[]string{group(`"matcher": "Bash|PowerShell|MonitorX", `, closed)}, false},
		"spaces":           {[]string{group(`"matcher": "Bash | PowerShell | Monitor", `, closed)}, false},
		"a regular expression": {
			[]string{group(`"matcher": "Bash|PowerShell|Monitor|mcp__.*", `, closed)}, false,
		},
		"not a string": {[]string{group(`"matcher": ["Bash", "PowerShell", "Monitor"], `, closed)}, false},
		"one group fails open": {
			[]string{group(`"matcher": "Bash|PowerShell", `, closed), group(`"matcher": "Monitor", `, open)}, false,
		},
	} {
		doc, err := parseJSONDoc([]byte(`{"hooks": {"PreToolUse": [` + strings.Join(tc.groups, ", ") + `]}}`))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := hookRuns(doc); got != tc.runs {
			t.Errorf("%s: hookRuns = %v", name, got)
		}
	}
}

// TestHR208_InitRefusesHooksTurnedOffInAnotherScope:Claude Code takes
// disableAllHooks from the first settings file that sets it (managed,
// local, project, user), so a file of another scope that turns every hook
// off fails init and changes nothing, unless a file Claude Code prefers to
// it turns them back on.
func TestHR208_InitRefusesHooksTurnedOffInAnotherScope(t *testing.T) {
	const off, on = `{"disableAllHooks": true}`, `{"disableAllHooks": false}`
	for name, tc := range map[string]struct {
		user, project, local, managed, scope, offIn string
	}{
		"user turns them off":          {user: off, offIn: "user"},
		"project turns them off":       {project: off, offIn: "project"},
		"local, for the project scope": {local: off, scope: "project", offIn: "local"},
		"local turns them back on":     {user: off, local: on},
		"project turns them back on":   {user: off, project: on},
		"managed turns them back on":   {project: off, managed: on},
		"user, for the project scope":  {user: off, scope: "project", offIn: "user"},
	} {
		f := newInitFixture(t)
		paths := map[string]string{
			"user": filepath.Join(f.home, ".claude", "settings.json"), "project": filepath.Join(f.project, ".claude", "settings.json"),
			"local": f.local(), "managed": f.managed,
		}
		written := map[string]string{"user": tc.user, "project": tc.project, "local": tc.local, "managed": tc.managed}
		for scope, content := range written {
			if content != "" {
				f.write(t, paths[scope], content)
			}
		}
		args := []string{}
		if tc.scope != "" {
			args = append(args, "--scope", tc.scope)
		}
		code, out, errs := f.run(t, args...)
		if tc.offIn == "" {
			if code != 0 {
				t.Errorf("%s: %d %s %s", name, code, out, errs)
			}
			continue
		}
		if code != 1 || !strings.Contains(errs, paths[tc.offIn]+" turns every hook off") {
			t.Errorf("%s: %d %s %s", name, code, out, errs)
		}
		for scope, path := range paths {
			if now, err := os.ReadFile(path); (written[scope] == "" && err == nil) || (written[scope] != "" && string(now) != written[scope]) {
				t.Errorf("%s: %s changed: %q", name, scope, now)
			}
		}
	}
}

// TestHR208_InitAlwaysReadsThePlatformsManagedSettings: --managed-settings
// adds a file to the platform's managed settings and never replaces them,
// so pointing it at the null device skips no managed check, drop-ins
// included.
func TestHR208_InitAlwaysReadsThePlatformsManagedSettings(t *testing.T) {
	for name, tc := range map[string]struct{ file, content, want string }{
		"the platform's file": {file: "managed-settings.json", content: `{"disableAllHooks": true}`, want: "disable every hook"},
		"a drop-in": {
			file: filepath.Join("managed-settings.d", "50-hooks.json"), content: `{"allowManagedHooksOnly": true}`, want: "allow only managed hooks",
		},
	} {
		f := newInitFixture(t)
		f.write(t, filepath.Join(f.platform, tc.file), tc.content)
		f.managed = os.DevNull
		code, out, errs := f.run(t)
		if _, err := os.Stat(f.local()); code != 1 || err == nil || !strings.Contains(errs, tc.want) ||
			!strings.Contains(out, filepath.Join(f.platform, tc.file)) {
			t.Errorf("%s: %d %s %s", name, code, out, errs)
		}
	}
}

// TestHR208_InitTargetsTheChosenScope: local is the default; project and
// user write their own files, and CLAUDE_CONFIG_DIR moves the user's.
func TestHR208_InitTargetsTheChosenScope(t *testing.T) {
	f := newInitFixture(t)
	for scope, path := range map[string]string{
		"project": filepath.Join(f.project, ".claude", "settings.json"),
		"user":    filepath.Join(f.home, ".claude", "settings.json"),
	} {
		if code, out, errs := f.run(t, "--scope", scope); code != 0 || !hookRunsIn(t, path) {
			t.Errorf("%s: %d %s %s", scope, code, out, errs)
		}
	}
	f.env["CLAUDE_CONFIG_DIR"] = filepath.Join(f.home, "cc")
	if code, _, errs := f.run(t, "--scope", "user"); code != 0 || !hookRunsIn(t, filepath.Join(f.home, "cc", "settings.json")) {
		t.Errorf("CLAUDE_CONFIG_DIR: %d %s", code, errs)
	}
	if code, _, _ := f.run(t, "--scope", "everywhere"); code == 0 {
		t.Error("an unknown scope")
	}
}

func hookRunsIn(t *testing.T, path string) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	doc, err := parseJSONDoc(b)
	return err == nil && hookRuns(doc)
}

// TestT084_InitRefusesFlagsThatWouldWriteSecretsOrNonsense: a gateway URL
// with credentials or a query, a connection that is not a name, a run that
// is not an id and a key file that is not one are refused before anything
// is read or written.
func TestT084_InitRefusesFlagsThatWouldWriteSecretsOrNonsense(t *testing.T) {
	f := newInitFixture(t)
	for name, args := range map[string][]string{
		"credentials in the URL": {"--gateway", "https://user:pass@gw.example.test"},
		"a query":                {"--gateway", "https://gw.example.test/?token=x"},
		"a connection":           {"--connection", "../shell"},
		"a run":                  {"--run", "latest"},
		"a key file":             {"--key-file", f.managed},
	} {
		if code, _, _ := f.run(t, args...); code == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := os.Stat(filepath.Join(f.project, ".claude")); err == nil {
		t.Fatal("a refused init created settings")
	}
}
