// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"encoding/json/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// shortName is the 8.3 short name of an existing Windows directory, or ""
// when the volume keeps none.
func shortName(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "cmd", "/c", "for %I in (.) do @echo %~sI")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("short name of %s: %v", dir, err)
	}
	if s := strings.TrimSpace(string(out)); s != dir {
		return s
	}
	return ""
}

// TestT069_APathRuleHoldsForEverySpellingOfItsDirectory: the org forbids
// shell commands in a directory, and an agent asks for one there through
// the Claude Code hook, spelling the directory every way the file system
// accepts (T-069, HR-187): through "..", with "." and doubled separators,
// on Windows with forward slashes, another case, a trailing dot or space,
// an alternate data stream, a device path or its 8.3 short name, and
// elsewhere through a symbolic link.
// Each spelling either reaches policy as the directory's one canonical
// path and is denied by the rule, or is refused before policy as
// ambiguous; none is allowed. A command in another directory is allowed,
// and recorded as delegated with the agent-held access mode: the hook's
// allow is a cooperative decision, never enforcement, and nothing reaches
// a target.
func TestT069_APathRuleHoldsForEverySpellingOfItsDirectory(t *testing.T) {
	s := start(t, options{budget: "1000.00", shell: true})
	root := t.TempDir()
	const name = "Customer Secrets"
	secret, public := filepath.Join(root, name), filepath.Join(root, "public")
	for _, d := range []string{secret, public} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	final, err := filepath.EvalSymlinks(secret)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := actionir.NormalizePath(final)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := json.Marshal(map[string]any{"id": "secrets", "rules": []any{map[string]any{
		"id": "no-secrets", "kind": "FORBID", "summary": "commands in the customer secrets directory",
		"operations": []string{"shell.command.run"}, "when": `action.params.cwd.startsWith(r"` + canon + `")`, "reason": "SECRETS_DIRECTORY",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	s.publishPolicy(t, string(bundle))

	sep := string(filepath.Separator)
	spellings := map[string]string{
		"canonical":                   secret,
		"climbing with ..":            public + sep + ".." + sep + name,
		"with . and doubled slashes":  root + sep + "." + sep + sep + name + sep,
		"with a trailing . segment":   secret + sep + ".",
		"through a child and back up": secret + sep + "sub" + sep + "..",
	}
	if runtime.GOOS == "windows" {
		spellings["forward slashes and a lower-case drive"] = strings.ToLower(secret[:1]) + filepath.ToSlash(secret[1:])
		spellings["upper case"] = strings.ToUpper(secret)
		spellings["a trailing dot"] = secret + "."
		spellings["a trailing space"] = secret + " "
		spellings["an alternate data stream"] = secret + ":hidden"
		spellings["a device path"] = `\\?\` + secret
		spellings["a dot device path"] = `\\.\` + secret
		if short := shortName(t, secret); short != "" {
			spellings["the 8.3 short name"] = short
		} else {
			t.Log("the volume keeps no 8.3 short names; that spelling is not tried")
		}
	} else {
		link := filepath.Join(root, "innocent")
		if err := os.Symlink(secret, link); err != nil {
			t.Fatal(err)
		}
		spellings["a symbolic link"] = link
	}
	n := 0
	event := func(command, cwd string) string {
		n++
		b, _ := json.Marshal(map[string]any{
			"session_id": "t069", "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": cwd,
			"tool_use_id": "toolu_t069_" + itoa(int64(n)), "tool_input": map[string]any{"command": command, "description": "t069"},
		})
		return string(b)
	}
	for how, cwd := range spellings {
		code, out, errs := s.hook(t, event("cat customers.csv", cwd))
		policy, ambiguous := strings.Contains(errs, "SECRETS_DIRECTORY"), strings.Contains(errs, "cannot decide this call")
		if code != 2 || out != "" || (!policy && !ambiguous) || strings.Contains(errs, `"ask"`) {
			t.Errorf("%s (%q): exit %d, stdout %q, stderr %q", how, cwd, code, out, errs)
		}
	}

	code, out, errs := s.hook(t, event("cat README.md", public))
	if code != 0 || !strings.Contains(out, `"permissionDecision":"allow"`) {
		t.Fatalf("a command in another directory: %d %s %s", code, out, errs)
	}
	var recorded string
	s.query(t, "SELECT outcome || '/' || access_mode FROM pc.execution_attempts ORDER BY recorded_at DESC LIMIT 1", nil, &recorded)
	if recorded != "delegated/agent_held" {
		t.Fatalf("the allowed command is recorded as %q, want delegated/agent_held", recorded)
	}
	if calls := s.simCalls.Load(); calls != 0 {
		t.Fatalf("a hook decision reached the target %d times", calls)
	}
	if st := s.sim.Stats(); st.Refunds != 0 || st.Refused != 0 {
		t.Fatalf("target %+v", st)
	}
}
