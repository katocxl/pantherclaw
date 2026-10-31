// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan

import (
	"strings"
	"testing"
)

// TestHR588_PackageRefIsTheTokenAlone (D233): a launcher gives its package or
// image and nothing else; whatever cannot be told apart from an argument
// gives nothing.
// Covers: F884
func TestHR588_PackageRefIsTheTokenAlone(t *testing.T) {
	for _, c := range []struct {
		line, want string
	}{
		{"npx -y @scope/pkg@1.2 --flag v", "@scope/pkg@1.2"},
		{"npx --yes pkg", "pkg"},
		{"npx -p real-pkg bin --x", "real-pkg"},
		{"npx --package=real-pkg bin", "real-pkg"},
		{"npx.cmd -y pkg", "pkg"},
		{"/usr/local/bin/npx pkg", "pkg"},
		{"cmd /c npx -y pkg --token sekret", "pkg"},
		{"bunx --bun pkg x", "pkg"},
		{"uvx mcp-server-git --repository /r", "mcp-server-git"},
		{"uvx --python 3.12 tool==1.0 a", "tool==1.0"},
		{"uvx --from tool[extra] cmd", "tool[extra]"},
		{"pipx run --spec black==24 black .", "black==24"},
		{"pipx run ruff check", "ruff"},
		{"docker run -i --rm -e A=sekret ghcr.io/a/b:1 --x", "ghcr.io/a/b:1"},
		{"docker run --env=A=sekret -v /a:/b reg:5000/img@sha256:" + strings.Repeat("a", 64), "reg:5000/img@sha256:" + strings.Repeat("a", 64)},
		{"docker run --mystery sekret image", ""},
		{"docker ps", ""},
		{"docker run", ""},
		{"pipx install thing", ""},
		{"npx --unknown sekret pkg", ""},
		{"npx ./local/script.js", ""},
		{"npx https://user:sekret@host/pkg.tgz", ""},
		{"uvx git+https://tok@host/repo", ""},
		{"npx ghp_0123456789abcdef", ""},
		{"docker run sk-ant-0123456789", ""},
		{"npx -p", ""},
		{"python server.py", ""},
		{"node npx pkg", ""},
		{"npx -- " + strings.Repeat("a", 300), ""},
	} {
		f := strings.Fields(c.line)
		if got := packageRef(f[0], f[1:]); got != c.want {
			t.Errorf("%q = %q, want %q", c.line, got, c.want)
		}
	}
}

// TestHR588_ExecutableIsTheBasename (D233): a hook's first word, base name
// only, past any NAME=value prefix; anything unusual gives nothing.
// Covers: F883
func TestHR588_ExecutableIsTheBasename(t *testing.T) {
	for line, want := range map[string]string{
		"/opt/hooks/guard.sh --key sekret":     "guard.sh",
		"TOKEN=sekret A=b guard.sh":            "guard.sh",
		`"/Program Files/acme/hook.exe" --x`:   "hook.exe",
		`C:\tools\hook.exe arg`:                "hook.exe",
		"$CLAUDE_PROJECT_DIR/.claude/check.py": "check.py",
		"bash -c 'curl https://x/sekret'":      "bash",
		"TOKEN=sekret":                         "",
		"":                                     "",
		"'unterminated sekret":                 "",
		"$(curl sekret)":                       "",
	} {
		if got := executableOf(line); got != want {
			t.Errorf("%q = %q, want %q", line, got, want)
		}
	}
}
