// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cicheck

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// actions returns every integrations/**/action.yml by its path.
func actions(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	base := filepath.Join(root, "integrations")
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "node_modules" {
			return filepath.SkipDir
		}
		if d.IsDir() || (d.Name() != "action.yml" && d.Name() != "action.yaml") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no action.yml under integrations")
	}
	return out
}

// runBlocks returns the lines of the action's run: scripts: the single
// line form and everything indented under a block form.
func runBlocks(action string) []string {
	var out []string
	lines := strings.Split(action, "\n")
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		t := strings.TrimLeft(l, " ")
		if !strings.HasPrefix(t, "run:") && !strings.HasPrefix(t, "- run:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "- "), "run:"))
		if rest != "|" && rest != ">" && !strings.HasPrefix(rest, "|") {
			out = append(out, rest)
			continue
		}
		indent := len(l) - len(t)
		for i+1 < len(lines) {
			next := lines[i+1]
			if strings.TrimSpace(next) != "" && len(next)-len(strings.TrimLeft(next, " ")) <= indent {
				break
			}
			out = append(out, next)
			i++
		}
	}
	return out
}

// TestHR130_ActionsAreHardened: the workflow rules hold for every action
// this repository ships: pull_request_target never appears, every step is
// pinned by full commit SHA, and a checkout keeps no credentials
// (G0 M23 D123).
func TestHR130_ActionsAreHardened(t *testing.T) {
	for name, a := range actions(t) {
		if strings.Contains(code(a), "pull_request_target") {
			t.Errorf("%s: uses pull_request_target", name)
		}
		uses := usesLine.FindAllStringSubmatch(a, -1)
		for _, m := range uses {
			if !strings.HasPrefix(m[1], "./") && !pinnedUses.MatchString(m[1]) {
				t.Errorf("%s: action %q is not pinned to a full commit SHA", name, m[1])
			}
		}
		lines := strings.Split(a, "\n")
		for i, l := range lines {
			if !strings.Contains(l, "uses: actions/checkout@") {
				continue
			}
			end := min(i+7, len(lines))
			if !strings.Contains(strings.Join(lines[i:end], "\n"), "persist-credentials: false") {
				t.Errorf("%s:%d: actions/checkout without persist-credentials: false", name, i+1)
			}
		}
	}
}

// TestHR566_ActionsNeedNoSecrets: an action names no secret, gets the
// token in the one step that posts, and refuses other events.
func TestHR566_ActionsNeedNoSecrets(t *testing.T) {
	for name, a := range actions(t) {
		if strings.Contains(a, "secrets.") {
			t.Errorf("%s: reads a secret", name)
		}
		if n := strings.Count(a, "github.token"); n > 1 {
			t.Errorf("%s: %d steps get the token, only the comment step may", name, n)
		}
		if strings.Contains(a, "github.token") {
			steps := regexp.MustCompile(`(?m)^    - name:`).Split(a, -1)
			for _, s := range steps {
				if strings.Contains(s, "github.token") && !strings.Contains(s, "Comment on the pull request") {
					t.Errorf("%s: a step other than the comment gets the token", name)
				}
				if strings.Contains(s, "github.token") && !strings.Contains(s, "github.event.pull_request.head.repo.full_name == github.repository") {
					t.Errorf("%s: the comment step runs on forks", name)
				}
			}
		}
		if !strings.Contains(a, `"$GITHUB_EVENT_NAME" != "pull_request"`) {
			t.Errorf("%s: does not refuse other events", name)
		}
	}
}

// TestT245_ActionInputsNeverReachAShellAsCode: an expression in a run:
// block is pasted into the script before it runs, so a branch name could
// be code there. Everything reaches the shell through env.
func TestT245_ActionInputsNeverReachAShellAsCode(t *testing.T) {
	for name, a := range actions(t) {
		blocks := runBlocks(a)
		if len(blocks) == 0 {
			t.Errorf("%s: found no run blocks", name)
		}
		for _, l := range blocks {
			if strings.Contains(l, "${{") {
				t.Errorf("%s: an expression in a run block: %s", name, strings.TrimSpace(l))
			}
		}
	}
}

// TestHR566_DownloadsAreVerified: an action that fetches a binary checks
// its digest before anything runs it.
func TestHR566_DownloadsAreVerified(t *testing.T) {
	for name, a := range actions(t) {
		if !strings.Contains(a, "curl ") {
			continue
		}
		check := strings.Index(a, "--check --strict")
		extract := strings.Index(a, "tar -xzf")
		if check < 0 || extract < check {
			t.Errorf("%s: extracts a download before verifying it", name)
		}
	}
}

// TestRunBlocks: the scan finds both forms, so the expression check above
// looks at what it says it does.
func TestRunBlocks(t *testing.T) {
	a := "steps:\n  - name: a\n    run: exit 1\n  - name: b\n    run: |\n      echo one\n\n      echo ${{ x }}\n    shell: bash\n  - run: echo two\n"
	got := strings.Join(runBlocks(a), "\n")
	for _, want := range []string{"exit 1", "echo one", "${{ x }}", "echo two"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	if strings.Contains(got, "shell: bash") {
		t.Errorf("read past the block: %q", got)
	}
}
