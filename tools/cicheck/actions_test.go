// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cicheck

import (
	"io/fs"
	"os"
	"os/exec"
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

// gitlabTemplate is the GitLab component, by its path.
const gitlabTemplate = "integrations/gitlab/templates/pantherclaw-check.yml"

// integrationScripts returns everything that runs in a customer's pipeline:
// the actions and the GitLab component.
func integrationScripts(t *testing.T) map[string]string {
	t.Helper()
	out := actions(t)
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(gitlabTemplate)))
	if err != nil {
		t.Fatal(err)
	}
	out[gitlabTemplate] = string(b)
	return out
}

// TestHR566_DownloadsAreVerified: whatever fetches a binary checks its
// digest before anything runs it.
func TestHR566_DownloadsAreVerified(t *testing.T) {
	found := 0
	for name, a := range integrationScripts(t) {
		if !strings.Contains(a, "curl ") {
			continue
		}
		found++
		check := strings.Index(a, "--check --strict")
		extract := strings.Index(a, "tar -xzf")
		if check < 0 || extract < check {
			t.Errorf("%s: extracts a download before verifying it", name)
		}
	}
	if found < 2 {
		t.Errorf("found %d downloads, want the action and the GitLab component", found)
	}
}

// checksumMatch finds the awk program that picks the archive's line.
var checksumMatch = regexp.MustCompile(`awk -v f="\$name" '([^']+)'`)

// TestHR566_ChecksumsAreMatchedExactly: a release lists <archive>.sbom.json
// too, so a substring match finds two lines and refuses every real release
// (G0 M23 D126). The program in each file runs on such a checksums file.
func TestHR566_ChecksumsAreMatchedExactly(t *testing.T) {
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Skip("no awk")
	}
	const name = "pantherclaw_1.0.0_linux_amd64.tar.gz"
	archive := strings.Repeat("a", 64) + "  " + name
	sums := filepath.Join(t.TempDir(), "checksums.txt")
	lines := strings.Repeat("b", 64) + "  " + name + ".sbom.json\n" + archive + "\n" +
		strings.Repeat("c", 64) + "  x" + name + "\n"
	if err := os.WriteFile(sums, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	for file, a := range integrationScripts(t) {
		m := checksumMatch.FindStringSubmatch(a)
		if m == nil {
			t.Errorf("%s: no exact checksum match", file)
			continue
		}
		out, err := exec.CommandContext(t.Context(), awk, "-v", "f="+name, m[1], sums).Output()
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if got := strings.TrimRight(string(out), "\r\n"); got != archive {
			t.Errorf("%s: matched %q", file, got)
		}
	}
}

// TestHR566_AnUnreadableBaseStopsTheCheck: on GitLab a base that cannot be
// fetched exits 2, since a check with nothing to compare would pass a
// widening. Only a file absent at the fetched base counts as no base, and
// git's own errors stay in the log (G0 M23 D127).
func TestHR566_AnUnreadableBaseStopsTheCheck(t *testing.T) {
	a := integrationScripts(t)[gitlabTemplate]
	for _, want := range []string{
		"if ! git fetch --depth=1 origin \"$base\"; then",
		"git ls-tree --name-only FETCH_HEAD -- \"$PC_POLICY\"",
	} {
		i := strings.Index(a, want)
		if i < 0 {
			t.Errorf("%s: no %q", gitlabTemplate, want)
		}
		if strings.HasPrefix(want, "if !") && i >= 0 && !strings.Contains(a[i:min(i+160, len(a))], "exit 2") {
			t.Errorf("%s: a failed fetch does not exit 2", gitlabTemplate)
		}
	}
	for l := range strings.SplitSeq(a, "\n") {
		if strings.Contains(l, "git ") && (strings.Contains(l, "--quiet") || strings.Contains(l, "/dev/null") || strings.Contains(l, "&&")) {
			t.Errorf("%s: a git failure can pass unseen: %s", gitlabTemplate, strings.TrimSpace(l))
		}
	}
}

// TestHR566_ACommentNeverDecidesTheCheck: exit 2 has no report, so it keeps
// the last one; failing to post warns, and the last step still ends the job
// with the check's own result (G0 M23 D133).
func TestHR566_ACommentNeverDecidesTheCheck(t *testing.T) {
	a := actions(t)["integrations/github-action/action.yml"]
	var step string
	for _, s := range regexp.MustCompile(`(?m)^    - name:`).Split(a, -1) {
		if strings.Contains(s, "Comment on the pull request") {
			step = s
		}
	}
	if step == "" {
		t.Fatal("no comment step")
	}
	for _, want := range []string{"steps.check.outputs.code != '2'", "if ! post; then", "::warning"} {
		if !strings.Contains(step, want) {
			t.Errorf("the comment step has no %q", want)
		}
	}
	if regexp.MustCompile(`set -[a-z]*e`).MatchString(step) || strings.Contains(step, "continue-on-error") {
		t.Error("a failure in the comment step can end the job, or hides how it ended")
	}
	if !strings.Contains(a, `run: exit "$CODE"`) {
		t.Error("the check's own result does not end the job")
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
