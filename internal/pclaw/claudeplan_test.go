// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHR208_InitChangesNothingUntilConfirmed: init shows the diff and asks;
// no, or no answer at all, changes nothing; --yes changes without asking;
// and --dry-run with --yes is refused.
func TestHR208_InitChangesNothingUntilConfirmed(t *testing.T) {
	for _, answer := range []string{"n\n", "", "yes please\n"} {
		f := newInitFixture(t)
		f.answer = answer
		code, out, errs := f.run(t)
		if _, err := os.Stat(f.local()); code != 1 || err == nil || !strings.Contains(out, "+++ ") || !strings.Contains(out, "[y/N]") ||
			!strings.Contains(errs, "not confirmed") {
			t.Errorf("answer %q: %d %s %s", answer, code, out, errs)
		}
	}
	f := newInitFixture(t)
	f.answer = ""
	if code, out, errs := f.run(t, "--yes"); code != 0 || !hookRunsIn(t, f.local()) || strings.Contains(out, "[y/N]") {
		t.Errorf("--yes: %d %s %s", code, out, errs)
	}
	if code, _, _ := f.run(t, "--yes", "--dry-run"); code == 0 {
		t.Error("--yes with --dry-run")
	}
}

// answerAfterChanging answers yes at init's prompt after writing a file,
// as Claude Code may while the person reads the diff.
type answerAfterChanging struct {
	t             *testing.T
	path, content string
	answered      bool
}

func (r *answerAfterChanging) Read(p []byte) (int, error) {
	if r.answered {
		return 0, io.EOF
	}
	r.answered = true
	if err := os.MkdirAll(filepath.Dir(r.path), 0o700); err != nil {
		r.t.Error(err)
	}
	if err := os.WriteFile(r.path, []byte(r.content), 0o600); err != nil {
		r.t.Error(err)
	}
	return copy(p, "y\n"), nil
}

// TestHR208_InitWritesNothingWhenAFileChangedMeanwhile: a settings file
// that changed between init reading it and the person confirming (Claude
// Code added a deny rule to it, or created it) is not overwritten: init
// fails, writes and backs up nothing, and says to run it again, which
// keeps the change.
func TestHR208_InitWritesNothingWhenAFileChangedMeanwhile(t *testing.T) {
	added := strings.Replace(existingLocal, `"Read(./.env)"`, "\"Read(./.env)\",\n      \"Bash(rm:*)\"", 1)
	for name, before := range map[string]string{"changed": existingLocal, "created": ""} {
		f := newInitFixture(t)
		if before != "" {
			f.write(t, f.local(), before)
		}
		f.stdin = &answerAfterChanging{t: t, path: f.local(), content: added}
		code, out, errs := f.run(t)
		if now, _ := os.ReadFile(f.local()); code != 1 || string(now) != added || !strings.Contains(out, "[y/N]") ||
			!strings.Contains(errs, "changed after init read it") || !strings.Contains(errs, "run pclaw init again") {
			t.Errorf("%s: %d %s %s", name, code, out, errs)
		}
		if len(backups(t, f.local())) != 0 {
			t.Errorf("%s: backed up", name)
		}
		f.stdin = nil
		code, out, errs = f.run(t)
		perm, _ := readJSON(t, f.local())["permissions"].(map[string]any)
		deny, _ := perm["deny"].([]any)
		if code != 0 || !hookRunsIn(t, f.local()) || len(deny) != 3 || deny[2] != "Bash(rm:*)" {
			t.Errorf("%s, run again: %d %s %s", name, code, out, errs)
		}
	}
}
