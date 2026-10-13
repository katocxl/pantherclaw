// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// initPlan is everything `pclaw init` would change. All of it is shown,
// and none of it is done until the person confirms (HR-208).
type initPlan struct {
	// edits are the files init adds to, their documents changed in place.
	edits []*claudeSettings
	// done is printed once the changes are made.
	done []string
}

// file is the plan's copy of a file, so two additions to one file land in
// one document.
func (p *initPlan) file(s claudeSettings) *claudeSettings {
	for _, e := range p.edits {
		if samePath(e.path, s.path) {
			return e
		}
	}
	p.edits = append(p.edits, &s)
	return &s
}

// addHook adds the hook to the target file's PreToolUse hooks.
func (p *initPlan) addHook(target claudeSettings, hook *jsonNode) error {
	s := p.file(target)
	hooks, ok := s.doc.object("hooks")
	if !ok {
		return &exitError{code: 1, msg: "pclaw init: " + s.path + ": hooks is not an object; it is left as it is"}
	}
	pre, ok := hooks.array("PreToolUse")
	if !ok {
		return &exitError{code: 1, msg: "pclaw init: " + s.path + ": hooks.PreToolUse is not a list; it is left as it is"}
	}
	pre.items = append(pre.items, hook)
	p.done = append(p.done, "Every Bash and PowerShell command now asks PantherClaw first; when it cannot answer, the command is blocked.")
	return nil
}

func samePath(a, b string) bool {
	a, b = filepath.ToSlash(filepath.Clean(a)), filepath.ToSlash(filepath.Clean(b))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// initWrite is one file init replaces: the bytes the plan was made from
// (nil for a file that did not exist) and the new content.
type initWrite struct {
	path          string
	before, after []byte
}

// unchanged fails when a file is no longer what the plan was made from.
// Claude Code rewrites its settings and ~/.claude.json while it runs, and
// the person may take a while to answer, so writing the plan then would
// lose what changed meanwhile (a deny rule added, say).
func unchanged(writes []initWrite) error {
	for _, w := range writes {
		now, err := os.ReadFile(w.path)
		if errors.Is(err, os.ErrNotExist) {
			now = nil
		} else if err != nil {
			return err
		}
		if (now == nil) != (w.before == nil) || !bytes.Equal(now, w.before) {
			return &exitError{code: 1, msg: "pclaw init: " + w.path + " changed after init read it (Claude Code rewrites its settings " +
				"while it runs); nothing was changed, so run pclaw init again"}
		}
	}
	return nil
}

// apply shows the plan, asks, and carries it out: each file, unless it
// changed since the plan was made, is backed up and replaced through a
// temporary file.
func (f initFlags) apply(a *app, p *initPlan) error {
	var writes []initWrite
	for _, s := range p.edits {
		after, err := s.doc.encode()
		if err != nil {
			return err
		}
		if after = likeOriginal(s.raw, after); bytes.Equal(after, s.raw) {
			continue
		}
		if _, err := fmt.Fprint(a.stdout, lineDiff(s.path, s.raw, after)); err != nil {
			return err
		}
		writes = append(writes, initWrite{s.path, s.raw, after})
	}
	switch {
	case len(writes) == 0:
		_, err := fmt.Fprintln(a.stdout, "Nothing to change.")
		return err
	case f.dryRun:
		_, err := fmt.Fprintln(a.stdout, "Dry run: nothing was changed.")
		return err
	case !f.yes && !confirm(a, "Make these changes?"):
		return &exitError{code: 1, msg: "pclaw init: not confirmed; nothing was changed"}
	}
	if err := unchanged(writes); err != nil {
		return err
	}
	for _, w := range writes {
		backup, err := backupFile(w.path, time.Now())
		if err != nil {
			return err
		}
		if err := writeAtomically(w.path, w.after); err != nil {
			return err
		}
		if backup != "" {
			_, _ = fmt.Fprintf(a.stdout, "Backed up %s to %s.\n", w.path, backup)
		}
		_, _ = fmt.Fprintf(a.stdout, "Wrote %s.\n", w.path)
	}
	for _, d := range p.done {
		_, _ = fmt.Fprintln(a.stdout, d)
	}
	return nil
}

// confirm asks on stdout and reads one line from stdin: only y or yes
// agrees, and no answer (end of input) is no.
func confirm(a *app, question string) bool {
	_, _ = fmt.Fprintf(a.stdout, "%s [y/N] ", question)
	line, _ := bufio.NewReader(io.LimitReader(a.stdin, 64)).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	_, _ = fmt.Fprintln(a.stdout)
	return false
}
