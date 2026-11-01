// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Limits of the hook and skill readers.
const (
	maxHooksPerFile = 256
	maxSkillsPerDir = 500
)

var (
	// hookEvent is what an event name looks like. A member name is free text,
	// so anything else is skipped rather than reported.
	hookEvent = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
	// executableName is what the basename of an executable looks like.
	executableName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	// assignment is a NAME=value that comes before a command in a shell line.
	assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// hookFiles returns the settings files that can hold hooks.
func hookFiles(o Options) []string {
	var out []string
	if o.Home != "" {
		out = append(out, filepath.Join(o.Home, ".claude", "settings.json"), filepath.Join(o.Home, ".cursor", "hooks.json"),
			filepath.Join(o.Home, ".gemini", "settings.json"))
	}
	for _, p := range o.Paths {
		out = append(out, filepath.Join(p, ".claude", "settings.json"), filepath.Join(p, ".claude", "settings.local.json"),
			filepath.Join(p, ".cursor", "hooks.json"), filepath.Join(p, ".gemini", "settings.json"))
	}
	return out
}

// hookFindings reports each hook of a settings file: its event and the
// basename of what it runs. Everything else stays here: the rest of the
// command line, a matcher, and a prompt or URL hook's text.
func hookFindings(host, path string, read func(string) []byte) []Finding {
	hooks, _ := configOf(path, read(path))["hooks"].(map[string]any)
	var out []Finding
	for event, entries := range hooks {
		list, _ := entries.([]any)
		if !hookEvent.MatchString(event) {
			continue
		}
		for _, entry := range list {
			if len(out) >= maxHooksPerFile {
				return out
			}
			m, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			// Claude Code and Gemini CLI nest a list under a matcher; Cursor
			// lists the hooks themselves.
			inner, nested := m["hooks"].([]any)
			if !nested {
				inner = []any{m}
			}
			for _, h := range inner {
				if len(out) >= maxHooksPerFile {
					return out
				}
				hm, ok := h.(map[string]any)
				if !ok {
					continue
				}
				command, _ := hm["command"].(string)
				exe := executableOf(command)
				attrs := map[string]string{"event": event, "host": clip(host)}
				if exe != "" {
					attrs["executable"] = exe
				}
				out = append(out, Finding{Kind: KindHook, Key: key(KindHook, host, path, event, exe), Attributes: attrs})
			}
		}
	}
	return out
}

// executableOf returns the basename of what a shell line runs, "" when the
// line does not start with a plain name: NAME=value prefixes are passed over,
// and nothing after the first word is read.
func executableOf(line string) string {
	for {
		word, rest := firstWord(line)
		if word == "" {
			return ""
		}
		if assignment.MatchString(word) {
			line = rest
			continue
		}
		base := baseName(word)
		if !executableName.MatchString(base) {
			return ""
		}
		return base
	}
}

// firstWord splits off a shell line's first word, with its quotes removed.
func firstWord(line string) (word, rest string) {
	line = strings.TrimLeft(line, " \t\r\n")
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0 && c == quote:
			quote = 0
		case quote != 0:
			b.WriteByte(c)
		case c == '"' || c == '\'':
			quote = c
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			return b.String(), line[i:]
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), ""
}

// skillDirs returns the directories that hold agent skills.
func skillDirs(o Options) []string {
	var out []string
	add := func(root string) {
		for _, d := range []string{".claude", ".cursor", ".codex", ".gemini"} {
			out = append(out, filepath.Join(root, d, "skills"))
		}
	}
	if o.Home != "" {
		add(o.Home)
	}
	for _, p := range o.Paths {
		add(p)
	}
	return out
}

// skillFindings reports each skill under dir by name and path. A skill is a
// directory holding SKILL.md, whose presence is checked; the file is never
// opened.
func skillFindings(o Options, dir string) []Finding {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Finding
	for _, e := range entries {
		if len(out) >= maxSkillsPerDir {
			break
		}
		path := filepath.Join(dir, e.Name())
		file := filepath.Join(path, "SKILL.md")
		if !e.IsDir() || !o.allowed(file) {
			continue
		}
		stat := os.Stat
		if o.Contained {
			stat = os.Lstat // The same no-link rule as o.reader (D287).
		}
		if info, err := stat(file); err != nil || !info.Mode().IsRegular() {
			continue
		}
		out = append(out, Finding{Kind: KindSkill, Key: key(KindSkill, o.Host, path), Attributes: map[string]string{
			"name": clip(e.Name()), "path": clip(path), "host": clip(o.Host),
		}})
	}
	return out
}

// allowed says whether the scan may read path. A scan of another person's
// home (Options.Contained) stays inside it and follows no symbolic link: it
// runs as root or SYSTEM and that person owns what is there.
func (o Options) allowed(path string) bool {
	if !o.Contained {
		return true
	}
	rel, err := filepath.Rel(o.Home, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return false
	}
	at := o.Home
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		at = filepath.Join(at, part)
		info, err := os.Lstat(at)
		// A Windows junction is ModeIrregular, and no privilege is needed to
		// make one.
		if err != nil || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return false
		}
	}
	return true
}
