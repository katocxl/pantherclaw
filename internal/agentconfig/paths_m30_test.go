// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package agentconfig

import (
	"runtime"
	"testing"
)

// TestHR712_ClassifyNamesOnlyListedProjectFiles: Classify marks the listed
// project files and trees by class (G0 M30 D940), after slash-normalizing
// and resolving . and ..; a path that leaves the project, is absolute or is
// not listed names nothing.
func TestHR712_ClassifyNamesOnlyListedProjectFiles(t *testing.T) {
	for p, want := range map[string]PathClass{
		"CLAUDE.md":                       ClassMemory,
		`.claude\settings.json`:           ClassSettings,
		"src/../.mcp.json":                ClassMCP,
		".cursor/hooks.json":              ClassHooks,
		".cursor/rules/style/go.mdc":      ClassMemory,
		".claude/skills/review/SKILL.md":  ClassSkills,
		".github/copilot-instructions.md": ClassMemory,
	} {
		if got, ok := Classify(p); !ok || got != want {
			t.Errorf("%s: %q %v, want %q", p, got, ok, want)
		}
	}
	for _, p := range []string{
		"", ".", "main.go", "docs/CLAUDE.md", ".claude", ".cursor/rules", "../CLAUDE.md", "/etc/CLAUDE.md",
		`C:\repo\CLAUDE.md`, ".claude/settings.json.bak", ".claude/skillsx/a",
	} {
		if c, ok := Classify(p); ok {
			t.Errorf("%q classified as %q", p, c)
		}
	}
	// Names compare without case only where the file system does.
	if _, ok := Classify("claude.md"); ok != (runtime.GOOS == "windows") {
		t.Errorf("claude.md classified %v on %s", ok, runtime.GOOS)
	}
}
