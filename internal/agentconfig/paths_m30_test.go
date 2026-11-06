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
	// Names compare without case on every host (D1215).
	for p, want := range map[string]PathClass{"claude.md": ClassMemory, ".Claude/Settings.json": ClassSettings, "Agents.md": ClassMemory} {
		if got, ok := Classify(p); !ok || got != want {
			t.Errorf("%s on %s: %q %v, want %q", p, runtime.GOOS, got, ok, want)
		}
	}
}

// TestHR712_UserScopePathsMatchTheirRoot (G0 M30 D1215): home-relative
// paths match the home entries and configuration-directory paths the
// configuration entries; neither matches as a project path, and a project
// path does not match the home table.
func TestHR712_UserScopePathsMatchTheirRoot(t *testing.T) {
	for _, c := range []struct {
		root Root
		p    string
		want PathClass
	}{
		{RootHome, ".claude/CLAUDE.md", ClassMemory},
		{RootHome, ".claude.json", ClassSettings},
		{RootHome, ".Codeium/Windsurf/mcp_config.json", ClassMCP},
		{RootConfig, "Claude/claude_desktop_config.json", ClassMCP},
		{RootConfig, "Code/User/mcp.json", ClassMCP},
	} {
		if e, ok := MatchRoot(c.root, c.p); !ok || e.Class != c.want || e.Scope != ScopeUser {
			t.Errorf("%s %s: %+v %v", c.root, c.p, e, ok)
		}
		if _, ok := Classify(c.p); ok {
			t.Errorf("%s matched as a project path", c.p)
		}
	}
	if _, ok := MatchRoot(RootHome, "AGENTS.md"); ok {
		t.Error("a project path matched the home table")
	}
}
