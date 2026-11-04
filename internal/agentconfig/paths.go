// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package agentconfig names the files that configure a coding agent or hold
// its memory: settings, MCP server lists, hooks, memory files and skills
// (G0 M30 D940). The local scan reports their digests (D941), the Claude
// Code hook asks the gateway before an agent writes one (D943), and the
// containment sandbox keeps them read-only (D944). The package only names
// paths; it reads nothing.
package agentconfig

import (
	"path"
	"runtime"
	"strings"
)

// PathClass is what a protected file configures.
type PathClass string

// Path classes.
const (
	ClassSettings PathClass = "settings"
	ClassMCP      PathClass = "mcp"
	ClassHooks    PathClass = "hooks"
	ClassMemory   PathClass = "memory"
	ClassSkills   PathClass = "skills"
)

// Classes are every path class, in order.
var Classes = []PathClass{ClassSettings, ClassMCP, ClassHooks, ClassMemory, ClassSkills}

// Scope says whose file it is: the user's, or a project's.
type Scope string

// Scopes.
const (
	ScopeUser    Scope = "user"
	ScopeProject Scope = "project"
)

// Root is the directory an entry's glob is relative to.
type Root string

// Roots.
const (
	// RootProject is a project directory (ScopeProject).
	RootProject Root = "project"
	// RootHome is the user's home directory (os.UserHomeDir).
	RootHome Root = "home"
	// RootConfig is the user's configuration directory (os.UserConfigDir:
	// %APPDATA% on Windows, $XDG_CONFIG_HOME on Linux).
	RootConfig Root = "config"
)

// Entry is one protected file, or a tree of them.
type Entry struct {
	Client string
	Scope  Scope
	Root   Root
	// Glob is slash-separated and relative to Root: a literal path, or a
	// directory followed by "/**" for every file below it.
	Glob  string
	Class PathClass
	// Servers is the member path to an MCP configuration's servers object,
	// nil for a file the scan does not read servers from.
	Servers []string
	// Hooks: the file can hold hooks the scan lists.
	Hooks bool
}

// Tree reports whether the entry names every file below a directory, and
// that directory.
func (e Entry) Tree() (string, bool) {
	return strings.CutSuffix(e.Glob, "/**")
}

// Entries are the protected files, in the order the scan reads them: the
// MCP configurations, settings, hook files and skill directories of the
// clients the local scan knows (internal/scan), and the memory files
// coding agents read. The JetBrains configurations, whose paths the IDEs'
// registries set, and $CODEX_HOME and $GEMINI_CLI_HOME stay in the scan.
var Entries = []Entry{
	// The user's configuration directory.
	{Client: "claude_desktop", Scope: ScopeUser, Root: RootConfig, Glob: "Claude/claude_desktop_config.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "vscode", Scope: ScopeUser, Root: RootConfig, Glob: "Code/User/mcp.json", Class: ClassMCP, Servers: []string{"servers"}},
	{Client: "vscode", Scope: ScopeUser, Root: RootConfig, Glob: "Code/User/settings.json", Class: ClassSettings, Servers: []string{"mcp", "servers"}},
	{Client: "devin_desktop", Scope: ScopeUser, Root: RootConfig, Glob: "devin/mcp_config.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "zed", Scope: ScopeUser, Root: RootConfig, Glob: "zed/settings.json", Class: ClassSettings, Servers: []string{"context_servers"}},

	// The user's home directory.
	{Client: "claude_desktop", Scope: ScopeUser, Root: RootHome, Glob: "Library/Application Support/Claude/claude_desktop_config.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "claude_code", Scope: ScopeUser, Root: RootHome, Glob: ".claude.json", Class: ClassSettings, Servers: []string{"mcpServers"}},
	{Client: "cursor", Scope: ScopeUser, Root: RootHome, Glob: ".cursor/mcp.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "windsurf", Scope: ScopeUser, Root: RootHome, Glob: ".codeium/windsurf/mcp_config.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "devin_desktop", Scope: ScopeUser, Root: RootHome, Glob: ".config/devin/mcp_config.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "zed", Scope: ScopeUser, Root: RootHome, Glob: ".config/zed/settings.json", Class: ClassSettings, Servers: []string{"context_servers"}},
	{Client: "junie", Scope: ScopeUser, Root: RootHome, Glob: ".junie/mcp/mcp.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "jetbrains_ai", Scope: ScopeUser, Root: RootHome, Glob: ".ai/mcp/mcp.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "codex", Scope: ScopeUser, Root: RootHome, Glob: ".codex/config.toml", Class: ClassSettings, Servers: []string{"mcp_servers"}},
	{Client: "gemini_cli", Scope: ScopeUser, Root: RootHome, Glob: ".gemini/settings.json", Class: ClassSettings, Servers: []string{"mcpServers"}, Hooks: true},
	{Client: "claude_code", Scope: ScopeUser, Root: RootHome, Glob: ".claude/settings.json", Class: ClassSettings, Hooks: true},
	{Client: "cursor", Scope: ScopeUser, Root: RootHome, Glob: ".cursor/hooks.json", Class: ClassHooks, Hooks: true},
	{Client: "claude_code", Scope: ScopeUser, Root: RootHome, Glob: ".claude/CLAUDE.md", Class: ClassMemory},
	{Client: "claude_code", Scope: ScopeUser, Root: RootHome, Glob: ".claude/skills/**", Class: ClassSkills},
	{Client: "cursor", Scope: ScopeUser, Root: RootHome, Glob: ".cursor/skills/**", Class: ClassSkills},
	{Client: "codex", Scope: ScopeUser, Root: RootHome, Glob: ".codex/skills/**", Class: ClassSkills},
	{Client: "gemini_cli", Scope: ScopeUser, Root: RootHome, Glob: ".gemini/skills/**", Class: ClassSkills},

	// A project directory.
	{Client: "project", Scope: ScopeProject, Root: RootProject, Glob: ".mcp.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "cursor", Scope: ScopeProject, Root: RootProject, Glob: ".cursor/mcp.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "vscode", Scope: ScopeProject, Root: RootProject, Glob: ".vscode/mcp.json", Class: ClassMCP, Servers: []string{"servers"}},
	{Client: "zed", Scope: ScopeProject, Root: RootProject, Glob: ".zed/settings.json", Class: ClassSettings, Servers: []string{"context_servers"}},
	{Client: "junie", Scope: ScopeProject, Root: RootProject, Glob: ".junie/mcp/mcp.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "jetbrains_ai", Scope: ScopeProject, Root: RootProject, Glob: ".ai/mcp/mcp.json", Class: ClassMCP, Servers: []string{"mcpServers"}},
	{Client: "codex", Scope: ScopeProject, Root: RootProject, Glob: ".codex/config.toml", Class: ClassSettings, Servers: []string{"mcp_servers"}},
	{Client: "gemini_cli", Scope: ScopeProject, Root: RootProject, Glob: ".gemini/settings.json", Class: ClassSettings, Servers: []string{"mcpServers"}, Hooks: true},
	{Client: "claude_code", Scope: ScopeProject, Root: RootProject, Glob: ".claude/settings.json", Class: ClassSettings, Hooks: true},
	{Client: "claude_code", Scope: ScopeProject, Root: RootProject, Glob: ".claude/settings.local.json", Class: ClassSettings, Hooks: true},
	{Client: "cursor", Scope: ScopeProject, Root: RootProject, Glob: ".cursor/hooks.json", Class: ClassHooks, Hooks: true},
	{Client: "claude_code", Scope: ScopeProject, Root: RootProject, Glob: "CLAUDE.md", Class: ClassMemory},
	{Client: "claude_code", Scope: ScopeProject, Root: RootProject, Glob: "CLAUDE.local.md", Class: ClassMemory},
	{Client: "agents_md", Scope: ScopeProject, Root: RootProject, Glob: "AGENTS.md", Class: ClassMemory},
	{Client: "gemini_cli", Scope: ScopeProject, Root: RootProject, Glob: "GEMINI.md", Class: ClassMemory},
	{Client: "cursor", Scope: ScopeProject, Root: RootProject, Glob: ".cursorrules", Class: ClassMemory},
	{Client: "windsurf", Scope: ScopeProject, Root: RootProject, Glob: ".windsurfrules", Class: ClassMemory},
	{Client: "copilot", Scope: ScopeProject, Root: RootProject, Glob: ".github/copilot-instructions.md", Class: ClassMemory},
	{Client: "cursor", Scope: ScopeProject, Root: RootProject, Glob: ".cursor/rules/**", Class: ClassMemory},
	{Client: "claude_code", Scope: ScopeProject, Root: RootProject, Glob: ".claude/skills/**", Class: ClassSkills},
	{Client: "cursor", Scope: ScopeProject, Root: RootProject, Glob: ".cursor/skills/**", Class: ClassSkills},
	{Client: "codex", Scope: ScopeProject, Root: RootProject, Glob: ".codex/skills/**", Class: ClassSkills},
	{Client: "gemini_cli", Scope: ScopeProject, Root: RootProject, Glob: ".gemini/skills/**", Class: ClassSkills},
}

// OfRoot returns the entries relative to root, in table order.
func OfRoot(root Root) []Entry {
	var out []Entry
	for _, e := range Entries {
		if e.Root == root {
			out = append(out, e)
		}
	}
	return out
}

// foldCase: file names compare without case where the file system does.
var foldCase = runtime.GOOS == "windows"

// Classify says whether a project-relative path names a protected file, and
// its class. The path is slash-normalized first (a backslash is a separator,
// "." and ".." are resolved); one that leaves the project names nothing.
// Names compare case-sensitively, except on Windows.
func Classify(relPath string) (PathClass, bool) {
	e, ok := Match(relPath)
	return e.Class, ok
}

// Match is Classify returning the project entry that matched.
func Match(relPath string) (Entry, bool) {
	p := Normalize(relPath)
	if p == "" {
		return Entry{}, false
	}
	for _, e := range Entries {
		if e.Root == RootProject && matches(e.Glob, p) {
			return e, true
		}
	}
	return Entry{}, false
}

// Normalize is the slash-separated, cleaned form of a relative path, ""
// for one that is absolute, empty or leaves its root.
func Normalize(relPath string) string {
	p := strings.ReplaceAll(relPath, `\`, "/")
	if p == "" || strings.HasPrefix(p, "/") || (len(p) >= 2 && p[1] == ':') {
		return ""
	}
	p = path.Clean(p)
	if p == "." || p == ".." || strings.HasPrefix(p, "../") {
		return ""
	}
	return p
}

// matches compares a cleaned relative path with a glob.
func matches(glob, p string) bool {
	if foldCase {
		glob, p = strings.ToLower(glob), strings.ToLower(p)
	}
	if dir, tree := strings.CutSuffix(glob, "/**"); tree {
		return strings.HasPrefix(p, dir+"/")
	}
	return glob == p
}
