// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package githubscan

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

// MCPConfigPaths are the committed MCP configuration files a scan reads,
// and nothing else of a repository's contents (HR-209).
var MCPConfigPaths = []string{".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"}

// maxMCPConfig is the largest configuration file read.
const maxMCPConfig = 256 << 10

// MCPServer is one server a configuration names, by names only: never a
// value, an argument, a URL or a header's content (HR-209).
type MCPServer struct {
	Name string
	// Command is the command's base name ("npx", "docker"); empty for a
	// remote server.
	Command string
	// Transport is "stdio" or "remote".
	Transport string
	// Env and Headers are the names of the environment variables and
	// headers it sets, sorted.
	Env, Headers []string
}

var errMCPConfig = errors.New("githubscan: not an MCP configuration")

// ParseMCPConfig reads a committed MCP configuration: {"mcpServers": {...}}
// (Claude Code, Cursor), {"servers": {...}} (VS Code), or both, merged.
// Every value is dropped here, in memory, before anything is kept:
// configuration files often hold literal tokens in environment values,
// headers, arguments or URLs. incomplete reports a server entry that did
// not decode, or a name under both keys (the first is kept): the file then
// holds more than the servers returned (#336 review).
func ParseMCPConfig(raw []byte) (servers []MCPServer, incomplete bool, err error) {
	if len(raw) > maxMCPConfig {
		return nil, false, errMCPConfig
	}
	var doc struct {
		MCPServers map[string]jsontext.Value `json:"mcpServers"`
		Servers    map[string]jsontext.Value `json:"servers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false, errMCPConfig
	}
	entries := maps.Clone(doc.MCPServers)
	if entries == nil {
		entries = map[string]jsontext.Value{}
	}
	for name, v := range doc.Servers {
		if _, twice := entries[name]; twice {
			incomplete = true
			continue
		}
		entries[name] = v
	}
	out := make([]MCPServer, 0, len(entries))
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		var s struct {
			Command string                    `json:"command"`
			URL     string                    `json:"url"`
			Env     map[string]jsontext.Value `json:"env"`
			Headers map[string]jsontext.Value `json:"headers"`
		}
		if json.Unmarshal(entries[name], &s) != nil {
			incomplete = true
			continue
		}
		m := MCPServer{Name: clip(name), Transport: "stdio", Env: names(s.Env), Headers: names(s.Headers)}
		switch {
		case s.Command != "":
			m.Command = commandName(s.Command)
		case s.URL != "":
			m.Transport = "remote"
		}
		out = append(out, m)
	}
	return out, incomplete, nil
}

// commandName is the base name of the program a command runs, and nothing
// else: arguments may carry secrets, and so may a path or a leading
// NAME=value assignment (PGPASSWORD=… psql), which is skipped like an
// argument. A word that is not a plain program name gives "".
func commandName(command string) string {
	for _, word := range strings.Fields(command) {
		if strings.Contains(word, "=") {
			continue // an environment assignment: its value is never kept
		}
		name := path.Base(strings.ReplaceAll(word, `\`, "/"))
		if !programName.MatchString(name) || secretShaped.MatchString(name) {
			return ""
		}
		return name
	}
	return ""
}

// programName is what a program's base name may be.
var programName = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)

func names(m map[string]jsontext.Value) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if n := clip(k); n != "" {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// secretShaped matches what looks like a credential rather than a name: a
// GitHub token, or a long opaque string. Such a "name" is never kept.
var secretShaped = regexp.MustCompile(`(gh[pousr]_|github_pat_)[A-Za-z0-9_]{16,}|[A-Za-z0-9+/=_-]{32,}`)

// clip keeps a name to printable ASCII of at most 64 bytes, and nothing
// that looks like a credential.
func clip(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return -1
		}
		return r
	}, s)
	if secretShaped.MatchString(s) {
		return ""
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
