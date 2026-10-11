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
// (Claude Code, Cursor) or {"servers": {...}} (VS Code). Every value is
// dropped here, in memory, before anything is kept: configuration files
// often hold literal tokens in environment values, headers, arguments or
// URLs.
func ParseMCPConfig(raw []byte) ([]MCPServer, error) {
	if len(raw) > maxMCPConfig {
		return nil, errMCPConfig
	}
	var doc struct {
		MCPServers map[string]jsontext.Value `json:"mcpServers"`
		Servers    map[string]jsontext.Value `json:"servers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errMCPConfig
	}
	servers := doc.MCPServers
	if servers == nil {
		servers = doc.Servers
	}
	out := make([]MCPServer, 0, len(servers))
	for _, name := range slices.Sorted(maps.Keys(servers)) {
		var s struct {
			Command string                    `json:"command"`
			URL     string                    `json:"url"`
			Env     map[string]jsontext.Value `json:"env"`
			Headers map[string]jsontext.Value `json:"headers"`
		}
		if json.Unmarshal(servers[name], &s) != nil {
			continue
		}
		m := MCPServer{Name: clip(name), Transport: "stdio", Env: names(s.Env), Headers: names(s.Headers)}
		switch {
		case s.Command != "":
			// The base name of the first word only: arguments may carry
			// secrets, and so may a path.
			first, _, _ := strings.Cut(strings.TrimSpace(s.Command), " ")
			m.Command = clip(path.Base(strings.ReplaceAll(first, `\`, "/")))
		case s.URL != "":
			m.Transport = "remote"
		}
		out = append(out, m)
	}
	return out, nil
}

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
