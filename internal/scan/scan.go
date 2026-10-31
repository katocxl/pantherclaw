// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package scan is the local shadow-agent scan behind `pclaw scan`
// (PN-001.1, F015). It reads, and never changes, the MCP configurations of
// Claude Desktop, Claude Code, Cursor, VS Code, Windsurf (now Devin
// Desktop), Zed, JetBrains Junie and AI Assistant, OpenAI Codex CLI and
// Google Gemini CLI, looks for agent-framework projects under the given directories, and checks
// the environment and the servers' configured environment, HTTP headers and
// OAuth client secrets for credentials agents use, PantherClaw pck_ keys
// included. It also lists hooks (event and executable basename) and skills
// (name and path), never a command's other arguments, a prompt or a skill's
// contents (G0 M24 D233, HR-588). Secrets never appear in a finding: only the
// variable or header name, the kind of credential and its well-known prefix.
// Findings stay on the machine unless submitted.
package scan

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

// Finding kinds.
const (
	KindMCPServer    = "mcp_server"
	KindAgentProject = "agent_project"
	KindEnvSecret    = "env_secret"
	KindHook         = "hook"
	KindSkill        = "skill"
)

// Limits keep a scan bounded on large trees. MaxNesting bounds the nesting
// of an XML configuration, as the strict JSON readers do (HR-100).
const (
	MaxDepth    = 5
	MaxFiles    = 20000
	MaxFileSize = 1 << 20
	MaxNesting  = 32
	maxValue    = 256
)

// Finding is one thing the scan found. Attributes are what a person needs to
// recognize it; they never hold a secret.
type Finding struct {
	Kind       string            `json:"kind"`
	Key        string            `json:"key"` // stable per machine: hex SHA-256
	Attributes map[string]string `json:"attributes"`
}

// Options say where to look.
type Options struct {
	// Host names the machine in finding keys and attributes.
	Host string
	// Home and ConfigDir locate the per-user configurations
	// (os.UserHomeDir, os.UserConfigDir).
	Home, ConfigDir string
	// CodexHome and GeminiCLIHome are $CODEX_HOME and $GEMINI_CLI_HOME,
	// which move those clients' per-user configuration.
	CodexHome, GeminiCLIHome string
	// Paths are project directories to walk (at most MaxDepth deep).
	Paths []string
	// Environ is the environment to check (os.Environ).
	Environ []string
	// Contained reads only inside Home and follows no symbolic link there:
	// the scan of another person's home, as root or SYSTEM (D235).
	Contained bool
}

func key(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// clip keeps at most maxValue bytes of valid UTF-8, cutting on a rune
// boundary (a protobuf string field refuses invalid UTF-8).
func clip(s string) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= maxValue {
		return s
	}
	s = s[:maxValue]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// Run scans and returns the findings, sorted by kind and key.
func Run(o Options) []Finding {
	var out []Finding
	var read []os.FileInfo
	for _, c := range clientConfigs(o) {
		if !o.allowed(c.path) {
			continue
		}
		// Read each file once, even when two locations name it (a
		// case-insensitive file system, a symlinked ~/.config).
		info, err := os.Stat(c.path)
		if err != nil || slices.ContainsFunc(read, func(r os.FileInfo) bool { return os.SameFile(r, info) }) {
			continue
		}
		read = append(read, info)
		out = append(out, mcpFindings(o.Host, c.client, c.path, c.servers)...)
	}
	for _, p := range o.Paths {
		out = append(out, projects(o, p)...)
	}
	for _, path := range hookFiles(o) {
		if o.allowed(path) {
			out = append(out, hookFindings(o.Host, path)...)
		}
	}
	for _, dir := range skillDirs(o) {
		if o.allowed(dir) {
			out = append(out, skillFindings(o, dir)...)
		}
	}
	out = append(out, envSecrets(o.Host, "environment", o.Environ)...)
	slices.SortFunc(out, func(a, b Finding) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
	return slices.CompactFunc(out, func(a, b Finding) bool { return a.Key == b.Key })
}

// clientConfig is one MCP configuration file and the path to its servers.
type clientConfig struct {
	client, path string
	servers      []string // member path to the servers object
}

func clientConfigs(o Options) []clientConfig {
	var out []clientConfig
	add := func(client, path string, servers ...string) {
		if path != "" {
			out = append(out, clientConfig{client: client, path: path, servers: servers})
		}
	}
	// The AI Assistant's mcp.json paths that the IDEs' registries set, read
	// beside the default ones.
	var jbGlobal, jbProject []string
	if o.ConfigDir != "" {
		add("claude_desktop", filepath.Join(o.ConfigDir, "Claude", "claude_desktop_config.json"), "mcpServers")
		add("vscode", filepath.Join(o.ConfigDir, "Code", "User", "mcp.json"), "servers")
		add("vscode", filepath.Join(o.ConfigDir, "Code", "User", "settings.json"), "mcp", "servers")
		// %APPDATA% on Windows, $XDG_CONFIG_HOME on Linux.
		add("devin_desktop", filepath.Join(o.ConfigDir, "devin", "mcp_config.json"), "mcpServers")
		add("zed", filepath.Join(o.ConfigDir, "zed", "settings.json"), "context_servers")
		jetBrains := filepath.Join(o.ConfigDir, "JetBrains")
		for _, p := range jetBrainsConfigs(jetBrains) {
			add("jetbrains_ai", p, "mcpServers")
		}
		jbGlobal, jbProject = jetBrainsMCPJSONPaths(jetBrains)
	}
	if o.Home != "" {
		add("claude_desktop", filepath.Join(o.Home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), "mcpServers")
		add("claude_code", filepath.Join(o.Home, ".claude.json"), "mcpServers")
		add("cursor", filepath.Join(o.Home, ".cursor", "mcp.json"), "mcpServers")
		add("windsurf", filepath.Join(o.Home, ".codeium", "windsurf", "mcp_config.json"), "mcpServers")
		add("devin_desktop", filepath.Join(o.Home, ".config", "devin", "mcp_config.json"), "mcpServers")
		add("zed", filepath.Join(o.Home, ".config", "zed", "settings.json"), "context_servers")
		add("junie", filepath.Join(o.Home, ".junie", "mcp", "mcp.json"), "mcpServers")
		add("jetbrains_ai", filepath.Join(o.Home, ".ai", "mcp", "mcp.json"), "mcpServers")
		for _, p := range jbGlobal {
			add("jetbrains_ai", resolvePath(o.Home, p), "mcpServers")
		}
		add("codex", filepath.Join(o.Home, ".codex", "config.toml"), "mcp_servers")
		add("gemini_cli", filepath.Join(o.Home, ".gemini", "settings.json"), "mcpServers")
	}
	if o.CodexHome != "" {
		add("codex", filepath.Join(o.CodexHome, "config.toml"), "mcp_servers")
	}
	if o.GeminiCLIHome != "" {
		add("gemini_cli", filepath.Join(o.GeminiCLIHome, ".gemini", "settings.json"), "mcpServers")
	}
	for _, p := range o.Paths {
		add("project", filepath.Join(p, ".mcp.json"), "mcpServers")
		add("cursor", filepath.Join(p, ".cursor", "mcp.json"), "mcpServers")
		add("vscode", filepath.Join(p, ".vscode", "mcp.json"), "servers")
		add("zed", filepath.Join(p, ".zed", "settings.json"), "context_servers")
		add("junie", filepath.Join(p, ".junie", "mcp", "mcp.json"), "mcpServers")
		add("jetbrains_ai", filepath.Join(p, ".ai", "mcp", "mcp.json"), "mcpServers")
		for _, j := range jbProject {
			add("jetbrains_ai", resolvePath(p, j), "mcpServers")
		}
		for _, w := range jetBrainsWorkspaces(p) {
			add("jetbrains_ai", w, "mcpServers")
		}
		add("codex", filepath.Join(p, ".codex", "config.toml"), "mcp_servers")
		add("gemini_cli", filepath.Join(p, ".gemini", "settings.json"), "mcpServers")
	}
	return out
}

// afterCheck runs between a file's check and its read; tests replace it.
var afterCheck = func() {}

// openRegular opens path and checks the open file, or returns nil: what is
// read is what was checked, whatever replaces the name meanwhile (G0 M24
// D254). Opening does not wait, so a FIFO cannot hang the scan.
func openRegular(path string) *os.File {
	f, err := os.OpenFile(path, os.O_RDONLY|openNoWait, 0) //nolint:gosec // G304: scanning the user's own configuration
	if err != nil {
		return nil
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxFileSize {
		_ = f.Close()
		return nil
	}
	return f
}

// readFile reads a regular file of at most MaxFileSize bytes, or returns nil.
func readFile(path string) []byte {
	f := openRegular(path)
	if f == nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	afterCheck()
	b, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil || len(b) > MaxFileSize {
		return nil
	}
	return b
}

// readConfig reads a JSON, JSONC, TOML (Codex) or JetBrains XML file into
// an object; anything else is skipped.
func readConfig(path string) map[string]any {
	b := readFile(path)
	if b == nil {
		return nil
	}
	var v map[string]any
	switch filepath.Ext(path) {
	case ".toml":
		if _, err := toml.Decode(string(b), &v); err != nil {
			return nil
		}
		return v
	case ".xml":
		return fromJetBrainsXML(b)
	}
	if json.Unmarshal(fromJSONC(b), &v, jsontext.AllowDuplicateNames(true)) != nil {
		return nil
	}
	return v
}

// fromJSONC removes what JSONC allows and JSON does not (VS Code and Zed
// settings): // and /* */ comments, and a comma before a closing bracket.
func fromJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inStr, esc := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case inStr:
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && (b[i] != '*' || b[i+1] != '/') {
				i++
			}
			i++
		case c == '}' || c == ']':
			// Outside a string, the last byte before the bracket that is
			// not white space is structural, so a comma there is trailing.
			j := len(out)
			for j > 0 && strings.IndexByte(" \t\r\n", out[j-1]) >= 0 {
				j--
			}
			if j > 0 && out[j-1] == ',' {
				out = append(out[:j-1], out[j:]...)
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

func member(v map[string]any, path []string) map[string]any {
	for _, p := range path {
		next, ok := v[p].(map[string]any)
		if !ok {
			return nil
		}
		v = next
	}
	return v
}

func mcpFindings(host, client, path string, serversAt []string) []Finding {
	doc := readConfig(path)
	if doc == nil {
		return nil
	}
	groups := []map[string]any{member(doc, serversAt)}
	if client == "jetbrains_ai" {
		groups[0] = jetBrainsServers(doc)
	}
	if client == "claude_code" {
		// ~/.claude.json also keeps per-project servers.
		if projects, ok := doc["projects"].(map[string]any); ok {
			for _, p := range projects {
				if pm, ok := p.(map[string]any); ok {
					groups = append(groups, member(pm, serversAt))
				}
			}
		}
	}
	var out []Finding
	for _, servers := range groups {
		for name, raw := range servers {
			s, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			attrs := map[string]string{"client": client, "config": clip(path), "name": clip(name), "host": clip(host)}
			where := client + " " + name
			cmd, _ := s["command"].(string)
			env, _ := s["env"].(map[string]any)
			args := s["args"]
			if nested, ok := s["command"].(map[string]any); ok { // older Zed: {"command": {"path", "args", "env"}}
				cmd, _ = nested["path"].(string)
				env, _ = nested["env"].(map[string]any)
				args = nested["args"]
			}
			if cmd != "" {
				attrs["transport"], attrs["command"] = "stdio", clip(filepath.Base(cmd))
				if ref := packageRef(cmd, stringArgs(args)); ref != "" {
					attrs["package_ref"] = ref
				}
			}
			// serverUrl: Windsurf and Devin Desktop; httpUrl: Gemini CLI.
			if u := firstString(s, "url", "serverUrl", "httpUrl"); u != "" {
				attrs["transport"] = "http"
				if pu, err := url.Parse(u); err == nil {
					attrs["url_host"] = clip(pu.Host) // never the path or query: tokens live there
				}
			}
			var envNames, headerNames []string
			for k, v := range env {
				envNames = append(envNames, k)
				if val, ok := v.(string); ok {
					out = append(out, envSecrets(host, where, []string{k + "=" + val})...)
				}
			}
			for _, field := range []string{"headers", "http_headers"} { // http_headers: Codex
				headers, _ := s[field].(map[string]any)
				for k, v := range headers {
					headerNames = append(headerNames, k)
					if val, ok := v.(string); ok {
						out = append(out, headerSecrets(host, where+" headers", k, val)...)
					}
				}
			}
			// Codex names the environment variables a server inherits
			// (env_vars) and those that hold its bearer token and header
			// values. The names are listed; the variables are not looked up.
			ref := func(where, field string, v any) {
				n, found := varRef(host, where, field, v)
				if n != "" {
					envNames = append(envNames, n)
				}
				out = append(out, found...)
			}
			if vars, ok := s["env_vars"].([]any); ok {
				for _, v := range vars {
					if m, ok := v.(map[string]any); ok { // {name = "X", source = "remote"}
						v = m["name"]
					}
					ref(where, "env_vars", v)
				}
			}
			if v, ok := s["bearer_token_env_var"]; ok {
				headerNames = append(headerNames, "Authorization")
				ref(where, "bearer_token_env_var", v)
			}
			if headers, ok := s["env_http_headers"].(map[string]any); ok {
				for k, v := range headers {
					headerNames = append(headerNames, k)
					ref(where+" env_http_headers", k, v)
				}
			}
			// Codex refuses a literal bearer_token, but the file can still
			// hold one.
			if v, ok := s["bearer_token"].(string); ok {
				out = append(out, valueSecrets(host, where, "bearer_token", "", v, "http_credential")...)
			}
			if oauth, ok := s["oauth"].(map[string]any); ok {
				for _, field := range []string{"clientSecret", "client_secret"} { // Gemini CLI, Codex
					if v, ok := oauth[field].(string); ok {
						out = append(out, valueSecrets(host, where+" oauth", field, "", v, "oauth_client_secret")...)
					}
				}
			}
			slices.Sort(envNames)
			if envNames = slices.Compact(envNames); len(envNames) > 0 {
				attrs["env_names"] = clip(strings.Join(envNames, ","))
			}
			slices.Sort(headerNames)
			if headerNames = slices.Compact(headerNames); len(headerNames) > 0 {
				attrs["header_names"] = clip(strings.Join(headerNames, ","))
			}
			out = append(out, Finding{Kind: KindMCPServer, Key: key(KindMCPServer, host, path, name), Attributes: attrs})
		}
	}
	return out
}

// stringArgs reads a server's args, an array of strings. It stops at anything
// else, so a package is read only from a plain argument list.
func stringArgs(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, a := range list {
		s, ok := a.(string)
		if !ok {
			break
		}
		out = append(out, s)
	}
	return out
}

// firstString returns the first of the named members that is a non-empty
// string.
func firstString(v map[string]any, names ...string) string {
	for _, n := range names {
		if s, ok := v[n].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// frameworks maps a dependency name to the framework it indicates.
var frameworks = map[string]string{
	"langchain": "langchain", "langchain-core": "langchain", "@langchain/core": "langchain", "langchain-community": "langchain",
	"langgraph": "langgraph", "@langchain/langgraph": "langgraph", "crewai": "crewai", "autogen-agentchat": "autogen",
	"pyautogen": "autogen", "openai-agents": "openai-agents", "@openai/agents": "openai-agents", "llama-index": "llamaindex",
	"llamaindex": "llamaindex", "pydantic-ai": "pydantic-ai", "semantic-kernel": "semantic-kernel", "mastra": "mastra",
	"@mastra/core": "mastra", "claude-agent-sdk": "claude-agent-sdk", "@anthropic-ai/claude-agent-sdk": "claude-agent-sdk",
	"mcp": "mcp-sdk", "@modelcontextprotocol/sdk": "mcp-sdk", "github.com/modelcontextprotocol/go-sdk": "mcp-sdk",
	"github.com/mark3labs/mcp-go": "mcp-sdk", "github.com/tmc/langchaingo": "langchain",
}

// npmFrameworks maps npm package names too generic to read in the other
// ecosystems' manifests to the framework they indicate: "ai" is the Vercel
// AI SDK on npm only.
var npmFrameworks = map[string]string{"ai": "vercel-ai"}

var skipDirs = []string{".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target"}

// projects walks dir for dependency manifests that use an agent framework.
func projects(o Options, dir string) []Finding {
	var out []Finding
	files := 0
	root, err := filepath.Abs(dir)
	if err != nil {
		return nil
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable entries are skipped
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(root, path)
			if slices.Contains(skipDirs, d.Name()) || strings.Count(rel, string(filepath.Separator)) >= MaxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		if files++; files > MaxFiles {
			return filepath.SkipAll
		}
		var found []string
		switch d.Name() {
		case "package.json":
			found = packageJSON(path)
		case "requirements.txt", "pyproject.toml", "go.mod":
			found = lineDeps(path)
		default:
			return nil
		}
		if len(found) == 0 {
			return nil
		}
		slices.Sort(found)
		found = slices.Compact(found)
		projectDir := filepath.Dir(path)
		out = append(out, Finding{Kind: KindAgentProject, Key: key(KindAgentProject, o.Host, projectDir), Attributes: map[string]string{
			"path": clip(projectDir), "manifest": d.Name(), "frameworks": clip(strings.Join(found, ",")), "host": clip(o.Host),
		}})
		return nil
	})
	return out
}

func packageJSON(path string) []string {
	doc := readConfig(path)
	var out []string
	for _, section := range []string{"dependencies", "devDependencies"} {
		if deps, ok := doc[section].(map[string]any); ok {
			for name := range deps {
				if f, ok := frameworks[name]; ok {
					out = append(out, f)
				} else if f, ok := npmFrameworks[name]; ok {
					out = append(out, f)
				}
			}
		}
	}
	return out
}

// lineDeps finds framework names at the start of dependency lines
// (requirements.txt, pyproject.toml, go.mod).
func lineDeps(path string) []string {
	f := openRegular(path)
	if f == nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for lines := 0; sc.Scan() && lines < 5000; lines++ {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		line = strings.Trim(line, `"',`)
		line = strings.TrimPrefix(line, "require ")
		name := strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(" =<>~![;@\"'", r) })
		if len(name) == 0 {
			continue
		}
		if fw, ok := frameworks[name[0]]; ok {
			out = append(out, fw)
		}
	}
	return out
}

// secretKinds recognize credentials by their well-known prefix; the prefix
// is not secret and is all a finding shows of the value.
var secretKinds = []struct{ prefix, kind string }{
	{"pck_", "pantherclaw_api_key"},
	{"sk-ant-", "anthropic_api_key"},
	{"sk-proj-", "openai_api_key"},
	{"github_pat_", "github_token"},
	{"ghp_", "github_token"},
	{"gho_", "github_token"},
	{"xoxb-", "slack_token"},
	{"xoxp-", "slack_token"},
	{"AKIA", "aws_access_key_id"},
	{"AIza", "google_api_key"},
}

// secretNames recognize credentials by variable name when the value has
// no telling prefix.
var secretNames = map[string]string{ //nolint:gosec // G101: variable names, not credentials
	"OPENAI_API_KEY": "openai_api_key", "ANTHROPIC_API_KEY": "anthropic_api_key", "PANTHERCLAW_API_KEY": "pantherclaw_api_key",
	"GITHUB_TOKEN": "github_token", "GH_TOKEN": "github_token", "AWS_SECRET_ACCESS_KEY": "aws_secret_access_key",
}

// credentialHeaders carry a credential whatever its value looks like.
var credentialHeaders = []string{"authorization", "proxy-authorization", "x-api-key"}

// knownPrefix recognizes a credential by its well-known prefix.
func knownPrefix(value string) (kind, prefix string) {
	for _, s := range secretKinds {
		if strings.HasPrefix(value, s.prefix) {
			return s.kind, s.prefix
		}
	}
	return "", ""
}

// placeholder reports a reference the client fills in at start-up, so the
// file holds no credential: ${env:GITHUB_TOKEN} or ${input:token} (VS Code),
// $GITHUB_TOKEN, ${GITHUB_TOKEN:-default} or %GITHUB_TOKEN% (Gemini CLI).
func placeholder(value string) bool {
	switch {
	case strings.HasPrefix(value, "${"):
		return strings.HasSuffix(value, "}")
	case strings.HasPrefix(value, "$"):
		return identifier(value[1:])
	case len(value) >= 2 && strings.HasPrefix(value, "%") && strings.HasSuffix(value, "%"):
		return identifier(value[1 : len(value)-1])
	}
	return false
}

// identifier reports an environment variable name: ASCII letters, digits
// and underscores, not starting with a digit.
func identifier(s string) bool {
	for i, r := range s {
		if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (i == 0 || r < '0' || r > '9') {
			return false
		}
	}
	return s != ""
}

// varRef reads a field that names an environment variable (Codex env_vars,
// bearer_token_env_var, env_http_headers). Only a conventional name such as
// GITHUB_TOKEN is returned for listing, so a credential pasted there by
// mistake is never listed; one with a known prefix is reported redacted.
func varRef(host, where, field string, v any) (string, []Finding) {
	s, _ := v.(string)
	if kind, _ := knownPrefix(s); kind == "" && identifier(s) && strings.ToUpper(s) == s {
		return s, nil
	}
	return "", valueSecrets(host, where, field, "", s, "")
}

func secretFinding(host, where, name, kind, redacted string) Finding {
	return Finding{Kind: KindEnvSecret, Key: key(KindEnvSecret, host, where, name), Attributes: map[string]string{
		"name": clip(name), "secret_kind": kind, "where": clip(where), "redacted": clip(redacted), "host": clip(host),
	}}
}

// valueSecrets reports a value that holds a credential, redacted: one with a
// known prefix or, when kind is set, any value that is not a placeholder.
// The scheme (such as "Bearer ") is shown before the prefix.
func valueSecrets(host, where, name, scheme, value, kind string) []Finding {
	if len(value) < 8 || placeholder(value) {
		return nil
	}
	k, shown := knownPrefix(value)
	if k != "" {
		kind = k
	}
	if kind == "" {
		return nil
	}
	return []Finding{secretFinding(host, where, name, kind, scheme+shown+"…")}
}

// envSecrets reports NAME=value pairs that hold credentials, redacted.
func envSecrets(host, where string, env []string) []Finding {
	var out []Finding
	for _, kv := range env {
		if name, value, ok := strings.Cut(kv, "="); ok {
			out = append(out, valueSecrets(host, where, name, "", value, secretNames[strings.ToUpper(name)])...)
		}
	}
	return out
}

// headerSecrets reports an HTTP header of an MCP server that holds a
// credential, redacted. These are reported as env_secret findings too, so
// only the credential's kind is ever submitted.
func headerSecrets(host, where, name, value string) []Finding {
	scheme, token := "", value
	if s, t, ok := strings.Cut(value, " "); ok && slices.Contains([]string{"bearer", "basic", "token"}, strings.ToLower(s)) {
		scheme, token = s+" ", strings.TrimSpace(t)
	}
	kind := ""
	if slices.Contains(credentialHeaders, strings.ToLower(name)) {
		kind = "http_credential"
	}
	return valueSecrets(host, where, name, scheme, token, kind)
}
