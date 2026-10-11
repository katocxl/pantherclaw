// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// `pclaw init --mcp NAME=CONNECTION` governs the MCP server NAME (G0 M8
// design decision 9, HR-208). The original entry stays as it is; init
// adds a governed entry, pantherclaw-NAME, a stdio server that reaches the
// gateway connection through `pclaw mcp proxy`, and the deny rule
// mcp__NAME__* in the scope's settings file, so Claude Code cannot use the
// original. A deny rule only strengthens. The original's credentials are
// never copied: the governed entry holds only the gateway's URL, the
// connection's name and the key file's path.

// mcpNameRe is a server name Claude Code's allowlists accept, short enough
// for its governed name.
var mcpNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,52}$`)

// governedPrefix names the governed entry of a server.
const governedPrefix = "pantherclaw-"

// mcpRoute is one --mcp NAME=CONNECTION.
type mcpRoute struct{ name, connection string }

func parseMCPRoutes(values []string) ([]mcpRoute, error) {
	var out []mcpRoute
	for _, v := range values {
		name, conn, ok := strings.Cut(v, "=")
		if !ok || !mcpNameRe.MatchString(name) || !connectionName.MatchString(conn) {
			return nil, fmt.Errorf("--mcp %q: want NAME=CONNECTION (at most 52 letters, digits, - and _ in the name)", v)
		}
		out = append(out, mcpRoute{name, conn})
	}
	return out, nil
}

// denyRule is the rule that keeps Claude Code from using a server's tools.
func denyRule(server string) string { return "mcp__" + server + "__*" }

// proxyArgs are the arguments of the stdio server for a connection.
func (f initFlags) proxyArgs(conn, key string) []string {
	args := []string{"mcp", "proxy", "--gateway", strings.TrimSuffix(f.gateway, "/"), "--connection", conn, "--key-file", key}
	if f.run != "" {
		args = append(args, "--run", f.run)
	}
	return args
}

// mcpFile is a file that keeps MCP servers, with where in it.
type mcpFile struct {
	scope, path string
	// project: the servers are under projects[<the project>] (local).
	project bool
}

// mcpFiles are the files that keep Claude Code's MCP servers, the scope's
// own first (local: ~/.claude.json under the project, user: its top
// level, project: .mcp.json).
func mcpFiles(scope, home, config, project string) []mcpFile {
	state := filepath.Join(home, ".claude.json")
	if alt := filepath.Join(config, ".claude.json"); config != filepath.Join(home, ".claude") {
		if _, err := os.Stat(alt); err == nil {
			state = alt
		}
	}
	all := []mcpFile{
		{"local", state, true}, {"project", filepath.Join(project, ".mcp.json"), false}, {"user", state, false},
	}
	i := slices.IndexFunc(all, func(m mcpFile) bool { return m.scope == scope })
	return append([]mcpFile{all[i]}, slices.Delete(slices.Clone(all), i, i+1)...)
}

// servers returns the servers object of a file's document, nil when it has
// none; with create, missing objects are added.
func (m mcpFile) servers(doc *jsonNode, project string, create bool) *jsonNode {
	at := doc
	if m.project {
		at = nil
		if projects := doc.get("projects"); projects != nil && projects.kind == '{' {
			for i, k := range projects.keys {
				if samePath(k, project) {
					at = projects.vals[i]
				}
			}
		}
		if at == nil || at.kind != '{' {
			// Claude Code adds a project's entry the first time it runs
			// there; pclaw does not invent one.
			return nil
		}
	}
	if !create {
		return at.get("mcpServers")
	}
	if s, ok := at.object("mcpServers"); ok {
		return s
	}
	return nil
}

// errReplace: a server entry of that name exists and is not the one init
// would add.
var errReplace = errors.New("pclaw init never replaces a server entry")

// addServer adds a server entry; an identical one is left as it is.
func addServer(servers *jsonNode, name string, entry *jsonNode) error {
	if have := servers.get(name); have != nil {
		a, _ := have.encode()
		b, _ := entry.encode()
		if !bytes.Equal(a, b) {
			return errReplace
		}
		return nil
	}
	servers.set(name, entry)
	return nil
}

// denies reports whether a document denies the rule, or every tool of the
// server it names.
func denies(doc *jsonNode, rule string) bool {
	server := strings.TrimSuffix(rule, "__*")
	return slices.ContainsFunc(doc.get("permissions").get("deny").itemsOf(), func(n *jsonNode) bool {
		return n.str() == rule || n.str() == server
	})
}

// addDeny adds a permissions.deny rule unless the document has it.
func addDeny(doc *jsonNode, rule string) error {
	if denies(doc, rule) {
		return nil
	}
	perms, ok := doc.object("permissions")
	if !ok {
		return errors.New("permissions is not an object")
	}
	deny, ok := perms.array("deny")
	if !ok {
		return errors.New("permissions.deny is not a list")
	}
	deny.items = append(deny.items, jsonOf(rule))
	return nil
}

// mcpBlocked says why Claude Code would not run the server: a deny list
// names it, or an allowlist that applies leaves it out.
func mcpBlocked(name string, argv []string, managed, settings []claudeSettings) error {
	matches := func(list *jsonNode) bool {
		for _, e := range list.itemsOf() {
			if e.get("serverName").str() == name {
				return true
			}
			if cmd := e.get("serverCommand").itemsOf(); len(cmd) == len(argv) && slices.EqualFunc(cmd, argv, func(n *jsonNode, s string) bool {
				return n.str() == s
			}) {
				return true
			}
		}
		return false
	}
	managedOnly := slices.ContainsFunc(managed, func(s claudeSettings) bool { return s.doc.get("allowManagedMcpServersOnly").bool() })
	var allows []*jsonNode
	for _, s := range append(slices.Clone(managed), settings...) {
		if s.doc == nil {
			continue
		}
		if matches(s.doc.get("deniedMcpServers")) {
			return fmt.Errorf("%s denies the MCP server %q (deniedMcpServers)", s.path, name)
		}
		if l := s.doc.get("allowedMcpServers"); l != nil && (s.scope == "managed" || !managedOnly) {
			allows = append(allows, l)
		}
	}
	if len(allows) > 0 && !slices.ContainsFunc(allows, matches) {
		return fmt.Errorf("allowedMcpServers in Claude Code's settings leaves out the MCP server %q, so it would never run; "+
			"ask your administrator to allow it", name)
	}
	return nil
}

// governMCP plans each --mcp server's governed entry and deny rule.
func (f initFlags) governMCP(a *app, p *initPlan, routes []mcpRoute, home, config string, managed, settings []claudeSettings,
	target claudeSettings,
) error {
	key, err := filepath.Abs(f.keyFile)
	if err != nil {
		return err
	}
	fail := func(format string, v ...any) error {
		return &exitError{code: 1, msg: "pclaw init: " + fmt.Sprintf(format, v...)}
	}
	files := mcpFiles(f.scope, home, config, f.project)
	for _, r := range routes {
		governed, args := governedPrefix+r.name, f.proxyArgs(r.connection, key)
		if err := mcpBlocked(governed, append([]string{"pclaw"}, args...), managed, settings); err != nil {
			return fail("%v", err)
		}
		if m := managedRulesOnly(managed); m != "" && !slices.ContainsFunc(managed, func(s claudeSettings) bool { return denies(s.doc, denyRule(r.name)) }) {
			return fail("managed settings (%s) allow only managed permission rules, so a deny rule for %q would be ignored and "+
				"its original entry would go around PantherClaw; ask your administrator to deny %s in managed settings", m, r.name, denyRule(r.name))
		}
		entry := jsonFields("type", "stdio", "command", "pclaw", "args", args)
		original, present := "", false
		for _, m := range files {
			s, err := readSettings(m.scope, m.path)
			if err != nil {
				return err
			}
			servers := m.servers(p.file(s).doc, f.project, false)
			if servers.get(r.name) != nil && original == "" {
				original = m.path
			}
			if have := servers.get(governed); have != nil {
				if addServer(servers, governed, entry) != nil {
					return fail("an MCP server named %q already exists in %s (%s scope) and %v: remove it yourself", governed, m.path, m.scope, errReplace)
				}
				present = true
			}
		}
		if !present {
			s, err := readSettings(files[0].scope, files[0].path)
			if err != nil {
				return err
			}
			servers := files[0].servers(p.file(s).doc, f.project, true)
			if servers == nil {
				return fail("%s has no place for this project's MCP servers yet (run claude in the project once, or use --scope project "+
					"or user); it is left as it is", files[0].path)
			}
			_ = addServer(servers, governed, entry)
		}
		if !slices.ContainsFunc(append(slices.Clone(managed), settings...), func(s claudeSettings) bool { return denies(s.doc, denyRule(r.name)) }) {
			if err := addDeny(p.file(target).doc, denyRule(r.name)); err != nil {
				return fail("%s: %v; it is left as it is", target.path, err)
			}
		}
		switch {
		case original != "":
			p.done = append(p.done, fmt.Sprintf("The MCP server %q in %s is left as it is, and denied; Claude Code reaches it as %q, "+
				"through PantherClaw.", r.name, original, governed))
		default:
			_, _ = fmt.Fprintf(a.stdout, "No MCP server named %q is configured for Claude Code; the deny rule keeps one added later "+
				"from going around PantherClaw.\n", r.name)
		}
	}
	return nil
}

// managedRulesOnly is the managed settings file that keeps every other
// scope's permission rules from applying, or "".
func managedRulesOnly(managed []claudeSettings) string {
	for _, m := range managed {
		if m.doc.get("allowManagedPermissionRulesOnly").bool() {
			return m.path
		}
	}
	return ""
}
