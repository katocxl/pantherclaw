// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

// `pclaw managed-settings generate` writes the admin files that pin
// PantherClaw's hook and the allowed MCP servers (G0 M23 D113, F850). It
// writes to --out or stdout and refuses a managed location: an administrator
// reviews the files and installs them with their own tools. Generating them
// asks no server and changes no coverage state (HR-567).
//
// Key names follow the vendors' documentation, checked on 2026-10-31:
// https://code.claude.com/docs/en/managed-mcp.md and
// https://docs.github.com/en/copilot/how-tos/administer-copilot/manage-mcp-usage/configure-enterprise-allowlist

func init() {
	commands["managed-settings generate"] = command{
		usage: "managed-settings generate --client claude-code|copilot [--allow-file FILE] [--out DIR]",
		run:   generateManagedSettings,
	}
}

// Managed locations of Claude Code and GitHub Copilot, on every platform: a
// directory made on one machine may be another's mount.
var vendorManagedDirs = []string{
	`C:\Program Files\ClaudeCode`, "/Library/Application Support/ClaudeCode", "/etc/claude-code",
	`C:\Program Files\GitHubCopilot`, "/Library/Application Support/GitHubCopilot", "/etc/github-copilot",
}

// serverManagedRepo is the repository Copilot's server-managed settings live
// in; a checkout of it is a managed location too.
const serverManagedRepo = ".github-private"

// managedDirs are the managed locations on this machine.
func (a *app) managedDirs() []string {
	dirs := append([]string{managedSettingsDir}, vendorManagedDirs...)
	if v, ok := a.env("ProgramFiles"); ok && v != "" {
		dirs = append(dirs, filepath.Join(v, "ClaudeCode"), filepath.Join(v, "GitHubCopilot"))
	}
	return dirs
}

// realPath is path with every link in its existing part resolved; the part
// that does not exist yet stays as it is.
func realPath(path string) string {
	rest := ""
	for p := filepath.Clean(path); ; {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return filepath.Clean(path)
		}
		rest, p = filepath.Join(filepath.Base(p), rest), parent
	}
}

// foldPath is path as this platform's file system compares it.
func foldPath(path string) string {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(path)
	}
	return path
}

// inManagedLocation reports whether path, with its links resolved, is a
// managed location or under one.
func (a *app) inManagedLocation(path string) bool {
	resolved := foldPath(realPath(path))
	if slices.Contains(strings.Split(filepath.ToSlash(resolved), "/"), serverManagedRepo) {
		return true
	}
	return slices.ContainsFunc(a.managedDirs(), func(dir string) bool {
		root := foldPath(realPath(dir))
		return resolved == root || strings.HasPrefix(resolved, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
	})
}

// allowedServer is one server of the allow file: one transport, by URL or by
// the command that starts it.
type allowedServer struct {
	name    string
	url     string
	command []string
}

// allowServerName is what Claude Code's allow list takes as a server name.
var allowServerName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// readAllowFile reads the allow file. A command is an argument list, or one
// string that is the whole command: nothing here splits it as a shell would.
func readAllowFile(path string) ([]allowedServer, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the path the administrator named
	if err != nil {
		return nil, err
	}
	var file struct {
		Servers []struct {
			Name    string         `json:"name"`
			URL     string         `json:"url"`
			Command jsontext.Value `json:"command"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &file, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("allow file %s: %w", path, err)
	}
	seen := map[string]bool{}
	out := make([]allowedServer, 0, len(file.Servers))
	for i, s := range file.Servers {
		where := fmt.Sprintf("allow file %s: server %d", path, i+1)
		if !allowServerName.MatchString(s.Name) {
			return nil, fmt.Errorf("%s: name must be 1 to 64 letters, digits, hyphens or underscores", where)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("%s: %s appears twice", where, s.Name)
		}
		seen[s.Name] = true
		command, err := allowCommand(s.Command)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		if (s.URL == "") == (len(command) == 0) {
			return nil, fmt.Errorf("%s: needs a url or a command, not both", where)
		}
		if s.URL != "" {
			if err := checkAllowURL(s.URL); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
		}
		out = append(out, allowedServer{name: s.Name, url: s.URL, command: command})
	}
	return out, nil
}

var errAllowCommand = errors.New("command must be a string or a list of non-empty strings")

func allowCommand(v jsontext.Value) ([]string, error) {
	if len(v) == 0 {
		return nil, nil
	}
	var argv []string
	if v.Kind() == '"' {
		argv = []string{""}
		if err := json.Unmarshal(v, &argv[0]); err != nil {
			return nil, errAllowCommand
		}
	} else if v.Kind() != '[' || json.Unmarshal(v, &argv) != nil {
		return nil, errAllowCommand
	}
	if slices.Contains(argv, "") {
		return nil, errAllowCommand
	}
	return argv, nil
}

// checkAllowURL takes an exact http or https URL: it goes into managed-mcp.json
// as the server's address, so it has no wildcard, and no file of the kit
// holds a credential.
func checkAllowURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("url must be an http or https URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Contains(s, "*") {
		return errors.New("url must be exact, without credentials, a query or a wildcard")
	}
	return nil
}

// allowList is the servers as an allow list: each entry has one matcher,
// serverUrl or serverCommand. A name is never a matcher: the vendors say it
// is no security control.
func allowList(servers []allowedServer) *jsonNode {
	list := &jsonNode{kind: '['}
	for _, s := range servers {
		if s.url != "" {
			list.items = append(list.items, jsonFields("serverUrl", s.url))
		} else {
			list.items = append(list.items, jsonFields("serverCommand", s.command))
		}
	}
	return list
}

// managedMCP is managed-mcp.json. No server here has an env block: the
// vendor says to keep credentials out of this file.
func managedMCP(servers []allowedServer) *jsonNode {
	defs := &jsonNode{kind: '{'}
	for _, s := range servers {
		def := jsonFields("type", "http", "url", s.url)
		if s.url == "" {
			def = jsonFields("type", "stdio", "command", s.command[0])
			if len(s.command) > 1 {
				def.set("args", jsonOf(s.command[1:]))
			}
		}
		defs.set(s.name, def)
	}
	return jsonFields("mcpServers", defs)
}

// kitFile is one generated file.
type kitFile struct {
	name string
	doc  *jsonNode
}

// claudeCodeKit allows only managed hooks and runs PantherClaw's, which takes
// its gateway, connection and key file from the environment (hook.go).
func claudeCodeKit(servers []allowedServer) []kitFile {
	hooks := jsonFields("PreToolUse", &jsonNode{kind: '[', items: []*jsonNode{hookGroup(claudeHookArgs)}})
	return []kitFile{
		{"managed-settings.json", jsonFields("allowManagedHooksOnly", true, "hooks", hooks, "allowedMcpServers", allowList(servers))},
		{"managed-mcp.json", managedMCP(servers)},
	}
}

// copilotKit has the allow list, and a deny list the allow file has nothing
// for.
func copilotKit(servers []allowedServer) []kitFile {
	return []kitFile{{"managed-settings.json", jsonFields("allowedMcpServers", allowList(servers), "deniedMcpServers", &jsonNode{kind: '['})}}
}

// errManagedOut refuses a managed location (HR-567).
func errManagedOut(path string) error {
	return &exitError{code: 1, msg: "pclaw managed-settings generate: " + path +
		" is a managed location, and pclaw never writes one: generate elsewhere, review the files and install them yourself"}
}

func generateManagedSettings(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("managed-settings generate", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	client := fs.String("client", "", "claude-code or copilot")
	allowFile := fs.String("allow-file", "", `the allowed MCP servers, JSON: {"servers":[{"name","url","command"}]}`)
	out := fs.String("out", "", "the directory to write to (default: stdout); never a managed location")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errUsage
	}
	var kit func([]allowedServer) []kitFile
	switch *client {
	case "claude-code":
		kit = claudeCodeKit
	case "copilot":
		kit = copilotKit
	default:
		return errUsage
	}
	var servers []allowedServer
	if *allowFile != "" {
		var err error
		if servers, err = readAllowFile(*allowFile); err != nil {
			return err
		}
	}
	files := kit(servers)
	encoded := make([][]byte, len(files))
	for i, f := range files {
		b, err := f.doc.encode()
		if err != nil {
			return err
		}
		encoded[i] = b
	}
	if *out == "" {
		for i, f := range files {
			if len(files) > 1 {
				if _, err := fmt.Fprintf(a.stdout, "# %s\n", f.name); err != nil {
					return err
				}
			}
			if _, err := a.stdout.Write(encoded[i]); err != nil {
				return err
			}
		}
		return kitNotes(a, *client, len(servers))
	}
	dir, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if a.inManagedLocation(dir) {
		return errManagedOut(dir)
	}
	// A file already there may be a link into a managed location, which a
	// write would follow. Nothing is written unless every file is safe.
	targets := make([]string, len(files))
	for i, f := range files {
		if targets[i], err = linkTarget(filepath.Join(dir, f.name)); err != nil {
			return err
		}
		if a.inManagedLocation(targets[i]) {
			return errManagedOut(targets[i])
		}
	}
	for i, f := range files {
		if err := writeAtomically(targets[i], encoded[i]); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(a.stdout, "wrote "+filepath.Join(dir, f.name)); err != nil {
			return err
		}
	}
	return kitNotes(a, *client, len(servers))
}

// kitNotes goes to stderr, so stdout stays the files. It says what the files
// are not: nothing is installed, and nothing about coverage changed.
func kitNotes(a *app, client string, servers int) error {
	note := "Nothing was installed. Review these files and install them with your own tools; generating them changes no coverage state.\n"
	if client == "claude-code" {
		note += "The hook reads PANTHERCLAW_GATEWAY, PANTHERCLAW_HOOK_CONNECTION and PANTHERCLAW_WORKLOAD_KEY_FILE from its environment; " +
			"without them it blocks every command.\n"
	}
	if servers == 0 {
		note += "No servers were allowed, so this allow list blocks every MCP server.\n"
	}
	_, err := fmt.Fprint(a.stderr, note)
	return err
}
