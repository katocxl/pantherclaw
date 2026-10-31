// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
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

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/scan"
)

// `pclaw init` wires a developer's Claude Code to PantherClaw (G0 M8 track
// C, HR-208). It finds Claude Code's settings (user, project, local and
// managed), its MCP servers and the agent-framework projects under the
// project directory. It then enrolls the workload key as the signed-in
// person when it is not enrolled yet (HR-094: admitted with the fingerprint
// shown before), and installs the PreToolUse hook that asks the gateway
// before every command a tool runs in a shell (Bash, PowerShell and
// Monitor; HR-186) with `pclaw hook claude-code`, in the settings file of
// the chosen scope. When the org has no connection of the hook's name, it
// creates it, serving pc.shell, or says what must happen first
// (claudeconn.go).
//
// It only adds: it never removes or changes an existing deny rule, hook or
// server entry, and it never writes a secret (only the gateway's URL, the
// connection's name, the key file's path and the run; the enrollment token
// is used at once and kept nowhere). It shows the diff and changes nothing
// until the person confirms (or passed --yes); with --dry-run it changes
// nothing. It backs up every file before it changes it and writes through
// a temporary file. It refuses when managed settings, or the target file
// itself, would keep the hook from running, since a developer would then
// believe commands are decided when they are not.

func init() {
	commands["init"] = command{
		usage: "init --gateway URL --connection NAME --key-file FILE [--gateway-id ID] [--agent ID] [--mcp NAME=CONNECTION...] [--run ID] [--project DIR] " +
			"[--scope local|project|user] [--dry-run | --yes [--fingerprint FP]] [--managed-settings FILE] [--template NAME --repos OWNER/REPO[,…] [--yes-template] [template apply options]]",
		run: claudeInit,
	}
}

// claudeHookArgs are the hook's arguments before its flags: the command
// the hook runs is `pclaw hook claude-code`.
var claudeHookArgs = []string{"hook", "claude-code"}

// shellTools are the tools that run commands in a shell, which PantherClaw's
// hook decides (HR-186; Monitor added after review, founder decision
// 2026-10-13). The hook init installs matches them all.
var shellTools = []string{"Bash", "PowerShell", "Monitor"}

// connectionName is a connection name (ConnectionService).
var connectionName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// claudeSettings is one Claude Code settings file.
type claudeSettings struct {
	scope, path string
	doc         *jsonNode
	// raw is the file as read; nil when it does not exist.
	raw []byte
}

// managedSettingsDir is the directory Claude Code reads managed settings
// from on this platform (a variable, so tests can point it elsewhere).
var managedSettingsDir = func() string {
	switch runtime.GOOS {
	case "windows":
		return `C:\Program Files\ClaudeCode`
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	default:
		return "/etc/claude-code"
	}
}()

// managedSettingsPaths are where Claude Code reads managed settings on this
// platform, with its drop-in directory.
func managedSettingsPaths() []string {
	dir := managedSettingsDir
	out := []string{filepath.Join(dir, "managed-settings.json")}
	drops, _ := filepath.Glob(filepath.Join(dir, "managed-settings.d", "*.json"))
	slices.Sort(drops)
	return append(out, drops...)
}

// claudeHome is the user's home directory and Claude Code's configuration
// directory (CLAUDE_CONFIG_DIR, or ~/.claude).
func (a *app) claudeHome() (home, config string, err error) {
	for _, name := range []string{"HOME", "USERPROFILE"} {
		if v, ok := a.env(name); ok && v != "" {
			home = v
			break
		}
	}
	if home == "" {
		return "", "", errors.New("no home directory: set HOME (or USERPROFILE on Windows)")
	}
	config = filepath.Join(home, ".claude")
	if v, ok := a.env("CLAUDE_CONFIG_DIR"); ok && v != "" {
		config = v
	}
	return home, config, nil
}

func readSettings(scope, path string) (claudeSettings, error) {
	s := claudeSettings{scope: scope, path: path}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the user's own configuration
	switch {
	case errors.Is(err, os.ErrNotExist):
		s.doc = &jsonNode{kind: '{'}
		return s, nil
	case err != nil:
		return s, err
	}
	s.raw = b
	if s.doc, err = parseJSONDoc(b); err != nil {
		return s, fmt.Errorf("%s is not a JSON object pclaw can change safely (%w); it is left as it is", path, err)
	}
	return s, nil
}

// hookRuns reports whether a settings document runs PantherClaw's hook
// (pantherClawHook) before every tool in shellTools, in hook groups whose
// matchers name those tools exactly or match every tool. A pclaw hook that
// lets a command through when it cannot run, that runs another pclaw
// command or more than the hook's in a shell, or that leaves out one of
// those tools (Monitor, or Bash under a matcher naming BashOutput) is not
// PantherClaw's hook, so init adds its own beside it.
func hookRuns(doc *jsonNode) bool {
	covered := map[string]bool{}
	for _, group := range doc.get("hooks").get("PreToolUse").itemsOf() {
		if !slices.ContainsFunc(group.get("hooks").itemsOf(), pantherClawHook) {
			continue
		}
		tools, all := matched(group.get("matcher"))
		if all {
			return true
		}
		for _, tool := range tools {
			covered[tool] = true
		}
	}
	return !slices.ContainsFunc(shellTools, func(tool string) bool { return !covered[tool] })
}

// toolNames is a matcher Claude Code compares with tool names as they are,
// not as a regular expression: names joined by |, nothing else.
var toolNames = regexp.MustCompile(`^[A-Za-z0-9_]+(\|[A-Za-z0-9_]+)*$`)

// matched is what a hook group's matcher matches: every tool when it is
// missing, empty or *, or the tools it names. A matcher init cannot read
// for certain (not a string, or a regular expression, where " Bash" is
// not Bash) matches nothing here, so init adds its own hook beside it.
func matched(m *jsonNode) (tools []string, all bool) {
	if m == nil {
		return nil, true
	}
	if m.kind != 0 || m.raw.Kind() != '"' {
		return nil, false
	}
	switch s := m.str(); {
	case s == "" || s == "*":
		return nil, true
	case toolNames.MatchString(s):
		return strings.Split(s, "|"), false
	}
	return nil, false
}

// pantherClawHook reports whether a hook runs `pclaw hook claude-code` and
// blocks the call when it cannot run (onFailure "block"): in exec form
// (command pclaw, args hook claude-code and its flags), or as a shell
// command that is the hook's command and flags and nothing else, so that
// nothing in it (|| true, ; true, a redirection) can change what the
// hook's exit code says.
func pantherClawHook(h *jsonNode) bool {
	if h.get("type").str() != "command" || h.get("onFailure").str() != "block" {
		return false
	}
	command, args := h.get("command").str(), h.get("args").itemsOf()
	if base := filepath.Base(command); base == "pclaw" || base == "pclaw.exe" {
		return len(args) >= 2 && args[0].str() == claudeHookArgs[0] && args[1].str() == claudeHookArgs[1]
	}
	return hookShellCommand(command)
}

// hookFlags are the flags `pclaw hook claude-code` defines; each takes a
// value.
var hookFlags = []string{"gateway", "connection", "key-file", "run", "token-file"}

// shellWord is a word no shell splits, expands or reads as an operator,
// redirection or quote. A path with a backslash is not one, so a Windows
// path in a shell-form hook makes init add its own hook, in exec form.
var shellWord = regexp.MustCompile(`^[A-Za-z0-9_./:@+,=-]+$`)

// hookShellCommand reports whether a shell command is exactly
// `pclaw hook claude-code`, optionally followed by the hook's flags with
// their values (--connection shell, --run=ID), words separated by spaces.
func hookShellCommand(command string) bool {
	words := slices.DeleteFunc(strings.Split(command, " "), func(w string) bool { return w == "" })
	head := append([]string{"pclaw"}, claudeHookArgs...)
	if len(words) < len(head) || !slices.Equal(words[:len(head)], head) {
		return false
	}
	for rest := words[len(head):]; len(rest) > 0; {
		word := rest[0]
		name, value, inline := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(word, "-"), "-"), "=")
		if !strings.HasPrefix(word, "-") || !slices.Contains(hookFlags, name) {
			return false
		}
		if rest = rest[1:]; !inline {
			if len(rest) == 0 {
				return false
			}
			value, rest = rest[0], rest[1:]
		}
		if !shellWord.MatchString(value) {
			return false
		}
	}
	return true
}

// counts summarizes a settings document for the report.
func counts(doc *jsonNode) string {
	if doc == nil {
		return "cannot be read"
	}
	hooks := 0
	var events []*jsonNode
	if h := doc.get("hooks"); h != nil {
		events = h.vals
	}
	for _, groups := range events {
		for _, g := range groups.itemsOf() {
			hooks += len(g.get("hooks").itemsOf())
		}
	}
	return fmt.Sprintf("%d hooks, %d deny rules", hooks, len(doc.get("permissions").get("deny").itemsOf()))
}

// initFlags are init's options.
type initFlags struct {
	gateway, gatewayID, connection, keyFile, run, project, scope, managed, agent, fingerprint string
	dryRun, yes                                                                               bool
}

func claudeInit(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var f initFlags
	fs.StringVar(&f.gateway, "gateway", "", "the gateway's public URL")
	fs.StringVar(&f.connection, "connection", "", "the kind-local connection serving pc.shell (created when the org has none)")
	fs.StringVar(&f.gatewayID, "gateway-id", "", "the gateway to create the connection on, when the org has several (default: its only one)")
	fs.StringVar(&f.keyFile, "key-file", "", "the desktop workload key file (created and enrolled with --agent when it is not enrolled)")
	fs.StringVar(&f.agent, "agent", "", "the agent to enroll the key file as, signed in as yourself, when it is not enrolled yet")
	fs.StringVar(&f.run, "run", "", "the run (default: the key file's)")
	fs.StringVar(&f.project, "project", "", "the project directory (default: the current one)")
	fs.StringVar(&f.scope, "scope", "local", "where the hook goes: local (.claude/settings.local.json), project (.claude/settings.json) or user")
	fs.StringVar(&f.managed, "managed-settings", "", "also read managed settings from this file (the platform's are always read)")
	fs.BoolVar(&f.dryRun, "dry-run", false, "show what would change and change nothing")
	fs.BoolVar(&f.yes, "yes", false, "make the changes without asking")
	fs.StringVar(&f.fingerprint, "fingerprint", "", "with --yes, the fingerprint of the key to enroll, which you checked (HR-094)")
	var mcp list
	fs.Var(&mcp, "mcp", "NAME=CONNECTION: govern the MCP server NAME through pclaw mcp proxy to CONNECTION (repeatable)")
	var tpl templateOptions
	fs.StringVar(&tpl.name, "template", "", "then apply this template (coding-to-production) with the enrolled agent; see pclaw template apply")
	fs.BoolVar(&tpl.update, "update", false, "with --template, change what exists and differs from the template")
	yesTemplate := fs.Bool("yes-template", false, "with --template, apply the template's plan without asking; --yes alone only shows it")
	tplCheck := templateFlags(fs, &tpl)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if f.gateway == "" || f.connection == "" || f.keyFile == "" || fs.NArg() != 0 || (f.dryRun && f.yes) {
		return errUsage
	}
	if *yesTemplate && tpl.name == "" {
		return errUsage
	}
	if tpl.name != "" {
		if err := tplCheck(); err != nil {
			return err
		}
		// --yes confirms init's own writes; the template's changes need
		// their own --yes-template (the coordinator's decision Q9).
		tpl.dryRun, tpl.yes, tpl.planOnly = f.dryRun, *yesTemplate, f.yes && !*yesTemplate
	}
	routes, err := parseMCPRoutes(mcp)
	if err != nil {
		return err
	}
	hook, err := f.hookEntry()
	if err != nil {
		return err
	}
	if err := validGatewayID(f.gatewayID); err != nil {
		return err
	}
	p := &initPlan{}
	if p.enroll, err = f.enrollment(); err != nil {
		return err
	}
	home, config, err := a.claudeHome()
	if err != nil {
		return err
	}
	if f.project == "" {
		if f.project, err = os.Getwd(); err != nil {
			return err
		}
	}
	if f.project, err = filepath.Abs(f.project); err != nil {
		return err
	}
	files := map[string]string{
		"user":    filepath.Join(config, "settings.json"),
		"project": filepath.Join(f.project, ".claude", "settings.json"),
		"local":   filepath.Join(f.project, ".claude", "settings.local.json"),
	}
	if files[f.scope] == "" {
		return errors.New("--scope must be local, project or user")
	}
	// --managed-settings adds a file to the platform's, never replaces
	// them: what Claude Code enforces is always checked.
	managedPaths := managedSettingsPaths()
	if f.managed != "" {
		managedPaths = append(managedPaths, f.managed)
	}
	var settings []claudeSettings
	for _, scope := range []string{"user", "project", "local"} {
		s, err := readSettings(scope, files[scope])
		switch {
		case err != nil && scope == f.scope:
			return err
		case err != nil:
			// Claude Code may read what pclaw does not (with two members of
			// one name it takes the last), so this file's disableAllHooks
			// could keep the hook from running, and init cannot tell.
			return &exitError{code: 1, msg: "pclaw init: " + err.Error() + ". Claude Code may still apply that file's settings, disableAllHooks " +
				"among them, which would keep the hook from running, so init changes nothing: fix the file and run pclaw init again"}
		}
		settings = append(settings, s)
	}
	var managed []claudeSettings
	for _, p := range managedPaths {
		s, err := readSettings("managed", p)
		if err != nil {
			return fmt.Errorf("managed settings: %w", err)
		}
		if s.raw != nil {
			managed = append(managed, s)
		}
	}
	findings := report(a, a.scanOptions(home, f.project), settings, managed)
	target := settings[slices.IndexFunc(settings, func(s claudeSettings) bool { return s.scope == f.scope })]
	if err := hookBlocked(managed, settings, target); err != nil {
		return &exitError{code: 1, msg: "pclaw init: " + err.Error()}
	}
	if p.connection, err = f.hookConnection(ctx, a); err != nil {
		return err
	}
	if slices.ContainsFunc(managed, func(s claudeSettings) bool { return hookRuns(s.doc) }) || hookRuns(target.doc) {
		_, _ = fmt.Fprintln(a.stdout, "The PantherClaw hook is already installed.")
	} else if err := p.addHook(target, hook); err != nil {
		return err
	}
	if err := f.governMCP(a, p, routes, home, config, managed, settings, target); err != nil {
		return err
	}
	f.agentSDKSnippets(a, findings)
	if err := f.apply(ctx, a, p); err != nil || tpl.name == "" {
		return err
	}
	// The template's grant goes to the agent the key file is enrolled as.
	if tpl.agent = f.agent; tpl.agent == "" {
		kf, err := workloadclient.ReadKeyFile(f.keyFile)
		if err != nil {
			return err
		}
		tpl.agent = agentOfIdentifier(kf.Identifier)
	}
	return applyTemplate(ctx, a, tpl)
}

// agentOfIdentifier is the agent id in a workload identifier
// (pc:org/<org>/agent/<agent>/inst/<instance>), or "".
func agentOfIdentifier(id string) string {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "agent" {
			return parts[i+1]
		}
	}
	return ""
}

// hookEntry is the hook to install: exec form, so no shell parses the
// paths, and blocking when it cannot run.
func (f initFlags) hookEntry() (*jsonNode, error) {
	u, err := url.Parse(f.gateway)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("--gateway must be the gateway's base URL, without credentials or a query")
	}
	if !connectionName.MatchString(f.connection) {
		return nil, errors.New("--connection must be a connection name")
	}
	if f.run != "" {
		if _, err := ids.ParseUUID(f.run); err != nil {
			return nil, errors.New("--run must be a run id")
		}
	}
	key, err := filepath.Abs(f.keyFile)
	if err != nil {
		return nil, err
	}
	args := append(slices.Clone(claudeHookArgs), "--gateway", strings.TrimSuffix(f.gateway, "/"), "--connection", f.connection,
		"--key-file", key)
	if f.run != "" {
		args = append(args, "--run", f.run)
	}
	return hookGroup(args), nil
}

// hookGroup is the hook group that runs `pclaw` with args before every tool
// in shellTools: exec form, blocking when it cannot run.
func hookGroup(args []string) *jsonNode {
	entry := jsonFields("type", "command", "command", "pclaw", "args", args, "timeout", 10, "onFailure", "block")
	return jsonFields("matcher", strings.Join(shellTools, "|"), "hooks", &jsonNode{kind: '[', items: []*jsonNode{entry}})
}

// managedBlocked says why managed settings keep the hook from running: they
// allow only managed hooks without PantherClaw's, or disable every hook.
func managedBlocked(managed []claudeSettings) error {
	for _, m := range managed {
		switch {
		case m.doc.get("disableAllHooks").bool():
			return fmt.Errorf("managed settings (%s) disable every hook, so the PantherClaw hook would never run; ask your administrator", m.path)
		case m.doc.get("allowManagedHooksOnly").bool() && !slices.ContainsFunc(managed, func(s claudeSettings) bool { return hookRuns(s.doc) }):
			return fmt.Errorf("managed settings (%s) allow only managed hooks, so the PantherClaw hook would never run; "+
				"ask your administrator to add it to managed settings", m.path)
		}
	}
	return nil
}

// Managed states `pclaw init` and `pclaw scan` report (G0 M23 D114). They say
// what a file on this machine holds, never that anything is covered (HR-567).
const (
	// managedNotFound: no managed settings file on this machine.
	managedNotFound = "not_found"
	// managedPresent: a file is there and does not keep the hook from running.
	managedPresent = "present"
	// managedConflict: a file keeps the hook from running, or cannot be read.
	managedConflict = "conflict"
)

// managedLimits is what the managed state cannot say.
const managedLimits = "registry, MDM and server-managed settings cannot be read here, and a file found here is not coverage"

// managedState is the state of the managed settings files found.
func managedState(managed []claudeSettings) string {
	switch {
	case len(managed) == 0:
		return managedNotFound
	case managedBlocked(managed) != nil:
		return managedConflict
	}
	return managedPresent
}

// platformManagedState reads the platform's managed settings files.
func platformManagedState() string {
	var managed []claudeSettings
	for _, p := range managedSettingsPaths() {
		s, err := readSettings("managed", p)
		if err != nil {
			return managedConflict
		}
		if s.raw != nil {
			managed = append(managed, s)
		}
	}
	return managedState(managed)
}

// hookBlocked says why the hook would not run: managed settings that allow
// only managed hooks or disable every hook, a target file that disables
// its scope's hooks, or another settings file that turns every hook off
// and wins, because no file Claude Code prefers to it sets disableAllHooks.
func hookBlocked(managed, settings []claudeSettings, target claudeSettings) error {
	if err := managedBlocked(managed); err != nil {
		return err
	}
	if target.doc.get("disableAllHooks").bool() {
		return fmt.Errorf("%s disables its hooks (disableAllHooks); pclaw init never changes that setting, so remove it yourself "+
			"or choose another --scope", target.path)
	}
	if s := settingFrom("disableAllHooks", managed, settings); s != nil && s.doc.get("disableAllHooks").bool() {
		return fmt.Errorf("%s turns every hook off (disableAllHooks), and no settings file Claude Code prefers to it turns them back on, "+
			"so the PantherClaw hook would never run; pclaw init never changes that setting, so change it yourself", s.path)
	}
	return nil
}

// settingFrom is the settings file whose value of a true-or-false setting
// Claude Code applies, or nil when none sets it. Claude Code takes such a
// setting from the first file that sets it: managed settings, then local,
// project and user.
func settingFrom(name string, managed, settings []claudeSettings) *claudeSettings {
	ordered := slices.Clone(managed)
	for _, scope := range []string{"local", "project", "user"} {
		if i := slices.IndexFunc(settings, func(s claudeSettings) bool { return s.scope == scope }); i >= 0 {
			ordered = append(ordered, settings[i])
		}
	}
	for i, s := range ordered {
		if v := s.doc.get(name); v != nil && v.kind == 0 && (v.raw.Kind() == 't' || v.raw.Kind() == 'f') {
			return &ordered[i]
		}
	}
	return nil
}

// report shows what init found: the settings files, the MCP servers of
// Claude Code and the other clients pclaw scan knows (which go around
// PantherClaw unless they use pclaw mcp proxy), the credentials their
// configuration holds, by name only (each is a route around PantherClaw;
// init never copies one), and agent-framework projects.
func report(a *app, opts scan.Options, settings, managed []claudeSettings) []scan.Finding {
	w := a.stdout
	_, _ = fmt.Fprintln(w, "Claude Code settings:")
	for _, s := range append(slices.Clone(settings), managed...) {
		state := "not present"
		if s.raw != nil {
			state = counts(s.doc)
			if hookRuns(s.doc) {
				state += ", runs the PantherClaw hook"
			}
		}
		_, _ = fmt.Fprintf(w, "  %-8s %s (%s)\n", s.scope, s.path, state)
	}
	_, _ = fmt.Fprintf(w, "  managed state: %s (%s)\n", managedState(managed), managedLimits)
	findings := scan.Run(opts)
	for _, f := range findings {
		at := f.Attributes
		switch f.Kind {
		case scan.KindMCPServer:
			routed := "goes around PantherClaw"
			if at["command"] == "pclaw" || at["command"] == "pclaw.exe" {
				routed = "through pclaw mcp proxy"
			} else if at["client"] != "claude_code" && at["client"] != "project" {
				routed += " (pclaw init changes only Claude Code's configuration)"
			}
			_, _ = fmt.Fprintf(w, "MCP server %q of %s in %s (%s): %s\n", at["name"], at["client"], at["config"], at["transport"], routed)
		case scan.KindEnvSecret:
			_, _ = fmt.Fprintf(w, "Credential %s (%s) in %s's configuration: a route around PantherClaw; init never copies it, "+
				"so give it to the gateway's connection instead\n", at["name"], at["secret_kind"], at["where"])
		case scan.KindAgentProject:
			_, _ = fmt.Fprintf(w, "Agent framework project: %s (%s)\n", at["path"], at["frameworks"])
		}
	}
	return findings
}

// scanOptions are where init looks: the person's configuration, as pclaw
// scan does, read from init's own environment, and the project.
func (a *app) scanOptions(home, project string) scan.Options {
	o := scan.Options{Home: home, Paths: []string{project}}
	switch runtime.GOOS {
	case "windows":
		o.ConfigDir, _ = a.env("APPDATA")
	case "darwin":
		o.ConfigDir = filepath.Join(home, "Library", "Application Support")
	default:
		o.ConfigDir = filepath.Join(home, ".config")
		if v, ok := a.env("XDG_CONFIG_HOME"); ok && v != "" {
			o.ConfigDir = v
		}
	}
	o.CodexHome, _ = a.env("CODEX_HOME")
	o.GeminiCLIHome, _ = a.env("GEMINI_CLI_HOME")
	return o
}
