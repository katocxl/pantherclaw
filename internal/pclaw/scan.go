// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/scan"
)

func init() {
	commands["scan"] = command{"scan [--path DIR]... [--json] [--no-env] [--no-user-config] [--submit [--scope SCOPE [--complete]]]", scanCmd}
}

// submitBatch is the most findings one SubmitScanFindings call carries.
const submitBatch = 200

// scanCmd runs the local shadow-agent scan (PN-001.1). Results stay on the
// machine unless --submit sends the MCP servers and agent projects (never
// the credentials) to the org as discovered agents.
func scanCmd(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var paths list
	fs.Var(&paths, "path", "project directory to search for agent frameworks and MCP configs (repeatable; default: the current directory)")
	asJSON, noEnv, noUser := fs.Bool("json", false, "print the findings as JSON"),
		fs.Bool("no-env", false, "do not check the environment for credentials"),
		fs.Bool("no-user-config", false, "skip the per-user MCP configurations (Claude, Cursor, VS Code, Windsurf, Zed, Junie, JetBrains AI Assistant, Codex, Gemini CLI)")
	submit := fs.Bool("submit", false, "add the MCP servers and agent projects found to your org's discovered agents")
	scope := fs.String("scope", "", "CI mode: the repository or host this scan covers; its findings are kept apart per scope (with --submit)")
	complete := fs.Bool("complete", false, "CI mode: the scan read the whole --scope, so a discovery of the scope it no longer finds counts a missed scan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || ((*scope != "" || *complete) && !*submit) {
		return errUsage
	}
	if *complete && *scope == "" {
		return errCompleteScope
	}
	if len(paths) == 0 {
		paths = list{"."}
	}
	host, _ := os.Hostname()
	o := scan.Options{Host: host, Paths: paths}
	if !*noUser {
		o.Home, _ = os.UserHomeDir()
		o.ConfigDir, _ = os.UserConfigDir()
		o.CodexHome, o.GeminiCLIHome = os.Getenv("CODEX_HOME"), os.Getenv("GEMINI_CLI_HOME")
	}
	if !*noEnv {
		o.Environ = os.Environ()
	}
	findings := scan.Run(o)
	if *asJSON {
		b, err := json.Marshal(findings, json.Deterministic(true))
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(a.stdout, string(b)); err != nil {
			return err
		}
	} else if err := printFindings(a, findings); err != nil {
		return err
	}
	if !*submit {
		return nil
	}
	return submitFindings(ctx, a, host, findings, *scope, *complete)
}

var (
	errCompleteScope = errors.New("--complete needs --scope: a complete scan names what it covers")
	// errCompleteTooLarge: a complete scan is one submission (D130).
	errCompleteTooLarge = errors.New("complete scans are limited to 200 findings per scope; narrow --scope")
)

func printFindings(a *app, findings []scan.Finding) error {
	groups := []struct{ kind, title string }{
		{scan.KindMCPServer, "MCP servers"},
		{scan.KindAgentProject, "Agent projects"},
		{scan.KindEnvSecret, "Credentials (redacted)"},
	}
	var b strings.Builder
	for _, g := range groups {
		var lines []string
		for _, f := range findings {
			if f.Kind == g.kind {
				lines = append(lines, "  "+describeFinding(f))
			}
		}
		fmt.Fprintf(&b, "%s: %d\n", g.title, len(lines))
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
	}
	b.WriteString("Not finding something does not mean it is absent: the scan reads known locations only.\n")
	_, err := fmt.Fprint(a.stdout, b.String())
	return err
}

func describeFinding(f scan.Finding) string {
	at := f.Attributes
	switch f.Kind {
	case scan.KindMCPServer:
		s := at["name"] + " (" + at["client"] + ", " + at["config"] + ")"
		if at["command"] != "" {
			s += ": runs " + at["command"]
		}
		if at["url_host"] != "" {
			s += ": calls " + at["url_host"]
		}
		if at["env_names"] != "" {
			s += "; env " + at["env_names"]
		}
		if at["header_names"] != "" {
			s += "; headers " + at["header_names"]
		}
		return s
	case scan.KindAgentProject:
		return at["path"] + " (" + at["frameworks"] + " in " + at["manifest"] + ")"
	default:
		return at["name"] + ": " + at["secret_kind"] + " " + at["redacted"] + " (" + at["where"] + ")"
	}
}

// submitFindings sends the MCP servers and agent projects; credentials stay
// on the machine.
func submitFindings(ctx context.Context, a *app, host string, findings []scan.Finding, scope string, complete bool) error {
	var send []*pantherclawv1.ScanFinding
	for _, f := range findings {
		if f.Kind == scan.KindEnvSecret {
			continue
		}
		attrs := map[string]string{}
		for k, v := range f.Attributes {
			if k != "host" {
				attrs[k] = v
			}
		}
		send = append(send, &pantherclawv1.ScanFinding{Kind: f.Kind, Key: f.Key, Attributes: attrs})
	}
	if len(send) == 0 {
		if complete {
			// Nothing is sent, so nothing counts a miss (D130).
			_, err := fmt.Fprintln(a.stdout, "nothing to submit: an empty scope never marks agents vanished")
			return err
		}
		_, err := fmt.Fprintln(a.stdout, "nothing to submit")
		return err
	}
	if complete && len(send) > submitBatch {
		return errCompleteTooLarge
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	var created, counted, dropped, missed int32
	for start := 0; start < len(send); start += submitBatch {
		res, err := c.agents.SubmitScanFindings(ctx, &pantherclawv1.SubmitScanFindingsRequest{
			Findings: send[start:min(start+submitBatch, len(send))], Host: host, Scope: scope, Complete: complete,
		})
		if err != nil {
			return err
		}
		created, counted, dropped, missed = created+res.GetCreated(), counted+res.GetCounted(), dropped+res.GetDropped(), missed+res.GetMissed()
	}
	_, err = fmt.Fprintf(a.stdout, "submitted %d findings: %d new discovered agents, %d already known, %d dropped (org limit); credentials were not sent\n",
		len(send), created, counted, dropped)
	if err == nil && complete {
		_, err = fmt.Fprintf(a.stdout, "complete scan of %s: %d known discoveries of the scope were not found (each counts a missed scan)\n", scope, missed)
	}
	return err
}
