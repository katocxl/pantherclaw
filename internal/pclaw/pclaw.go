// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pclaw implements the pclaw command-line interface: login and
// tenancy administration (M2); agents, instances, trusted-issuer entries,
// runs and the waitlist, and the workload side of PAP/1 (M3). cmd/pclaw
// only wires the process.
//
// Authentication: `pclaw login` stores a CLI session (ADR-0016); every
// command refreshes the access token when needed, signing the refresh with
// the device key. Automation can instead set PANTHERCLAW_SERVER and
// PANTHERCLAW_API_KEY (a pck_ key). The `workload` commands run
// inside a workload and authenticate with its key file (PAP/1), never with
// a user session.
package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// Env reads environment variables (os.LookupEnv in production).
type Env func(string) (string, bool)

// Options are the process-level dependencies.
type Options struct {
	// OpenBrowser opens a URL in the user's browser (nil: never).
	OpenBrowser func(context.Context, string) error
	// HTTPClient overrides the HTTP client (tests).
	HTTPClient *http.Client
	// Stdin is the process input (mcp proxy, hook); nil reads nothing.
	Stdin io.Reader
}

type app struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	env            Env
	http           *http.Client
	openBrowser    func(context.Context, string) error
}

var errUsage = errors.New("usage")

type command struct {
	usage string
	run   func(context.Context, *app, []string) error
}

// commands maps "group verb" (or a single word) to its implementation.
var commands = map[string]command{
	"login":  {"login --server URL --org ID [--invitation TOKEN] [--idp NAME] [--no-browser]", login},
	"logout": {"logout", logout},
	"whoami": {"whoami", whoami},
}

func usageText() string {
	var b strings.Builder
	b.WriteString("pclaw — PantherClaw command line\n\nUsage:\n")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b.WriteString("  pclaw " + commands[n].usage + "\n")
	}
	b.WriteString("  pclaw version\n\nAutomation: set PANTHERCLAW_SERVER and PANTHERCLAW_API_KEY instead of logging in.\n")
	return b.String()
}

// Run executes pclaw and returns the exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, env Env, opts Options) int {
	a := &app{stdin: opts.Stdin, stdout: stdout, stderr: stderr, env: env, http: opts.HTTPClient, openBrowser: opts.OpenBrowser}
	if a.stdin == nil {
		a.stdin = strings.NewReader("")
	}
	if a.http == nil {
		// Only the configured server is contacted; no redirects (HR-070).
		a.http = httpx.NewControlClient(httpx.ControlConfig{Timeout: 30 * time.Second})
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usageText())
		return 2
	}
	if args[0] == "version" || args[0] == "--version" {
		_, _ = fmt.Fprintln(stdout, version.Get().String("pclaw"))
		return 0
	}
	cmd, rest, ok := lookup(args)
	if !ok {
		_, _ = fmt.Fprint(stderr, usageText())
		return 2
	}
	err := cmd.run(ctx, a, rest)
	var exit *exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		_, _ = fmt.Fprintln(stderr, exit.msg)
		return exit.code
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		_, _ = fmt.Fprintln(stderr, "usage: pclaw "+cmd.usage)
		return 2
	default:
		_, _ = fmt.Fprintln(stderr, "pclaw: "+describe(err))
		return 1
	}
}

func lookup(args []string) (command, []string, bool) {
	if len(args) >= 2 {
		if c, ok := commands[args[0]+" "+args[1]]; ok {
			return c, args[2:], true
		}
	}
	c, ok := commands[args[0]]
	return c, args[1:], ok
}

// exitError ends a command with its own exit code and message (the Claude
// Code hook blocks with code 2).
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// describe turns RPC errors into one readable line.
func describe(err error) string {
	var ce *connect.Error
	if errors.As(err, &ce) {
		return strings.ReplaceAll(strings.ToLower(ce.Code().String()), "_", " ") + ": " + ce.Message()
	}
	return err.Error()
}
