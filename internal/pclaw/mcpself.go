// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/pclaw/selfmcp"
)

// `pclaw mcp self` (G0 M27 D510; F947) is PantherClaw's own read-only MCP
// server: a customer's SOC agent starts it as a stdio MCP server, with the key
// of a service account that holds the Investigator role in
// PANTHERCLAW_API_KEY or PANTHERCLAW_API_KEY_FILE. It speaks only stdio and
// opens no listener. Diagnostics go to stderr; stdout carries only the
// protocol.

func init() {
	commands["mcp self"] = command{usage: "mcp self", run: mcpSelf}
}

func mcpSelf(ctx context.Context, a *app, args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	b, err := a.selfBackend()
	if err != nil {
		return err
	}
	return (&selfmcp.Server{Backend: b, Out: a.stdout}).Serve(ctx, a.stdin)
}

// selfBackend is the five reads under the service account's key, behind the
// allow-list transport. A person's stored login is refused: the role that
// audits every read binds only to service accounts.
func (a *app) selfBackend() (selfmcp.Backend, error) {
	if err := a.useAPIKeyFile(); err != nil {
		return nil, err
	}
	if key, ok := a.env("PANTHERCLAW_API_KEY"); !ok || key == "" {
		return nil, errors.New("pclaw mcp self needs a service account key: set PANTHERCLAW_API_KEY_FILE (or PANTHERCLAW_API_KEY) and PANTHERCLAW_SERVER")
	}
	s, err := a.session()
	if err != nil {
		return nil, err
	}
	base := a.http.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	hc := &http.Client{
		Transport: selfmcp.AllowList{Base: authTransport{s: s, base: base}}, Timeout: a.http.Timeout, CheckRedirect: a.http.CheckRedirect,
	}
	return selfmcp.NewBackend(connect.NewClient(connecthttp.NewTransport(hc, s.server))), nil
}
