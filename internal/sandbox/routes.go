// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sandbox

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
)

// Route is a route the edge saw the agent take: a destination it refused
// (direct_api; host and port) or a credential it stripped from a request
// (credential; the credential's kind and a SHA-256 prefix, never the
// value). Routes are untrusted observations that never grant anything
// (HR-148); the server records them for the session's agent and mapped
// connections (G0 M9 design decisions 4 and 11).
type Route struct {
	Kind    string
	Locator string
}

// Route kinds.
const (
	RouteDirectAPI  = "direct_api"
	RouteCredential = "credential"
)

// MaxRoutes bounds the routes a session reports, maxLocator a locator.
const (
	MaxRoutes  = 64
	maxLocator = 512
)

// StartAgent starts the agent's container and notes its address while it
// runs: the engine clears it once the container stopped.
func (s *Sandbox) StartAgent(ctx context.Context) error {
	if err := s.c.Start(ctx, s.Agent); err != nil {
		return err
	}
	info, err := s.c.InspectContainer(ctx, s.Agent)
	if err != nil {
		return err
	}
	if s.agentAddr = info.Address(s.Internal); s.agentAddr == "" {
		return errors.New("sandbox: the agent has no address on the sandbox network")
	}
	return nil
}

// Routes reads from the edge's log the routes the agent took, once each
// and at most MaxRoutes. The probe's own refused requests (its negative
// controls and the planted push) come from another address and are left
// out. Without a started agent there are none.
func (s *Sandbox) Routes(ctx context.Context) ([]Route, error) {
	if s.agentAddr == "" {
		return nil, nil
	}
	log, err := s.c.Logs(ctx, s.Edge)
	if err != nil {
		return nil, err
	}
	return edgeRoutes(log, s.agentAddr), nil
}

// edgeRoutes are the routes in an edge log that client took.
func edgeRoutes(log []byte, client string) []Route {
	var routes []Route
	seen := map[Route]bool{}
	for line := range strings.Lines(string(log)) {
		var e struct {
			Event       string `json:"event"`
			Client      string `json:"client"`
			Destination string `json:"destination"`
			Kind        string `json:"kind"`
			Prefix      string `json:"sha256_prefix"`
		}
		if json.Unmarshal([]byte(line), &e) != nil || e.Client != client {
			continue
		}
		var r Route
		switch {
		case e.Event == edge.EventRefused && e.Destination != "":
			r = Route{Kind: RouteDirectAPI, Locator: e.Destination}
		case e.Event == edge.EventCredentialStripped && e.Kind != "" && e.Prefix != "":
			r = Route{Kind: RouteCredential, Locator: e.Kind + ":" + e.Prefix}
		default:
			continue
		}
		if seen[r] || utf8.RuneCountInString(r.Locator) > maxLocator {
			continue
		}
		seen[r] = true
		if routes = append(routes, r); len(routes) == MaxRoutes {
			break
		}
	}
	return routes
}
