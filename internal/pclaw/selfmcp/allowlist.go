// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package selfmcp is PantherClaw's own read-only MCP server (G0 M27 D510,
// H9): `pclaw mcp self` speaks MCP on stdio so a customer's SOC agent can
// investigate. It has four tools, each one read procedure. It is not an
// assistant: it calls no model and nothing here sends a record to one
// (HR-542).
package selfmcp

import (
	"errors"
	"net/http"
	"slices"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// procedures is the closed allow-list of the tool layer (HR-656). The server
// holds the same list for the Investigator role (HR-655); a test ties them
// together.
var procedures = []string{
	pantherclawv1connect.InvestigationServiceWhatHappenedProcedure,
	pantherclawv1connect.InvestigationServiceGetRunTimelineProcedure,
	pantherclawv1connect.SearchServiceSearchProcedure,
	pantherclawv1connect.GraphServiceGetGraphProcedure,
}

// Procedures returns the allow-list.
func Procedures() []string { return slices.Clone(procedures) }

// errNotAllowed is what a request off the list gets. It never leaves the
// process.
var errNotAllowed = errors.New("selfmcp: the procedure is not on the read allow-list")

// AllowList is the HTTP transport under the tool layer: it sends a POST to an
// allow-listed procedure and refuses anything else before it leaves.
type AllowList struct {
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper. The path must be an allow-listed
// procedure exactly: pclaw's server URL is a base URL with no path
// (checkServer), so the procedure is the whole path.
func (t AllowList) RoundTrip(r *http.Request) (*http.Response, error) {
	allowed := r.Method == http.MethodPost && slices.Contains(procedures, r.URL.Path)
	if !allowed {
		return nil, errNotAllowed
	}
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}
