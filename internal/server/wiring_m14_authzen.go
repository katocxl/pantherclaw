// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"net/http"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/enforcementpoints"
	"github.com/katocxl/pantherclaw/internal/enforcementpoints/pointsrpc"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// AuthZEN (G0 M14 D26-D29; PN-023, ADR-0019): the API serves
// EnforcementPointService, the enforcement point confirm page and,
// outside Connect, the AuthZEN decision endpoint, which decides in-process
// through the Authority's external path (D61).

// m14AuthZEN is what the API mounts outside Connect.
type m14AuthZEN struct {
	endpoint *authzenEndpoint
	web      func(mux *http.ServeMux)
}

// mount adds the decision endpoint (its bearer is the credential, HR-317)
// and the confirm page.
func (m m14AuthZEN) mount(mux *http.ServeMux) {
	if m.endpoint != nil {
		m.endpoint.mount(mux)
	}
	if m.web != nil {
		m.web(mux)
	}
}

// registerAuthZEN serves EnforcementPointService and prepares the decision
// endpoint and the confirm page; without bearer authentication (tests)
// the endpoint is not served.
func registerAuthZEN(rs *connect.Server, d apiDeps) m14AuthZEN {
	points := enforcementpoints.New(d.pool)
	pantherclawv1connect.RegisterEnforcementPointServiceHandler(rs, pointsrpc.New(points, d.publicURL))
	var out m14AuthZEN
	if d.web != nil {
		web := d.web
		out.web = func(mux *http.ServeMux) { web.MountEnforcementPoints(mux, points) }
	}
	if d.m10ops.authn != nil && d.authority != nil {
		out.endpoint = newAuthZENEndpoint(d.pool, d.m10ops.authn, d.authority, d.publicURL, d.cel, clock.System{}, d.log)
		probeM14("m14.authzen.endpoint", out.endpoint)
	}
	probeM14("m14.authzen.points", points)
	return out
}
