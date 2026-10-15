// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/cases/adapters/casesrpc"
	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/investigations"
	"github.com/katocxl/pantherclaw/internal/investigations/adapters/investigationsrpc"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
)

// m10CaseEditions returns the server's entitlements source, or nil (fail
// closed: no cases, Community investigation views).
func m10CaseEditions(d apiDeps) capp.Editions {
	if d.billing == nil {
		return nil
	}
	return d.billing
}

// caseService builds the case use cases (G0 M10 D19). The reach and
// response lenses read exposure and response through the ports in
// wiring_m10_ports.go (capp.ReachView, capp.ResponseView; D49).
func caseService(d apiDeps) *capp.Service {
	return &capp.Service{
		Pool: d.pool, Editions: m10CaseEditions(d),
		Reach: casesReach{svc: m10Exposure(d.pool, d.billing)}, Response: casesResponse{r: m10Response(d.pool, d.billing)},
	}
}

// caseOpener is the reflexports.CaseOpener other streams open cases with
// (D1): detections, response and Shared Signals.
func caseOpener(d apiDeps) reflexports.CaseOpener { //nolint:unused // wired by the M10 streams that open cases (D1)
	return capp.NewOpener(m10CaseEditions(d))
}

// registerCases serves CaseService and InvestigationService on the public
// API (G0 M10 D19, D20).
func registerCases(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterCaseServiceHandler(rs, casesrpc.New(caseService(d)))
	inv := &investigations.Service{Pool: d.pool}
	if e := m10CaseEditions(d); e != nil {
		inv.Editions = e
	}
	pantherclawv1connect.RegisterInvestigationServiceHandler(rs, investigationsrpc.New(inv))
}
