// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/search"
	"github.com/katocxl/pantherclaw/internal/search/adapters/searchrpc"
)

// registerM11Search registers SearchService (G0 M10 D34; G0 M11 part 2
// D44–D48): structured, built-in and saved queries, quick find,
// plain-language questions, incident correlation (Team, through the
// licence), and opening cases from results through cases' CaseOpener.
func registerM11Search(rs *connect.Server, d apiDeps) {
	svc := &search.Service{
		Pool: d.pool, Defs: &defspg.Store{Pool: d.pool}, Clock: clock.System{},
		Exposure: searchExposure{svc: m10Exposure(d.pool, d.billing)},
		Cases:    m10CaseOpener(d.billing),
	}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	pantherclawv1connect.RegisterSearchServiceHandler(rs, searchrpc.New(svc))
}
