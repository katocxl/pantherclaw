// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/contentsignals/adapters/contentrpc"
	contentapp "github.com/katocxl/pantherclaw/internal/contentsignals/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// contentSink keeps what gateways report, for the Authority (G0 M27 D507):
// inference alerts through the Raiser and owned failures through the sink.
func contentSink(pool *db.Pool) *contentapp.Sink {
	return &contentapp.Sink{Raiser: edgesRaiser(pool), Failures: edgesFailures()}
}

// registerM27Content serves ContentSignalService (G0 M27 D507) and holds a
// change of mode out of ACTIVE behind the Gate (D512). The procedure
// permissions are in procedures_m27_content.go.
func registerM27Content(rs *connect.Server, d apiDeps) {
	svc := &contentapp.Service{Pool: d.pool}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	svc.RegisterProtect(d.m11protect.gate)
	pantherclawv1connect.RegisterContentSignalServiceHandler(rs, contentrpc.New(svc))
}
