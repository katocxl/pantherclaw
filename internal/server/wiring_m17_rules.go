// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/consequencerules"
	"github.com/katocxl/pantherclaw/internal/consequencerules/rulesrpc"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// registerM17Rules serves ConsequenceRuleService (G0 M17 D106–D108, D112)
// as pc_app, its changes held behind the process's protected-change Gate
// for a second person in every mode (D107). Without a licence the server
// is Community: proposals and retirements are refused.
func registerM17Rules(rs *connect.Server, d apiDeps) {
	svc := &consequencerules.Service{Pool: d.pool, Definitions: &defspg.Store{Pool: d.pool}}
	if d.billing != nil {
		svc.Editions = d.billing
	}
	svc.WithProtect(d.m11protect.gate)
	pantherclawv1connect.RegisterConsequenceRuleServiceHandler(rs, rulesrpc.New(svc))
}
