// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	"github.com/katocxl/pantherclaw/internal/automations/assurance/adapters/assurancerpc"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// registerAutomationAssurance serves AssuranceService (G0 M11 part 2
// D34–D38, D59) as pc_app; without a licence service every use case fails
// closed with EDITION_REQUIRED.
func registerAutomationAssurance(rs *connect.Server, d apiDeps) {
	svc := &assurance.Service{Pool: d.pool}
	if d.billing != nil {
		svc.Ents = d.billing
	}
	pantherclawv1connect.RegisterAssuranceServiceHandler(rs, assurancerpc.New(svc))
}
