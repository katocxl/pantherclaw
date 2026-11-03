// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/compliance/adapters/campaignresults"
	"github.com/katocxl/pantherclaw/internal/compliance/adapters/compliancerpc"
	coapp "github.com/katocxl/pantherclaw/internal/compliance/app"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

func complianceService(pool *db.Pool, bill *billing.Service) *coapp.Service {
	s := &coapp.Service{Pool: pool, Campaigns: campaignresults.Library(campaignResults(pool))}
	if bill != nil {
		s.Ents = bill
	}
	return s
}

// registerCompliance serves ComplianceService on the public API (G0 M25
// D311), as pc_app.
func registerCompliance(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterComplianceServiceHandler(rs, compliancerpc.New(complianceService(d.pool, d.billing)))
}
