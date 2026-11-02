// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/compliance/adapters/compliancerpc"
	coapp "github.com/katocxl/pantherclaw/internal/compliance/app"
	"github.com/katocxl/pantherclaw/internal/compliance/ports"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// complianceCampaigns builds the campaign results coverage reads. The stream
// that owns campaigns sets it from an init in its own wiring file; until then
// the source holds nothing and tagged controls read as not exercised.
var complianceCampaigns func(pool *db.Pool) ports.CampaignResults

func complianceService(pool *db.Pool, bill *billing.Service) *coapp.Service {
	s := &coapp.Service{Pool: pool, Campaigns: ports.NoCampaigns{}}
	if bill != nil {
		s.Ents = bill
	}
	if complianceCampaigns != nil {
		s.Campaigns = complianceCampaigns(pool)
	}
	return s
}

// registerCompliance serves ComplianceService on the public API (G0 M25
// D311), as pc_app.
func registerCompliance(rs *connect.Server, d apiDeps) {
	pantherclawv1connect.RegisterComplianceServiceHandler(rs, compliancerpc.New(complianceService(d.pool, d.billing)))
}
