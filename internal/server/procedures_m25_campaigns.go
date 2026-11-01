// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m25CampaignProcedures are the campaign procedures of RangeService (G0 M25
// D309): redteam.run over the range twin, reads are redteam.read.
var m25CampaignProcedures = map[string]td.Permission{
	pantherclawv1connect.RangeServiceStartCampaignProcedure:  td.PermRedteamRun,
	pantherclawv1connect.RangeServiceFinishCampaignProcedure: td.PermRedteamRun,
	pantherclawv1connect.RangeServiceGetCampaignProcedure:    td.PermRedteamRead,
	pantherclawv1connect.RangeServiceListCampaignsProcedure:  td.PermRedteamRead,
}

var m25CampaignClasses = map[string]entitlements.Class{
	pantherclawv1connect.RangeServiceStartCampaignProcedure:  entitlements.ClassChange,
	pantherclawv1connect.RangeServiceFinishCampaignProcedure: entitlements.ClassChange,
	pantherclawv1connect.RangeServiceGetCampaignProcedure:    entitlements.ClassRead,
	pantherclawv1connect.RangeServiceListCampaignsProcedure:  entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m25CampaignProcedures)
	maps.Copy(procedureClasses, m25CampaignClasses)
}
