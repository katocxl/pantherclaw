// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m29TokenProcedures are ModelUsageService's procedures (G0 M29 D825): the
// monthly token report needs budget.read; the use case then checks the
// edition (Team, D829).
var m29TokenProcedures = map[string]td.Permission{
	pantherclawv1connect.ModelUsageServiceGetTokenReportProcedure: td.PermBudgetRead,
}

// m29TokenClasses are their plan-gate classes: reads.
var m29TokenClasses = map[string]entitlements.Class{
	pantherclawv1connect.ModelUsageServiceGetTokenReportProcedure: entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m29TokenProcedures)
	maps.Copy(procedureClasses, m29TokenClasses)
}
