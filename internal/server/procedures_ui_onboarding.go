// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// uiOnboardingProcedures are OnboardingService's procedures (G0 UI D15).
var uiOnboardingProcedures = map[string]td.Permission{
	pantherclawv1connect.OnboardingServiceGetProgressProcedure: td.PermOnboardingRead,
}

func init() { maps.Copy(procedurePermissions, uiOnboardingProcedures) }
