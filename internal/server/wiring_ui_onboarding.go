// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Onboarding progress (G0 UI D15). Phase A serves OnboardingService's
// contract only; every call answers Unimplemented until progress is
// computed from the org's records.

// onboardingService serves OnboardingService.
type onboardingService struct {
	pantherclawv1connect.UnimplementedOnboardingServiceHandler
}

// registerUIOnboarding serves OnboardingService.
func registerUIOnboarding(rs *connect.Server, _ apiDeps) {
	pantherclawv1connect.RegisterOnboardingServiceHandler(rs, onboardingService{})
}
