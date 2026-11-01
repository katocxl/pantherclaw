// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package idps_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// TestThePageUseCaseNeedsAStepUp (G0 M22 D57): without a step-up of this
// browser session the server page's use case files no provider, not even
// for an org admin.
func TestThePageUseCaseNeedsAStepUp(t *testing.T) {
	e := newEnv(t)
	if _, _, err := e.svc.CreateOnPage(e.admin(e.alice), input("acme"), stepup.StepUp{}); !errors.Is(err, stepup.ErrStepUp) {
		t.Fatalf("no step-up: %v", err)
	}
	if ps, _, err := e.svc.List(e.admin(e.alice)); err != nil || len(ps) != 0 {
		t.Fatalf("a refused create filed: %+v %v", ps, err)
	}
}
