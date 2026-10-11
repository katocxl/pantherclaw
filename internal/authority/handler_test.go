// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestHR191_TheGatewayIsNotSentVerifyObligations: a verify obligation is
// the Authority's to apply after dispatch, so the gateway, which refuses
// to dispatch with an obligation it cannot apply, never sees it; the
// obligations it applies still reach it.
func TestHR191_TheGatewayIsNotSentVerifyObligations(t *testing.T) {
	out := gatewayObligations([]pdomain.Obligation{
		{Rule: "verify", Kind: pdomain.Verify, Level: defs.LevelFollowUp, Timing: pdomain.TimingAfterDispatch},
		{Rule: "batch", Kind: pdomain.CountMax, Param: "batch", Max: "10", Clamp: true, Timing: pdomain.TimingBeforeExecution},
	})
	if len(out) != 1 || out[0].GetRule() != "batch" || out[0].GetKind() != "count_max" || !out[0].GetClamp() {
		t.Fatalf("gateway obligations %v", out)
	}
	if out := gatewayObligations([]pdomain.Obligation{{Kind: pdomain.Verify, Level: defs.LevelFollowUp}}); len(out) != 0 {
		t.Fatalf("a verify obligation reached the gateway: %v", out)
	}
}
