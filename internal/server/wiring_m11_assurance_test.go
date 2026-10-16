// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import "testing"

// D96: the shared automations core gets assurance's TestGate and
// RolloutEvidence, so a tested version can be enabled and a verified
// COHORT stage widened.
func TestAssurancePortsOnTheSharedCore(t *testing.T) {
	core := newAutomationsCore(nil, nil, "", nil, nil)
	assurancePorts(core)
	if core.svc.TestGate == nil || core.svc.Rollout == nil {
		t.Fatalf("TestGate %v, Rollout %v", core.svc.TestGate, core.svc.Rollout)
	}
}
