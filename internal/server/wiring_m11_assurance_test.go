// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"testing"

	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// D96: the shared automations core gets assurance's TestGate and
// RolloutEvidence, so a tested version can be enabled and a verified
// COHORT stage widened.
func TestAssurancePortsOnTheSharedCore(t *testing.T) {
	core := newAutomationsCore(nil, nil, "")
	assurancePorts(core)
	if core.svc.TestGate == nil || core.svc.Rollout == nil {
		t.Fatalf("TestGate %v, Rollout %v", core.svc.TestGate, core.svc.Rollout)
	}
}

// D107 A1: the simulation previews through the shared core's grants
// service, never one of its own; before one is attached it refuses.
func TestSimulationPreviewsThroughTheSharedCore(t *testing.T) {
	core := newAutomationsCore(nil, nil, "")
	is := coreIssuer{core: core}
	if _, err := is.IssueForAutomationTx(context.Background(), db.TenantTx{}, grantsapp.AutomationIssue{}); !errors.Is(err, errNoIssuer) {
		t.Fatalf("no grants attached: %v", err)
	}
	grants := &grantsapp.Service{}
	core.grants = grants
	if _, err := is.IssueForAutomationTx(context.Background(), db.TenantTx{}, grantsapp.AutomationIssue{}); errors.Is(err, errNoIssuer) {
		t.Fatal("the attached grants service was not used")
	}
}
