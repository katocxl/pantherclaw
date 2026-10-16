// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import "testing"

// D96: the engine fills triggers' hooks, the evidence packs' execution
// reader and the shared core's ports; none is left nil.
func TestAutomationEnginePortsAreWired(t *testing.T) {
	if automationStarter == nil || automationStarter(nil, nil, nil) == nil {
		t.Fatal("no Starter")
	}
	if automationExecutions == nil || automationExecutions(nil) == nil {
		t.Fatal("no ExecutionLookup")
	}
	if automationPauser == nil || automationPauser(nil) == nil {
		t.Fatal("no Pauser")
	}
	if automationPackExecutions == nil || automationPackExecutions(nil) == nil {
		t.Fatal("no pack Executions")
	}
	if s := newPackBuilder(&Config{}, nil, nil, nil); s.Executions == nil {
		t.Fatal("packbuild.Executions is nil")
	}
	core := newAutomationsCore(nil, nil, "", nil, nil)
	shareCore(core, newAutomationEngine(engineDeps{}), nil, nil, nil)
	if core.svc.Executions == nil || core.svc.Triggers == nil || core.svc.Destinations == nil {
		t.Fatalf("core ports: executions %v, triggers %v, destinations %v",
			core.svc.Executions != nil, core.svc.Triggers != nil, core.svc.Destinations != nil)
	}
}
