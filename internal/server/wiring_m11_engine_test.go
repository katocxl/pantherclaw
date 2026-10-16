// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

// D96, D105 (N1, N8): the engine the driver runs every step with, triggers'
// hooks and the evidence packs' execution reader all use the process's one
// core: its grants and runs services (whatever ports other streams set on
// them, the promotion gate included) and its svc as Pauser, Voider and
// Ceilings. The core gets the engine's, triggers' and destinations' ports.
// Both process roles: RoleAll attaches the API's grants and runs before the
// workers start; RoleWorker attaches its own in the core jobs, after the
// engine jobs are registered.
func TestAutomationEnginePortsAreWired(t *testing.T) {
	roles := map[string]func(core *automationsCore){
		RoleAll: func(core *automationsCore) {
			core.attach(nil, &grantsapp.Service{}, runsapp.New(nil))
		},
		RoleWorker: func(core *automationsCore) {
			if _, err := registerAutomationsCoreJobs(nil, jobs.NewRegistry(), core, nil); err != nil {
				t.Fatal(err)
			}
		},
	}
	for role, attach := range roles {
		t.Run(role, func(t *testing.T) {
			core := newAutomationsCore(nil, nil, "")
			if role == RoleAll {
				attach(core)
			}
			e := driverEngine(core, nil, nil, "", nil, nil)
			if role == RoleWorker {
				attach(core)
			}
			if core.grants == nil || core.runs == nil {
				t.Fatal("the core has no grants or runs service")
			}
			sharesCore(t, "driver", e, core)
			cleanup, ok := e.Cleaner.(pgengine.Cleanup)
			if !ok {
				t.Fatalf("driver cleaner %T", e.Cleaner)
			}
			g, ok := cleanup.Grants.(grantsPort)
			if svc, err := g.svc(); !ok || err != nil || svc != core.grants || svc.Ceilings != core.svc {
				t.Fatalf("driver grants: not the shared core's grants service (%v)", err)
			}
			r, ok := cleanup.Runs.(runsPort)
			if svc, err := r.svc(); !ok || err != nil || svc != core.runs {
				t.Fatalf("driver runs: not the shared core's runs service (%v)", err)
			}
			if core.svc.Executions == nil || core.svc.Triggers == nil || core.svc.Destinations == nil {
				t.Fatalf("core ports: executions %v, triggers %v, destinations %v",
					core.svc.Executions != nil, core.svc.Triggers != nil, core.svc.Destinations != nil)
			}

			if p := automationPauser(core); any(p) != any(core.svc) {
				t.Fatalf("triggers' Pauser %T is not the shared core", p)
			}
			starter, ok := automationStarter(core, nil, nil, nil).(*pgengine.Engine)
			if !ok {
				t.Fatal("triggers' Starter is not the engine")
			}
			sharesCore(t, "starter", starter, core)
			lookup, ok := automationExecutions(core, nil).(*pgengine.Engine)
			if !ok {
				t.Fatal("triggers' ExecutionLookup is not the engine")
			}
			sharesCore(t, "lookup", lookup, core)
			packs, ok := newPackBuilder(&Config{}, nil, nil, core, nil).Executions.(*pgengine.Engine)
			if !ok {
				t.Fatal("packbuild.Executions is not the engine")
			}
			sharesCore(t, "packs", packs, core)
		})
	}
}

// sharesCore fails unless e pauses, voids and checks ceilings through the
// shared core.
func sharesCore(t *testing.T, name string, e *pgengine.Engine, core *automationsCore) {
	t.Helper()
	if any(e.Pauser) != any(core.svc) || any(e.Voider) != any(core.svc) || any(e.Ceilings) != any(core.svc) {
		t.Fatalf("%s engine: Pauser, Voider or Ceilings is not the shared core", name)
	}
}
