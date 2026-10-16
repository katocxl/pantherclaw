// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	"github.com/katocxl/pantherclaw/internal/billing"
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
// workers start; RoleWorker attaches the process's after the engine jobs
// are registered (the core jobs refuse to start without them, D112 X1).
func TestAutomationEnginePortsAreWired(t *testing.T) {
	roles := map[string]func(core *automationsCore){
		RoleAll: func(core *automationsCore) {
			core.attach(nil, &grantsapp.Service{}, runsapp.New(nil))
		},
		RoleWorker: func(core *automationsCore) {
			core.attach(nil, &grantsapp.Service{}, runsapp.New(nil))
			if _, err := registerAutomationsCoreJobs(nil, jobs.NewRegistry(), core, nil); err != nil {
				t.Fatal(err)
			}
		},
	}
	bill, log := &billing.Service{}, slog.New(slog.DiscardHandler)
	for role, attach := range roles {
		t.Run(role, func(t *testing.T) {
			core := newAutomationsCore(nil, nil, "")
			if role == RoleAll {
				attach(core)
			}
			e, err := driverEngine(core, engineDeps{bill: bill, log: log})
			if err != nil {
				t.Fatal(err)
			}
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
			s, err := automationStarter(core, nil, bill, log)
			starter, ok := s.(*pgengine.Engine)
			if err != nil || !ok {
				t.Fatalf("triggers' Starter is not the engine (%v)", err)
			}
			sharesCore(t, "starter", starter, core)
			l, err := automationExecutions(core, nil, bill, log)
			lookup, ok := l.(*pgengine.Engine)
			if err != nil || !ok {
				t.Fatalf("triggers' ExecutionLookup is not the engine (%v)", err)
			}
			sharesCore(t, "lookup", lookup, core)
			pb, err := newPackBuilder(&Config{}, nil, nil, core, bill, log)
			if err != nil {
				t.Fatal(err)
			}
			packs, ok := pb.Executions.(*pgengine.Engine)
			if !ok {
				t.Fatal("packbuild.Executions is not the engine")
			}
			sharesCore(t, "packs", packs, core)
		})
	}
}

// sharesCore fails unless e pauses, voids and checks ceilings through the
// shared core, and has the edition and the logger (D112).
func sharesCore(t *testing.T, name string, e *pgengine.Engine, core *automationsCore) {
	t.Helper()
	if any(e.Pauser) != any(core.svc) || any(e.Voider) != any(core.svc) || any(e.Ceilings) != any(core.svc) {
		t.Fatalf("%s engine: Pauser, Voider or Ceilings is not the shared core", name)
	}
	if e.Editions == nil || e.Log == nil {
		t.Fatalf("%s engine: Editions %v, Log %v", name, e.Editions != nil, e.Log != nil)
	}
}

// D104: a failed launch's withdraw names core's GRANT scope, so it revokes
// only the grant the launch was issued.
func TestAutomationWithdrawUsesTheGrantScope(t *testing.T) {
	if steps.RevokeOneGrant != grantsapp.RevokeScopeGrant {
		t.Fatalf("steps %q, core %q", steps.RevokeOneGrant, grantsapp.RevokeScopeGrant)
	}
}

// D108, D108a: the driver builds the security steps from the process's
// core and the server config.
func TestAutomationSecurityStepsGetTheConfig(t *testing.T) {
	var got []securityStepDeps
	prev := automationSecuritySteps
	automationSecuritySteps = func(d securityStepDeps) (autoports.StepRegistry, error) {
		got = append(got, d)
		return nil, nil
	}
	t.Cleanup(func() { automationSecuritySteps = prev })
	cfg := &Config{}
	cfg.CEL.MaxCost = 1234
	core := newAutomationsCore(nil, nil, "")
	if _, err := registerAutomationEngineJobs(nil, jobs.NewRegistry(), core, cfg, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("the driver built no security steps")
	}
	d := got[0]
	if d.Core != core || d.CEL != cfg.CEL || d.Freshness != freshnessOf(cfg) || d.LogOrigin != cfg.logOrigin() {
		t.Fatalf("security step deps %+v", d)
	}
}

// D97 N1, D105 N3: the cleanup recognizes triggers' exported Cancel errors
// (errors.Is, no copied reason), so a delivery that may have been sent is
// never reported canceled.
func TestAutomationCleanupClassifiesDeliveryErrors(t *testing.T) {
	e, err := driverEngine(newAutomationsCore(nil, nil, ""), engineDeps{})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := e.Cleaner.(pgengine.Cleanup)
	if !ok || c.MaybeSent == nil || c.NotPending == nil {
		t.Fatal("the driver's cleanup cannot classify Cancel errors")
	}
	if !c.MaybeSent(fmt.Errorf("cancel: %w", endpoints.ErrDeliveryMayHaveBeenSent)) || c.MaybeSent(endpoints.ErrDeliveryNotPending) {
		t.Fatal("MaybeSent does not match triggers' ErrDeliveryMayHaveBeenSent alone")
	}
	if !c.NotPending(endpoints.ErrDeliveryNotPending) || c.NotPending(endpoints.ErrDeliveryMayHaveBeenSent) {
		t.Fatal("NotPending does not match triggers' ErrDeliveryNotPending alone")
	}
}
