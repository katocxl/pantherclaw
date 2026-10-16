// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/promotions"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

// TestHR290_TheProductionGrantsStoreAndServiceHaveTheGate (D81, D93): the
// grants store, which issues, revises and delegates in its transaction,
// and the automation issuer (the grants service the automations core
// issues through, on the API and in a worker-only process) all carry the
// one promotion gate, with what a prefix needs. (Integration fixtures that
// build their own store test the grants themselves, not the gate.)
func TestHR290_TheProductionGrantsStoreAndServiceHaveTheGate(t *testing.T) {
	pool := &db.Pool{}
	store, svc := newGrants(pool)
	api := newAutomationsCore(pool, nil, "")
	api.attach(pool, svc, runsapp.New(pool).WithGrants(store))
	worker := newAutomationsCore(pool, nil, "")
	attachM11Issuance(worker, pool) // as cmdServe does before the role split (D113)
	if _, err := registerAutomationsCoreJobs(nil, jobs.NewRegistry(), worker, nil); err != nil {
		t.Fatal(err)
	}
	check := func(name string, g grantsapp.PromotionGate) {
		t.Helper()
		gate, ok := g.(promotions.Gate)
		if !ok {
			t.Fatalf("the %s's gate is %T, want promotions.Gate", name, g)
		}
		if gate.Packages == nil {
			t.Errorf("the %s's gate cannot expand prefixes", name)
		}
	}
	check("store", store.Promotions)
	check("automation issuer", api.svc.Grants.Promotions)
	check("worker's automation issuer", worker.svc.Grants.Promotions)
	if svc.Repo != store || api.svc.Grants.Store != grantsapp.TxStore(store) {
		t.Error("the service does not issue through the gated store")
	}
}
