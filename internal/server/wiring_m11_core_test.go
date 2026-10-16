// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
)

// TestM11Core_JobsShareTheAPICore (G0 M11 part 2 D91 K6): the sweeps run
// on the API's core, so every port set on it reaches the jobs.
func TestM11Core_JobsShareTheAPICore(t *testing.T) {
	pool := &db.Pool{}
	core := newAutomationsCore(pool, nil, "")
	gstore := &grantspg.Store{Pool: pool}
	grants := &grantsapp.Service{Repo: gstore, Store: gstore}
	runs := runsapp.New(pool)
	core.attach(pool, grants, runs)
	if _, err := registerAutomationsCoreJobs(nil, jobs.NewRegistry(), core, nil); err != nil {
		t.Fatal(err)
	}
	switch {
	case core.grants != grants, core.svc.Grants != grants, core.svc.Runs != runs:
		t.Fatal("the jobs built their own grants or runs services")
	case grants.Ceilings != core.svc, core.svc.Changes != core.changes:
		t.Fatal("the issuance services do not use the core")
	case core.svc.Failures == nil, core.svc.Operations == nil:
		t.Fatalf("core ports: failures %v operations %v", core.svc.Failures, core.svc.Operations)
	}
	worker := newAutomationsCore(pool, nil, "")
	if _, err := registerAutomationsCoreJobs(nil, jobs.NewRegistry(), worker, nil); err != nil {
		t.Fatal(err)
	}
	if worker.svc.Grants == nil || worker.svc.Runs == nil {
		t.Fatal("a worker-only process has no issuance services")
	}
}
