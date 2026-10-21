// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgengine_test

import (
	"context"
	"testing"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestEngineJobsInsertUnderRiver (G0 UI D94): River 0.48 accepts the
// engine's unique options (ByState holds every required state), a sweep's
// second wake of one execution is a duplicate, and an event's wake (with
// its own Wake id) never is.
func TestEngineJobsInsertUnderRiver(t *testing.T) {
	f := triggerstest.New(t)
	reg := jobs.NewRegistry()
	if _, err := pgengine.Register(reg, &pgengine.Engine{}); err != nil {
		t.Fatal(err)
	}
	client, err := jobs.NewClient(f.Pool, reg, jobs.Config{Logger: pclog.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	exec, err := ids.FromUUID[pgengine.ExecutionKind](ids.NewV7())
	if err != nil {
		t.Fatal(err)
	}
	sweep := pgengine.ExecutionArgs{Org: f.Org, Execution: exec}
	first, err := client.Insert(ctx, sweep, nil)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	second, err := client.Insert(ctx, sweep, nil)
	if err != nil || first.UniqueSkippedAsDuplicate || !second.UniqueSkippedAsDuplicate {
		t.Fatalf("second sweep wake: %+v, %v", second, err)
	}
	event := sweep
	event.Wake = ids.New[pgengine.WakeKind]()
	if res, err := client.Insert(ctx, event, nil); err != nil || res.UniqueSkippedAsDuplicate {
		t.Fatalf("event wake: %+v, %v", res, err)
	}
	if _, err := client.InsertMany(ctx, []river.InsertManyParams{{Args: pgengine.SweepOrgArgs{Org: f.Org}}}); err != nil {
		t.Fatalf("org sweep: %v", err)
	}
}
