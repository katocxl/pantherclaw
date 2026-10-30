// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgsimulation_test

import (
	"context"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
)

type enterprise struct{}

func (enterprise) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Enterprise, Status: billing.StatusValid}, nil
}

// TestHR478_BulkSimulationWritesOnlyItsOwnRows: a bulk simulation of a
// fleet cohort snapshots its agents when asked for, replays only their
// recorded decisions and counts them per cohort, and like any simulation
// writes nothing but its own rows; a cohort without agents replays
// nothing. It needs Enterprise (D161).
// Covers: F602
func TestHR478_BulkSimulationWritesOnlyItsOwnRows(t *testing.T) {
	w := newWorld(t)
	draft := w.decide()
	cohort, empty := ids.NewV7(), ids.NewV7()
	exec(t, w.pool, w.org, `INSERT INTO pc.fleet_cohorts (org_id, id, name, owner_user_id, created_by)
		VALUES ($1, $2, 'refunders', $4, 'test'), ($1, $3, 'nobody', $4, 'test')`, w.org, cohort, empty, w.alice)
	exec(t, w.pool, w.org, "INSERT INTO pc.fleet_cohort_members (org_id, cohort_id, agent_id, added_by) VALUES ($1, $2, $3, 'test')",
		w.org, cohort, w.agent)
	if _, err := w.svc.Simulate(w.human, simulation.Request{Version: draft, Days: 1, Cohort: &cohort}); err == nil {
		t.Fatal("a Team bulk simulation was queued")
	}
	w.svc.Editions, w.runner.Editions = enterprise{}, enterprise{}
	s, err := w.svc.Simulate(w.human, simulation.Request{Version: draft, Days: 1, Cohort: &cohort})
	if err != nil {
		t.Fatal(err)
	}
	if s.Cohort == nil || *s.Cohort != cohort || len(s.CohortAgents) != 1 || s.CohortAgents[0] != w.agent {
		t.Fatalf("snapshot %v of %v", s.CohortAgents, s.Cohort)
	}
	before := w.rowCounts()
	w.finish(s.ID)
	after := w.rowCounts()
	for tb, n := range before {
		if tb != "policy_simulation_samples" && after[tb] != n {
			t.Errorf("table %s: %d rows before the simulation ran, %d after", tb, n, after[tb])
		}
	}
	got, err := w.svc.Get(w.human, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != simulation.Done || got.Evaluated != 4 || got.Report.ByCohort[cohort.String()].Total() != 4 {
		t.Fatalf("bulk simulation: %s, %d evaluated, by cohort %v", got.State, got.Evaluated, got.Report.ByCohort)
	}
	if _, ok := got.Report.ByCohort[empty.String()]; ok {
		t.Error("a cohort without agents was counted")
	}
	none, err := w.svc.Simulate(w.human, simulation.Request{Version: draft, Days: 1, Cohort: &empty})
	if err != nil {
		t.Fatal(err)
	}
	w.finish(none.ID)
	if got, _ := w.svc.Get(w.human, none.ID); got.State != simulation.Done || got.Evaluated != 0 {
		t.Fatalf("an empty cohort's simulation: %s, %d evaluated", got.State, got.Evaluated)
	}
}
