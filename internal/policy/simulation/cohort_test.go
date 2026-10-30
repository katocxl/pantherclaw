// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/replay"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/policy/simulation"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// cohortWorld records three agents' decisions and two cohorts: inside
// holds agents 0 and 1, other agent 2.
func cohortWorld(t *testing.T) (w *world, agents []ids.UUID, inside, other ids.UUID) {
	t.Helper()
	w = newWorld(billing.Enterprise)
	w.record(6, "payments.refund.create", outcome{orig: "ALLOW", origReason: "ALLOWED", prop: "DENY", propReason: "POLICY_DENIED", rule: "r"})
	agents = []ids.UUID{ids.NewV7(), ids.NewV7(), ids.NewV7()}
	for i := range w.store.recorded {
		w.store.recorded[i].Agent = agents[i%3]
	}
	inside, other = ids.NewV7(), ids.NewV7()
	w.store.cohorts = map[ids.UUID][]ids.UUID{inside: agents[:2], other: agents[2:]}
	w.store.members = map[ids.UUID][]ids.UUID{agents[0]: {inside}, agents[1]: {inside}, agents[2]: {other}}
	w.store.readable = map[ids.UUID]bool{inside: true, other: true}
	return w, agents, inside, other
}

// TestHR478_CohortSimulationReplaysOnlyItsSnapshot: a bulk simulation of a
// cohort replays only the decisions of the agents snapshotted when it was
// asked for, under the same caps; an agent added to the cohort afterwards
// is not replayed, and the counts per cohort add up.
// Covers: F602
func TestHR478_CohortSimulationReplaysOnlyItsSnapshot(t *testing.T) {
	w, agents, inside, other := cohortWorld(t)
	s := w.simulate(t, simulation.Request{Cohort: &inside})
	if s.Cohort == nil || *s.Cohort != inside || len(s.CohortAgents) != 2 || s.CohortTruncated {
		t.Fatalf("snapshot %v of %v (truncated %v)", s.CohortAgents, s.Cohort, s.CohortTruncated)
	}
	// Agent 2 joins the cohort after the request: not in the snapshot.
	w.store.cohorts[inside] = agents
	done := w.run(t, s.ID)
	if done.Evaluated != 4 || done.Report.Counts[replay.NewlyDenied] != 4 {
		t.Fatalf("replayed %d (%v), want the snapshot's 4 decisions", done.Evaluated, done.Report.Counts)
	}
	if _, ok := done.Report.ByAgent[agents[2].String()]; ok {
		t.Error("an agent outside the snapshot was replayed")
	}
	if n := done.Report.ByCohort[inside.String()].Total(); n != 4 {
		t.Errorf("cohort %s counts %d, want 4", inside, n)
	}
	if _, ok := done.Report.ByCohort[other.String()]; ok {
		t.Error("a cohort with no replayed agent was counted")
	}
	// The caps are the org-wide ones.
	if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: version, Cohort: &inside, Days: simulation.MaxDays + 1}); code(err) != "INVALID_SIMULATION_WINDOW" {
		t.Errorf("a cohort simulation over 30 days: %v", err)
	}
	if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: version, Cohort: &inside, Max: simulation.MaxEvaluations + 1}); code(err) != "INVALID_SIMULATION_BOUNDS" {
		t.Errorf("a cohort simulation over 50 000 decisions: %v", err)
	}
	missing := ids.NewV7()
	if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: version, Cohort: &missing}); code(err) != "COHORT_NOT_FOUND" {
		t.Errorf("an unknown cohort: %v", err)
	}
	// A cohort holding more than a snapshot says so in what readers see.
	w.store.truncated = map[ids.UUID]bool{inside: true}
	if big := w.simulate(t, simulation.Request{Cohort: &inside}); !big.CohortTruncated {
		t.Error("a truncated snapshot is not shown as truncated")
	}
}

// TestHR478_OrgSimulationCountsPerCohort: an org-wide simulation counts
// its decisions per cohort too, and still one simulation runs at a time.
// Covers: F602
func TestHR478_OrgSimulationCountsPerCohort(t *testing.T) {
	w, _, inside, other := cohortWorld(t)
	s := w.simulate(t, simulation.Request{})
	if _, err := w.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: version, Cohort: &inside}); code(err) != "SIMULATION_RUNNING" {
		t.Errorf("a second, cohort simulation beside a queued one: %v", err)
	}
	done := w.run(t, s.ID)
	if a, b := done.Report.ByCohort[inside.String()].Total(), done.Report.ByCohort[other.String()].Total(); a != 4 || b != 2 {
		t.Errorf("per cohort %d and %d, want 4 and 2", a, b)
	}
}

// TestT213_SimulationHidesUnreadableCohorts: the counts of a cohort the
// reader may not read are left out of what it is shown.
// Covers: F602
func TestT213_SimulationHidesUnreadableCohorts(t *testing.T) {
	w, _, inside, other := cohortWorld(t)
	s := w.simulate(t, simulation.Request{})
	w.store.readable[other] = false
	done := w.run(t, s.ID)
	if _, ok := done.Report.ByCohort[other.String()]; ok {
		t.Error("an unreadable cohort's counts were shown")
	}
	if done.Report.ByCohort[inside.String()].Total() != 4 {
		t.Error("a readable cohort's counts were dropped")
	}
	page, err := w.svc.List(as(td.RolePolicyAuthor), pageRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range page.Items {
		if _, ok := x.Report.ByCohort[other.String()]; ok {
			t.Error("a listing showed an unreadable cohort's counts")
		}
	}
}

func pageRequest(t *testing.T) page.Request {
	t.Helper()
	p, err := page.Parse(0, "")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestHR478_CohortSimulationNeedsEnterprise: below Enterprise a bulk
// simulation is refused, and one already queued fails at its next step
// when the edition lapses (D161); an org-wide one still runs on Team.
// Covers: F602
func TestHR478_CohortSimulationNeedsEnterprise(t *testing.T) {
	team := newWorld(billing.Team)
	cohort := ids.NewV7()
	team.store.cohorts = map[ids.UUID][]ids.UUID{cohort: nil}
	if _, err := team.svc.Simulate(as(td.RolePolicyAuthor), simulation.Request{Version: version, Cohort: &cohort}); code(err) != "EDITION_REQUIRED" {
		t.Errorf("a Team bulk simulation: %v", err)
	}
	if len(team.store.sims) != 0 {
		t.Fatal("a refused bulk simulation was stored")
	}
	team.simulate(t, simulation.Request{})

	w, _, inside, _ := cohortWorld(t)
	s := w.simulate(t, simulation.Request{Cohort: &inside})
	w.runner.Editions = editions(billing.Team)
	if done := w.run(t, s.ID); done.State != simulation.Failed || done.Error != simulation.FailEdition || done.Evaluated != 0 {
		t.Errorf("a bulk simulation after the downgrade: %s %q, %d evaluated", done.State, done.Error, done.Evaluated)
	}
}
