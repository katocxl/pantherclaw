// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// automationWorld adds an automation whose ceiling covers refunds for the
// world's other agent, and one grant it issued under that ceiling.
func automationWorld() (*world, ids.UUID, ids.UUID) {
	w := newWorld()
	auto, issued := ids.NewV7(), ids.NewV7()
	refunds := gdomain.Ops{"payments.refund.*"}
	w.in.Ceilings = []domain.Ceiling{{
		ID: ids.NewV7(), Automation: auto, Agents: []ids.UUID{w.other}, Bounds: gdomain.Bounds{Operations: &refunds},
		ReviewBy: now.Add(30 * 24 * time.Hour), Active: true,
	}}
	w.in.Grants = append(w.in.Grants, domain.Grant{
		ID: issued, Agent: w.other, Bounds: gdomain.Bounds{Operations: &refunds}, Automation: &auto,
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	return w, auto, issued
}

// The ceiling view and the execution reach stay apart: ceiling rights are
// CONDITIONAL potential reach of the automation, never an agent's current
// reach; issued grants' rights carry the automation in the effective view.
func TestAutomationCeilingAndExecutionReachStaySeparate(t *testing.T) {
	w, auto, issued := automationWorld()
	res := domain.Compute(w.in)
	var ceiling, execution []domain.Right
	for _, r := range res.Rights {
		switch {
		case r.View == domain.IssuanceCeiling:
			ceiling = append(ceiling, r)
		case r.View == domain.Effective && r.Automation != nil:
			execution = append(execution, r)
		}
	}
	if len(ceiling) == 0 || len(execution) == 0 {
		t.Fatalf("ceiling %d, execution %d rights; want both", len(ceiling), len(execution))
	}
	for _, r := range ceiling {
		if r.Label != domain.Conditional || *r.Automation != auto || r.Grant != nil || *r.Agent != w.other {
			t.Errorf("ceiling right %+v", r)
		}
		if r.Operation != "" && r.Operation != "payments.refund.create" {
			t.Errorf("ceiling reaches %s outside its bounds", r.Operation)
		}
	}
	for _, r := range execution {
		if *r.Grant != issued || *r.Automation != auto {
			t.Errorf("execution right %+v", r)
		}
	}
	// The agent ranking never counts the ceiling.
	for _, x := range domain.Rank(res.Rights, nil, nil) {
		if x.Agent != nil && *x.Agent == w.other && x.Keys.Revocable == 0 {
			t.Errorf("the other agent's rank shows no grant reach: %+v", x.Keys)
		}
	}
	onlyCeiling := slices.DeleteFunc(slices.Clone(res.Rights), func(r domain.Right) bool { return r.View != domain.IssuanceCeiling })
	if got := domain.Rank(onlyCeiling, nil, nil); len(got) != 0 {
		t.Errorf("ceiling rights ranked as agents: %+v", got)
	}
}

// An inactive or past-review ceiling can issue nothing: it has no rights
// (D37a).
func TestAutomationCeilingInactiveHasNoReach(t *testing.T) {
	for name, mut := range map[string]func(*domain.Ceiling){
		"inactive":    func(c *domain.Ceiling) { c.Active = false },
		"past review": func(c *domain.Ceiling) { c.ReviewBy = now.Add(-time.Minute) },
	} {
		w, _, _ := automationWorld()
		mut(&w.in.Ceilings[0])
		for _, r := range domain.Compute(w.in).Rights {
			if r.View == domain.IssuanceCeiling {
				t.Errorf("%s: ceiling right %+v", name, r)
			}
		}
	}
}

// Ranking goes by the ceiling, never by activity: an idle automation with
// a wider ceiling ranks above a busy one with a narrow ceiling (F754).
func TestAutomationRankingByCeilingNotActivity(t *testing.T) {
	w, busy, _ := automationWorld()
	idle := ids.NewV7()
	all := gdomain.Ops{"payments.*"}
	w.in.Ceilings = append(w.in.Ceilings, domain.Ceiling{
		ID: ids.NewV7(), Automation: idle, Agents: []ids.UUID{w.agent, w.other}, Bounds: gdomain.Bounds{Operations: &all},
		ReviewBy: now.Add(time.Hour), Active: true,
	})
	ranked := domain.RankAutomations(domain.Compute(w.in).Rights, nil)
	if len(ranked) != 2 || ranked[0].Automation != idle || ranked[1].Automation != busy {
		t.Fatalf("ranking %+v; want the idle wide ceiling first", ranked)
	}
	if ranked[0].Keys.ActiveGrants != 0 || ranked[1].Keys.ActiveGrants != 1 || ranked[0].Keys.Agents != 2 {
		t.Errorf("keys %+v / %+v", ranked[0].Keys, ranked[1].Keys)
	}
}

// Readers of current authority keep their views: the ceiling appears only
// when asked for by name, and never in an agent ranking, a matrix of the
// default views or a reduction preview (D37a).
func TestHR289_ReadersNeverCountTheCeilingUnlessAsked(t *testing.T) {
	w, _, _ := automationWorld()
	with := domain.Compute(w.in).Rights
	w.in.Ceilings = nil
	without := domain.Compute(w.in).Rights
	if len(with) == len(without) {
		t.Fatal("the world has no ceiling rights")
	}
	if got, want := len(domain.Select(with, domain.Filter{})), len(without); got != want {
		t.Errorf("default select: %d rights, want %d", got, want)
	}
	if got := domain.Select(with, domain.Filter{View: domain.IssuanceCeiling}); len(got) != len(with)-len(without) {
		t.Errorf("asked-for ceiling: %d rights, want %d", len(got), len(with)-len(without))
	}
	if got, want := domain.Rank(with, nil, nil), domain.Rank(without, nil, nil); !slices.EqualFunc(got, want, func(a, b domain.Ranked) bool {
		return (a.Agent == nil) == (b.Agent == nil) && (a.Agent == nil || *a.Agent == *b.Agent) && a.Keys == b.Keys
	}) {
		t.Errorf("agent ranking changed with a ceiling:\n%+v\n%+v", got, want)
	}
	if got, want := len(domain.BuildMatrix(domain.Select(with, domain.Filter{})).Cells), len(domain.BuildMatrix(without).Cells); got != want {
		t.Errorf("matrix: %d cells, want %d", got, want)
	}
	w2, _, _ := automationWorld()
	d := domain.Preview(w2.in, domain.Change{Restrictions: []domain.Restriction{{Agent: &w2.other}}})
	for _, r := range slices.Concat(d.BeforeRights, d.AfterRights, d.Removed) {
		if r.View.Potential() {
			t.Fatalf("reduction preview carries a ceiling right %+v", r)
		}
	}
}
