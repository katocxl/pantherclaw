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
		case r.View == domain.Effective && len(r.Automations) > 0:
			execution = append(execution, r)
		}
	}
	if len(ceiling) == 0 || len(execution) == 0 {
		t.Fatalf("ceiling %d, execution %d rights; want both", len(ceiling), len(execution))
	}
	for _, r := range ceiling {
		if r.Label != domain.Conditional || !slices.Equal(r.Automations, []ids.UUID{auto}) || r.Grant != nil || *r.Agent != w.other {
			t.Errorf("ceiling right %+v", r)
		}
		if r.Operation != "" && r.Operation != "payments.refund.create" {
			t.Errorf("ceiling reaches %s outside its bounds", r.Operation)
		}
	}
	for _, r := range execution {
		if *r.Grant != issued || !r.HasAutomation(auto) {
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
	issued := []domain.IssuedGrant{{Automation: busy, Grant: w.in.Grants[1].ID, Agent: w.other, ExpiresAt: now.Add(time.Hour)}}
	ranked := domain.RankAutomations(domain.Compute(w.in).Rights, issued, now)
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

// A person's grant and an automation's grant on the same path make one
// EFFECTIVE right carrying the automation (D73 A1): M10 counts, ranks and
// previews see one right per path, as before.
func TestAutomationGrantSharesThePath(t *testing.T) {
	w, auto, _ := automationWorld()
	refunds := gdomain.Ops{"payments.refund.*"}
	w.in.Grants = append(w.in.Grants, domain.Grant{
		ID: ids.NewV7(), Agent: w.other, Bounds: gdomain.Bounds{Operations: &refunds},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	rights := domain.Compute(w.in).Rights
	seen := map[string]int{}
	for _, r := range rights {
		if r.View == domain.Effective {
			seen[r.PathKey()]++
		}
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("path %s has %d effective rights", k, n)
		}
	}
	r, ok := find(rights, domain.Effective, &w.other, "payments.refund.create", domain.VerbTransfer)
	if !ok || !r.HasAutomation(auto) {
		t.Fatalf("shared path right %+v %v", r, ok)
	}
	w.in.Ceilings = nil
	w.in.Grants = w.in.Grants[:1]
	before := len(domain.Compute(w.in).Rights)
	w.in.Grants = append(w.in.Grants, domain.Grant{
		ID: ids.NewV7(), Agent: w.other, Bounds: gdomain.Bounds{Operations: &refunds},
		NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
	})
	person := len(domain.Compute(w.in).Rights)
	w.in.Grants[1].Automation = &auto
	if got := len(domain.Compute(w.in).Rights); got != person || person <= before {
		t.Errorf("an automation grant changed the right count: %d (person %d, none %d)", got, person, before)
	}
}

// Containment previews reach the ceiling view (D73 A4): a ceiling agent
// held for writes keeps CONDITIONAL reach with the contained reason, a
// denied one has none.
func TestAutomationCeilingThroughContainment(t *testing.T) {
	w, _, _ := automationWorld()
	w.in.Grants = w.in.Grants[:1]
	w.in.Restrictions = []domain.Restriction{{Agent: &w.other, Hold: true}}
	n := 0
	for _, r := range domain.Compute(w.in).Rights {
		if r.View == domain.IssuanceCeiling && r.Verb != domain.VerbRead {
			n++
			if !slices.Contains(r.Reasons, domain.ReasonContainedHold) {
				t.Errorf("held ceiling right without the reason: %+v", r)
			}
		}
	}
	if n == 0 {
		t.Fatal("no ceiling write rights")
	}
	w.in.Restrictions = []domain.Restriction{{Agent: &w.other}}
	for _, r := range domain.Compute(w.in).Rights {
		if r.View == domain.IssuanceCeiling {
			t.Fatalf("a denied ceiling agent keeps ceiling reach: %+v", r)
		}
	}
}
