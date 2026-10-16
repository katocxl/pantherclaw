// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func admin(o *exposuretest.Org) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()}}},
	}})
}

// HR-289: an automation's current execution reach (effective rights of the
// grants it issued, tagged with it) and its issuance ceiling (a separate
// view, CONDITIONAL, only for an ACTIVE ceiling) are stored apart; every
// default read leaves the ceiling out; the ceiling view needs Business; an
// automation ranks by its ceiling, never by activity.
func TestHR289_AutomationExecutionReachAndCeilingStaySeparate(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.charge.*")
	busy := o.Automation(t, "refunds", []ids.UUID{o.Other}, "payments.refund.*")
	issued := o.IssuedGrant(t, busy, o.Other, "payments.refund.create")
	idle := o.Automation(t, "wide", []ids.UUID{o.Agent, o.Other})
	gone := o.Automation(t, "gone", []ids.UUID{o.Agent})
	o.EndCeiling(t, gone.Ceiling, "VOID")
	rec := recompute(t, o)

	byView := map[domain.View]int{}
	for _, r := range rec.Rights {
		byView[r.View]++
		switch {
		case r.View == domain.IssuanceCeiling && (r.Automation == nil || r.Grant != nil || r.Label != domain.Conditional):
			t.Errorf("ceiling right %+v", r)
		case r.View == domain.IssuanceCeiling && *r.Automation == gone.ID:
			t.Errorf("a VOID ceiling has reach: %+v", r)
		case r.View == domain.Effective && r.Grant != nil && *r.Grant == issued && (r.Automation == nil || *r.Automation != busy.ID):
			t.Errorf("an automation-issued grant's right does not name its automation: %+v", r)
		}
	}
	if byView[domain.IssuanceCeiling] == 0 {
		t.Fatal("no ceiling rights were stored")
	}

	all := viewer{org: true, agents: map[ids.UUID]bool{o.Agent: true, o.Other: true}}
	for _, r := range current(t, o, all, domain.Filter{}).Rights {
		if r.View.Potential() {
			t.Fatalf("a default read returned a ceiling right: %+v", r)
		}
	}
	ceiling := current(t, o, all, domain.Filter{View: domain.IssuanceCeiling}).Rights
	if len(ceiling) != byView[domain.IssuanceCeiling] {
		t.Fatalf("ceiling view: %d of %d rights", len(ceiling), byView[domain.IssuanceCeiling])
	}

	svc := &app.Service{Pool: o.P, Ents: edition(billing.Team)}
	ctx := admin(o)
	if _, err := svc.Exposure(ctx, domain.Filter{View: domain.IssuanceCeiling}); !errors.Is(err, app.ErrCeilingEdition) {
		t.Fatalf("ceiling view on Team: %v", err)
	}
	v, err := svc.Exposure(ctx, domain.Filter{Automation: &busy.ID})
	if err != nil || len(v.Rights) == 0 {
		t.Fatalf("execution reach on Team: %d rights, %v", len(v.Rights), err)
	}
	for _, r := range v.Rights {
		if r.View != domain.Effective || *r.Grant != issued {
			t.Errorf("execution reach right %+v", r)
		}
	}
	_, agents, autos, err := svc.RankWithAutomations(ctx, 0, true)
	if err != nil || autos.ByCeiling || autos.Note != app.NoteCeilingEdition {
		t.Fatalf("Team ranking: %+v %v", autos, err)
	}
	for _, a := range agents {
		if a.Agent != nil && *a.Agent == o.Other && a.Keys.Revocable == 0 {
			t.Errorf("the other agent ranks without its issued grant: %+v", a.Keys)
		}
	}

	svc.Ents = edition(billing.Business)
	_, _, autos, err = svc.RankWithAutomations(ctx, 0, true)
	if err != nil || !autos.ByCeiling || len(autos.Automations) != 2 {
		t.Fatalf("Business ranking: %+v %v", autos, err)
	}
	// The idle automation's ceiling is wider: it ranks first although it
	// issued nothing (F754).
	if autos.Automations[0].Automation != idle.ID || autos.Automations[0].Keys.ActiveGrants != 0 ||
		autos.Automations[1].Automation != busy.ID || autos.Automations[1].Keys.ActiveGrants != 1 {
		t.Fatalf("ranking %+v", autos.Automations)
	}
	g, err := svc.Graph(ctx, domain.ModeAuthority, app.GraphScope{Type: "automation", ID: busy.ID.String()}, domain.GraphFilter{},
		false, false, domain.DefaultLimits)
	if err != nil || g.Graph.Current[domain.EdgeIssued] == 0 || g.Graph.Current[domain.EdgeCeiling] != 0 {
		t.Fatalf("automation graph without the ceiling: %+v %v", g.Graph.Current, err)
	}
	g, err = svc.Graph(ctx, domain.ModeAuthority, app.GraphScope{Type: "automation", ID: busy.ID.String(), IncludeCeiling: true},
		domain.GraphFilter{}, false, false, domain.DefaultLimits)
	if err != nil || g.Graph.Current[domain.EdgeCeiling] == 0 {
		t.Fatalf("automation graph with the ceiling: %+v %v", g.Graph.Current, err)
	}
}
