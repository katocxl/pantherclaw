// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"reflect"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	exdomain "github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/search"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type exitEdition billing.Edition

func (e exitEdition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// TestD95_IssuanceCeilingNeverCountsAsCurrentAuthorityInSearch: search's
// who_can_write and widest_exposure answer current authority only, so an
// automation's ACTIVE issuance ceiling (a potential, CONDITIONAL view)
// changes neither answer, on Business where the ceiling view exists (G0
// M11 part 2 D37a, D95; closes D73 A2).
func TestD95_IssuanceCeilingNeverCountsAsCurrentAuthorityInSearch(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()}}},
	}})
	svc := &exapp.Service{Pool: o.P, Ents: exitEdition(billing.Business)}
	x := searchExposure{svc: svc}
	recompute := func() {
		t.Helper()
		o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
			_, err := exapp.Recompute(ctx, tx, "manual", 0)
			return err
		})
	}
	type answers struct {
		byConnection []search.Item
		byGroup      map[string][]search.Item
		widest       []search.Item
	}
	read := func(groups []string) answers {
		t.Helper()
		a := answers{byGroup: map[string][]search.Item{}}
		v, err := x.WhoCanWrite(ctx, "", &o.Conn)
		if err != nil {
			t.Fatal(err)
		}
		a.byConnection = v.Items
		for _, g := range groups {
			if v, err = x.WhoCanWrite(ctx, g, nil); err != nil {
				t.Fatal(err)
			}
			a.byGroup[g] = v.Items
		}
		if v, err = x.Widest(ctx, 50); err != nil {
			t.Fatal(err)
		}
		a.widest = v.Items
		return a
	}

	recompute()
	o.Automation(t, "wide", []ids.UUID{o.Agent, o.Other}, "payments.*")
	before := read(nil)
	if len(before.byConnection) == 0 || len(before.widest) == 0 {
		t.Fatalf("no current authority to compare: %d rights, %d ranked", len(before.byConnection), len(before.widest))
	}
	recompute()

	// The ceiling is there to leak: write rights through both agents.
	ceiling, err := svc.Exposure(ctx, exdomain.Filter{View: exdomain.IssuanceCeiling})
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]bool{}
	for _, r := range ceiling.Rights {
		if writeVerbs[r.Verb] {
			groups[r.ResourceGroup] = true
		}
	}
	if len(groups) == 0 {
		t.Fatalf("the ceiling has no write rights to check (%d rights)", len(ceiling.Rights))
	}
	var gs []string
	for g := range groups {
		gs = append(gs, g)
	}
	after := read(gs)

	if !reflect.DeepEqual(before.byConnection, after.byConnection) || !reflect.DeepEqual(before.widest, after.widest) {
		t.Fatalf("an issuance ceiling changed search's answers:\nwho_can_write %v\n-> %v\nwidest %v\n-> %v",
			before.byConnection, after.byConnection, before.widest, after.widest)
	}
	check := func(name string, items []search.Item) {
		for _, it := range items {
			if it.Fields["view"] == string(exdomain.IssuanceCeiling) || it.Fields["agent"] == o.Other.String() {
				t.Errorf("%s returned issuance-ceiling authority: %+v", name, it)
			}
		}
	}
	check("who_can_write by connection", after.byConnection)
	for g, items := range after.byGroup {
		check("who_can_write "+g, items)
	}
	for _, it := range after.widest {
		if it.ID == o.Other.String() && (it.Fields["resource_groups"] != "0" || it.Fields["connections"] != "0") {
			t.Errorf("widest_exposure ranks a ceiling-only agent by its ceiling: %+v", it)
		}
	}
}
