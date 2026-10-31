// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package protect_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR586_LeavingEnforceIsAlwaysProtected: the catalogue mode surface
// always waits for a second person, needs catalog.manage, and fails closed
// without a Gate (T-253).
//
// Covers: F874
func TestHR586_LeavingEnforceIsAlwaysProtected(t *testing.T) {
	s := protect.SurfaceCatalogMode
	if s != "mcp.catalog.mode" || !s.AlwaysProtected() || s.Permission() != td.PermCatalogManage {
		t.Fatalf("%s: always %v, permission %s", s, s.AlwaysProtected(), s.Permission())
	}
	applied := false
	var g *protect.Gate
	held, err := g.Hold(context.Background(), db.TenantTx{}, tenancy.Caller{}, protect.Change{
		Category: protect.ToolMeaning, Surface: s, Subject: "mode", Widening: []string{"catalog_mode"},
	}, func(context.Context) error { applied = true; return nil })
	if !errors.Is(err, protect.ErrUnavailable) || held != nil || applied {
		t.Fatalf("without a Gate: %v %v applied %v", held, err, applied)
	}
}

// TestHR453_CustomerRuleChangesAreAlwaysProtected: the customer
// consequence rule surface is the one surface that always waits for a
// second person (G0 M17 D107), needs consequence_rule.manage, and is never
// applied without a Gate, where every other surface applies as before
// protected changes existed; outside a confirmed re-run there is no
// publisher.
//
// Covers: F405
func TestHR453_CustomerRuleChangesAreAlwaysProtected(t *testing.T) {
	for _, s := range []protect.Surface{
		protect.SurfacePackageActivate, protect.SurfaceWindowCreate, protect.SurfaceWindowRetire, protect.SurfaceCredentialPut,
		protect.SurfaceConnectionUpdate, protect.SurfaceRouteMode, protect.SurfaceExclusionCreate, protect.SurfaceSettings,
	} {
		if s.AlwaysProtected() {
			t.Errorf("%s is always protected", s)
		}
	}
	s := protect.SurfaceConsequenceRule
	if !s.AlwaysProtected() || s.Permission() != td.PermConsequenceRuleManage {
		t.Fatalf("%s: always %v, permission %s", s, s.AlwaysProtected(), s.Permission())
	}
	applied := false
	apply := func(context.Context) error { applied = true; return nil }
	var g *protect.Gate
	held, err := g.Hold(context.Background(), db.TenantTx{}, tenancy.Caller{}, protect.Change{
		Category: protect.ConsequenceRules, Surface: s, Subject: "cx.rule", Widening: []string{"consequence_rule"},
	}, apply)
	if !errors.Is(err, protect.ErrUnavailable) || held != nil || applied {
		t.Fatalf("without a Gate: %v %v applied %v", held, err, applied)
	}
	if _, err := g.Hold(context.Background(), db.TenantTx{}, tenancy.Caller{}, protect.Change{Surface: protect.SurfaceWindowRetire}, apply); err != nil || !applied {
		t.Fatalf("another surface without a Gate: %v applied %v", err, applied)
	}
	if _, ok := protect.Publisher(context.Background()); ok {
		t.Fatal("a publisher outside a re-run")
	}
}
