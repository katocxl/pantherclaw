// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package entitlements_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
)

// TestHR354_PlanStateChangesOnlyThroughTheWriterTheCompCommandOrDevMode:
// the API has no procedure that changes a plan, the app role cannot delete
// a plan, and the plan writer works only in billing mode external.
func TestHR354_PlanStateChangesOnlyThroughTheWriterTheCompCommandOrDevMode(t *testing.T) {
	declared, err := protoperms.Declared(filepath.Join("..", "..", "proto"))
	if err != nil {
		t.Fatal(err)
	}
	for proc := range declared {
		if strings.Contains(proc, ".EntitlementService/") && !strings.HasSuffix(proc, "/GetEntitlements") {
			t.Errorf("EntitlementService serves %s: plans never change through the API", proc)
		}
	}
	f := newFixture(t)
	org := f.org(t)
	ctx := context.Background()
	for _, mode := range []entitlements.Mode{entitlements.ModeLicence, entitlements.ModeOff} {
		if err := f.svc(t, mode).ApplyPlan(ctx, org, snap("evt_1", time.Now(), entitlements.StatusActive)); !errors.Is(err, entitlements.ErrNotExternal) {
			t.Errorf("ApplyPlan in mode %s: %v, want BILLING_MODE", mode, err)
		}
	}
	var del bool
	f.d.AdminQueryRow(t, "SELECT has_table_privilege('pc_app', 'pc.org_entitlements', 'DELETE')", nil, &del)
	if del {
		t.Error("pc_app may delete plans")
	}
	for _, priv := range []string{"UPDATE", "DELETE"} {
		var ok bool
		f.d.AdminQueryRow(t, "SELECT has_table_privilege('pc_app', 'pc.entitlement_events', $1)", []any{priv}, &ok)
		if ok {
			t.Errorf("pc_app has %s on entitlement_events (append only)", priv)
		}
	}
}

// TestHR355_ApplyPlanIsIdempotentIgnoresOlderEventsAndAuditsEveryChange.
func TestHR355_ApplyPlanIsIdempotentIgnoresOlderEventsAndAuditsEveryChange(t *testing.T) {
	f := newFixture(t)
	s := f.svc(t, entitlements.ModeExternal)
	org := f.org(t)
	ctx := context.Background()
	t1 := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	if err := s.ApplyPlan(ctx, org, snap("evt_a", t1, entitlements.StatusActive)); err != nil {
		t.Fatal(err)
	}
	p := f.plan(t, s, org)
	if p.Status != entitlements.StatusActive || p.Source != entitlements.SourceBilling || p.Version != 1 || p.Limits.MaxEnvironments != 2 {
		t.Fatalf("plan = %+v", p)
	}
	// Replayed: nothing changes, nothing more is recorded.
	if err := s.ApplyPlan(ctx, org, snap("evt_a", t1, entitlements.StatusLapsed)); err != nil {
		t.Fatal(err)
	}
	if p := f.plan(t, s, org); p.Status != entitlements.StatusActive || p.Version != 1 {
		t.Errorf("replay changed the plan: %+v", p)
	}
	// Older: recorded, ignored.
	if err := s.ApplyPlan(ctx, org, snap("evt_b", t1.Add(-time.Minute), entitlements.StatusLapsed)); err != nil {
		t.Fatal(err)
	}
	if p := f.plan(t, s, org); p.Status != entitlements.StatusActive {
		t.Errorf("an older event changed the plan: %+v", p)
	}
	if n := f.count(t, org, "SELECT count(*)::int FROM pc.entitlement_events WHERE org_id = $1 AND kind = 'IGNORED_STALE'", org); n != 1 {
		t.Errorf("stale events recorded = %d", n)
	}
	// Equal timestamps apply (D40).
	if err := s.ApplyPlan(ctx, org, snap("evt_c", t1, entitlements.StatusPastDue)); err != nil {
		t.Fatal(err)
	}
	if p := f.plan(t, s, org); p.Status != entitlements.StatusPastDue || p.Version != 2 {
		t.Errorf("an equal-time event did not apply: %+v", p)
	}
	if n := f.audits(t, org, "billing.plan_applied"); n != 2 {
		t.Errorf("plan_applied audits = %d, want 2", n)
	}
	if n := f.audits(t, org, "billing.plan_event_ignored"); n != 1 {
		t.Errorf("plan_event_ignored audits = %d, want 1", n)
	}
	// Invalid limits never reach the row (the CHECK backs the writer).
	bad := snap("evt_d", time.Now(), entitlements.StatusActive)
	bad.Limits.MaxAgents = -1
	if err := s.ApplyPlan(ctx, org, bad); !errors.Is(err, entitlements.ErrInvalidSnapshot) {
		t.Errorf("negative limit: %v", err)
	}
	err := f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `UPDATE pc.org_entitlements SET limits = '{"max_agents": "25"}' WHERE org_id = $1`, org)
		return err
	})
	if err == nil {
		t.Error("a string limit was stored")
	}
}

// TestHR356_PlanRequiredGateKeepsOnlyTheAllowListWithoutAPlan (D43).
func TestHR356_PlanRequiredGateKeepsOnlyTheAllowListWithoutAPlan(t *testing.T) {
	f := newFixture(t)
	s := f.svc(t, entitlements.ModeExternal)
	org := f.org(t)
	ctx := context.Background()
	class := map[string]entitlements.Class{"/allow": entitlements.ClassAllow, "/read": entitlements.ClassRead,
		"/safety": entitlements.ClassSafety, "/change": entitlements.ClassChange}
	g := entitlements.NewGate(s, true, func(p string) entitlements.Class { return class[p] })
	check := func(want map[string]bool) {
		t.Helper()
		for p, ok := range want {
			err := g.Check(ctx, org, p)
			if ok != (err == nil) {
				t.Errorf("%s with %s: %v", p, f.plan(t, s, org).Status, err)
			}
			if err != nil {
				wantReason(t, p, err, "PLAN_REQUIRED")
			}
		}
		if err := g.Check(ctx, org, "/unclassified"); err == nil && f.plan(t, s, org).Status == entitlements.StatusLapsed {
			t.Error("an unclassified procedure ran on a lapsed plan (fail closed)")
		}
	}
	check(map[string]bool{"/allow": true, "/read": false, "/safety": false, "/change": false})
	at := time.Now().Add(-time.Hour)
	for i, st := range []entitlements.Status{entitlements.StatusTrialing, entitlements.StatusActive, entitlements.StatusPastDue} {
		if err := s.ApplyPlan(ctx, org, snap("evt_ok_"+string(st), at.Add(time.Duration(i)*time.Second), st)); err != nil {
			t.Fatal(err)
		}
		check(map[string]bool{"/allow": true, "/read": true, "/safety": true, "/change": true})
	}
	for i, st := range []entitlements.Status{entitlements.StatusPaused, entitlements.StatusLapsed} {
		if err := s.ApplyPlan(ctx, org, snap("evt_lapse_"+string(st), at.Add(time.Minute+time.Duration(i)*time.Second), st)); err != nil {
			t.Fatal(err)
		}
		check(map[string]bool{"/allow": true, "/read": true, "/safety": true, "/change": false})
	}
	canceled := snap("evt_cancel", at.Add(2*time.Minute), entitlements.StatusCanceled)
	canceled.PeriodEnd = time.Now().Add(24 * time.Hour)
	if err := s.ApplyPlan(ctx, org, canceled); err != nil {
		t.Fatal(err)
	}
	check(map[string]bool{"/change": true})
	f.clock.now = time.Now().Add(48 * time.Hour)
	check(map[string]bool{"/read": true, "/safety": true, "/change": false})
	// Without billing.require_plan nothing is gated.
	if err := entitlements.NewGate(s, false, func(string) entitlements.Class { return entitlements.ClassChange }).Check(ctx, org, "/change"); err != nil {
		t.Errorf("gate off: %v", err)
	}
}

// TestHR357_ALapsedOrMissingPlanNeverWeakensEnforcement: in every plan
// status the org keeps its edition and limits (no feature or detection is
// switched off), and safety actions run on every status that had a plan.
func TestHR357_ALapsedOrMissingPlanNeverWeakensEnforcement(t *testing.T) {
	f := newFixture(t)
	s := f.svc(t, entitlements.ModeExternal)
	ctx := context.Background()
	at := time.Now().Add(-time.Hour)
	for i, st := range []entitlements.Status{
		entitlements.StatusTrialing, entitlements.StatusActive, entitlements.StatusPastDue, entitlements.StatusPaused,
		entitlements.StatusCanceled, entitlements.StatusLapsed,
	} {
		org := f.org(t)
		biz := snap("evt", at.Add(time.Duration(i)*time.Second), st)
		biz.Edition, biz.PlanID = "business", "business"
		if err := s.ApplyPlan(ctx, org, biz); err != nil {
			t.Fatal(err)
		}
		e, err := s.For(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		if e.Edition != billing.Business || !e.AdvancedDetections() || !e.Cases() {
			t.Errorf("%s: entitlements %+v lost the plan's features", st, e)
		}
		if e.Limits.MaxAgents != 10 {
			t.Errorf("%s: agent limit %d, want the plan's 10", st, e.Limits.MaxAgents)
		}
		if !entitlements.Allows(f.plan(t, s, org).Status, entitlements.ClassSafety) {
			t.Errorf("%s: safety actions refused", st)
		}
		// Jobs that name the org read the same entitlements.
		if je, err := s.Current(tenantctx.WithOrg(ctx, org)); err != nil || je.Edition != billing.Business {
			t.Errorf("%s: a job reads %v, %v", st, je.Edition, err)
		}
	}
	// No plan at all: the org keeps Community enforcement, never less.
	org := f.org(t)
	e, err := s.For(ctx, org)
	if err != nil || e.Edition != billing.Community {
		t.Errorf("no plan: %+v, %v", e, err)
	}
}

// TestHR358_CompPlansAreOperatorOnlyWithAReasonAtMostAYearAndAudited.
func TestHR358_CompPlansAreOperatorOnlyWithAReasonAtMostAYearAndAudited(t *testing.T) {
	f := newFixture(t)
	org := f.org(t)
	ctx := context.Background()
	for _, mode := range []entitlements.Mode{entitlements.ModeLicence, entitlements.ModeExternal} {
		s := f.svc(t, mode)
		now := time.Now()
		for name, g := range map[string]entitlements.CompGrant{
			"no reason":  {PlanID: "team", Until: now.Add(time.Hour), Operator: "cli:op"},
			"too long":   {PlanID: "team", Until: now.Add(400 * 24 * time.Hour), Reason: "pilot", Operator: "cli:op"},
			"ended":      {PlanID: "team", Until: now.Add(-time.Hour), Reason: "pilot", Operator: "cli:op"},
			"dev":        {PlanID: "dev", Edition: "development", Until: now.Add(time.Hour), Reason: "pilot", Operator: "cli:op"},
			"no edition": {PlanID: "partner", Until: now.Add(time.Hour), Reason: "pilot", Operator: "cli:op"},
		} {
			if err := s.GrantComp(ctx, org, g); !errors.Is(err, entitlements.ErrInvalidComp) {
				t.Errorf("%s/%s: %v", mode, name, err)
			}
		}
		if err := s.GrantComp(ctx, org, entitlements.CompGrant{
			PlanID: "partner", Edition: "business", Until: now.Add(30 * 24 * time.Hour), Reason: "design partner", Operator: "cli:op",
		}); err != nil {
			t.Fatal(err)
		}
		p := f.plan(t, s, org)
		if p.Status != entitlements.StatusComp || p.Source != entitlements.SourceComp || p.CompReason != "design partner" || p.CompUntil == nil {
			t.Fatalf("%s: plan = %+v", mode, p)
		}
		if e, _ := s.For(ctx, org); e.Edition != billing.Business {
			t.Errorf("%s: comp edition not in force: %v", mode, e.Edition)
		}
		f.clock.now = now.Add(31 * 24 * time.Hour)
		if p := f.plan(t, s, org); mode == entitlements.ModeExternal && p.Status != entitlements.StatusLapsed {
			t.Errorf("an ended comp plan reads %s", p.Status)
		}
		if p := f.plan(t, s, org); mode == entitlements.ModeLicence && p.Source != entitlements.SourceLicence {
			t.Errorf("self-hosted: an ended comp plan still overrides the licence: %+v", p)
		}
		f.clock.now = now
	}
	s := f.svc(t, entitlements.ModeExternal)
	if err := s.RevokeComp(ctx, org, "pilot over", "cli:op"); err != nil {
		t.Fatal(err)
	}
	if p := f.plan(t, s, org); p.Status != entitlements.StatusLapsed {
		t.Errorf("revoked comp reads %s", p.Status)
	}
	if err := s.RevokeComp(ctx, org, "again", "cli:op"); !errors.Is(err, entitlements.ErrNoComp) {
		t.Errorf("second revoke: %v", err)
	}
	if n := f.audits(t, org, "billing.comp_granted"); n != 2 {
		t.Errorf("comp_granted audits = %d", n)
	}
	if n := f.audits(t, org, "billing.comp_revoked"); n != 1 {
		t.Errorf("comp_revoked audits = %d", n)
	}
	// The table refuses a comp plan beyond a year or ending before it began.
	for _, until := range []string{"now() + interval '13 months'", "now() - interval '1 minute'"} {
		err := f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, `UPDATE pc.org_entitlements SET status = 'COMP', comp_at = now(), comp_until = `+until+` WHERE org_id = $1`, org)
			return err
		})
		if err == nil {
			t.Errorf("comp_until %s stored", until)
		}
	}
}

// TestHR361_COMPAndDEVNeverComeThroughApplyPlan.
func TestHR361_COMPAndDEVNeverComeThroughApplyPlan(t *testing.T) {
	f := newFixture(t)
	s := f.svc(t, entitlements.ModeExternal)
	org := f.org(t)
	ctx := context.Background()
	for _, st := range []entitlements.Status{entitlements.StatusComp, entitlements.StatusDev, "ENTERPRISE", ""} {
		if err := s.ApplyPlan(ctx, org, snap("evt_"+string(st), time.Now(), st)); !errors.Is(err, entitlements.ErrInvalidSnapshot) {
			t.Errorf("status %q: %v", st, err)
		}
	}
	dev := snap("evt_dev_edition", time.Now(), entitlements.StatusActive)
	dev.Edition = "development"
	if err := s.ApplyPlan(ctx, org, dev); !errors.Is(err, entitlements.ErrInvalidSnapshot) {
		t.Errorf("edition development: %v", err)
	}
	// The table pins COMP and DEV to their own writers, and refuses
	// LICENCE rows.
	for _, row := range []string{
		`('COMP', 'BILLING', now())`, `('DEV', 'BILLING', now())`, `('ACTIVE', 'DEV', now())`, `('ACTIVE', 'LICENCE', now())`,
		`('COMP', 'COMP', NULL)`,
	} {
		err := f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, `INSERT INTO pc.org_entitlements (org_id, edition, status, source, last_event_at)
				SELECT $1, 'team', v.s, v.src, v.at FROM (VALUES `+row+`) AS v(s, src, at)`, org)
			return err
		})
		if err == nil {
			t.Errorf("row %s stored", row)
		}
	}
}

// TestT162_BillingEventsForUnknownOrgsAndReplaysChangeNothing.
func TestT162_BillingEventsForUnknownOrgsAndReplaysChangeNothing(t *testing.T) {
	f := newFixture(t)
	s := f.svc(t, entitlements.ModeExternal)
	ctx := context.Background()
	for name, org := range map[string]ids.OrgID{"unknown": ids.New[ids.Org](), "platform": ids.PlatformOrg, "zero": {}} {
		if err := s.ApplyPlan(ctx, org, snap("evt_x", time.Now(), entitlements.StatusActive)); !errors.Is(err, entitlements.ErrUnknownOrg) {
			t.Errorf("%s org: %v", name, err)
		}
	}
	a, b := f.org(t), f.org(t)
	at := time.Now().Add(-time.Minute)
	if err := s.ApplyPlan(ctx, a, snap("evt_same", at, entitlements.StatusActive)); err != nil {
		t.Fatal(err)
	}
	// The same event id for another org is that org's own event.
	if err := s.ApplyPlan(ctx, b, snap("evt_same", at, entitlements.StatusLapsed)); err != nil {
		t.Fatal(err)
	}
	if pa, pb := f.plan(t, s, a), f.plan(t, s, b); pa.Status != entitlements.StatusActive || pb.Status != entitlements.StatusLapsed {
		t.Errorf("plans = %s, %s", pa.Status, pb.Status)
	}
}
