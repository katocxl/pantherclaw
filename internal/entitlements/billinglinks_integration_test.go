// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package entitlements_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/entitlements"
)

// TestT163_SubscriptionsBindOnlyThroughServerRecordedCheckouts (D37, D45,
// D46, D52): an unknown checkout binds nothing, a ref never moves to
// another org, an org keeps at most one current subscription, and a second
// one is kept as a duplicate.
func TestT163_SubscriptionsBindOnlyThroughServerRecordedCheckouts(t *testing.T) {
	f := newFixture(t)
	l := f.svc(t, entitlements.ModeExternal).NewLinks()
	ctx := context.Background()
	a, b := f.org(t), f.org(t)
	exp := time.Now().Add(time.Hour)

	if _, err := l.BindSubscription(ctx, "paddle", "txn_unknown", "sub_x", "ctm_x"); !errors.Is(err, entitlements.ErrLinkNotFound) {
		t.Errorf("unknown checkout: %v", err)
	}
	if _, _, err := l.SubscriptionOrg(ctx, "paddle", "sub_x"); !errors.Is(err, entitlements.ErrLinkNotFound) {
		t.Errorf("unknown subscription: %v", err)
	}
	if sup, err := l.RecordCheckout(ctx, a.String(), "paddle", "txn_a1", exp); err != nil || sup != "" {
		t.Fatalf("record: %q, %v", sup, err)
	}
	if sup, err := l.RecordCheckout(ctx, a.String(), "paddle", "txn_a1", exp); err != nil || sup != "" {
		t.Errorf("recording the same pending checkout again: %q, %v", sup, err)
	}
	// A newer checkout supersedes the pending one.
	if sup, err := l.RecordCheckout(ctx, a.String(), "paddle", "txn_a2", exp); err != nil || sup != "txn_a1" {
		t.Errorf("supersede: %q, %v", sup, err)
	}
	// A ref never moves to another org.
	if _, err := l.RecordCheckout(ctx, b.String(), "paddle", "txn_a2", exp); !errors.Is(err, entitlements.ErrLinkConflict) {
		t.Errorf("another org's checkout ref: %v", err)
	}
	// The superseded checkout still binds when the org has no subscription.
	org, err := l.BindSubscription(ctx, "paddle", "txn_a1", "sub_a1", "ctm_a")
	if err != nil || org != a.String() {
		t.Fatalf("bind: %q, %v", org, err)
	}
	if again, err := l.BindSubscription(ctx, "paddle", "txn_a1", "sub_a1", "ctm_a"); err != nil || again != a.String() {
		t.Errorf("the same binding again: %q, %v", again, err)
	}
	if _, err := l.BindSubscription(ctx, "paddle", "txn_a1", "sub_other", "ctm_a"); !errors.Is(err, entitlements.ErrLinkConflict) {
		t.Errorf("a consumed checkout for another subscription: %v", err)
	}
	if ref, ok, err := l.CurrentSubscription(ctx, a.String(), "paddle"); err != nil || !ok || ref != "sub_a1" {
		t.Errorf("current = %q %v %v", ref, ok, err)
	}
	// While a subscription is current, no new checkout is recorded.
	if _, err := l.RecordCheckout(ctx, a.String(), "paddle", "txn_a3", exp); !errors.Is(err, entitlements.ErrLinkConflict) {
		t.Errorf("checkout with a current subscription: %v", err)
	}
	// A second subscription through the other recorded checkout is kept as
	// a duplicate (D52), every time it is bound.
	for range 2 {
		org, err := l.BindSubscription(ctx, "paddle", "txn_a2", "sub_a2", "ctm_a")
		if !errors.Is(err, entitlements.ErrLinkDuplicate) || !errors.Is(err, entitlements.ErrLinkConflict) || org != a.String() {
			t.Errorf("duplicate: %q, %v", org, err)
		}
	}
	if o, cur, err := l.SubscriptionOrg(ctx, "paddle", "sub_a2"); err != nil || cur || o != a.String() {
		t.Errorf("duplicate is current=%v (%q, %v)", cur, o, err)
	}
	// Ending: not current any more, and a new checkout may be recorded.
	if err := l.EndSubscription(ctx, "paddle", "sub_a1"); err != nil {
		t.Fatal(err)
	}
	if err := l.EndSubscription(ctx, "paddle", "sub_a1"); err != nil {
		t.Errorf("ending twice: %v", err)
	}
	if _, cur, err := l.SubscriptionOrg(ctx, "paddle", "sub_a1"); err != nil || cur {
		t.Errorf("ended subscription current=%v, %v", cur, err)
	}
	if _, err := l.RecordCheckout(ctx, a.String(), "paddle", "txn_a4", exp); err != nil {
		t.Errorf("checkout after the end: %v", err)
	}
	// Another org cannot take over the subscription ref.
	if _, err := l.RecordCheckout(ctx, b.String(), "paddle", "txn_b1", exp); err != nil {
		t.Fatal(err)
	}
	if _, err := l.BindSubscription(ctx, "paddle", "txn_b1", "sub_a1", "ctm_b"); !errors.Is(err, entitlements.ErrLinkConflict) {
		t.Errorf("another org binding sub_a1: %v", err)
	}
	// Every lookup went through the audited lister.
	var n int
	f.d.AdminQueryRow(t, "SELECT count(*)::int FROM pc.cross_org_list_audit WHERE purpose = 'billing_link_lookup' AND subject LIKE 'paddle:%'", nil, &n)
	if n == 0 {
		t.Error("billing lookups were not audited with their ref")
	}
	for name, err := range map[string]error{
		"bad provider": func() error { _, err := l.RecordCheckout(ctx, a.String(), "Paddle!", "x", exp); return err }(),
		"too long":     func() error { _, err := l.RecordCheckout(ctx, a.String(), "paddle", "x", time.Now().Add(8*24*time.Hour)); return err }(),
		"platform org": func() error { _, err := l.RecordCheckout(ctx, "00000000-0000-7000-8000-000000000001", "paddle", "x", exp); return err }(),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestT163_ConcurrentBindsSettleOnOneSubscription (D55): two binds of the
// org's two checkouts at once leave one current subscription and one
// duplicate, never a database error.
func TestT163_ConcurrentBindsSettleOnOneSubscription(t *testing.T) {
	f := newFixture(t)
	l := f.svc(t, entitlements.ModeExternal).NewLinks()
	ctx := context.Background()
	org := f.org(t)
	exp := time.Now().Add(time.Hour)
	for _, ref := range []string{"txn_1", "txn_2"} {
		if _, err := l.RecordCheckout(ctx, org.String(), "paddle", ref, exp); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = l.BindSubscription(ctx, "paddle", []string{"txn_1", "txn_2"}[i%2], []string{"sub_1", "sub_2"}[i%2], "ctm")
		}()
	}
	wg.Wait()
	ok, dup := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, entitlements.ErrLinkDuplicate):
			dup++
		default:
			t.Errorf("bind: %v", err)
		}
	}
	if ok != 2 || dup != 2 {
		t.Errorf("binds: %d bound, %d duplicate; want 2 and 2 (each pair twice)", ok, dup)
	}
	if n := f.count(t, org, "SELECT count(*)::int FROM pc.billing_links WHERE org_id = $1 AND state = 'CURRENT'", org); n != 1 {
		t.Errorf("current subscriptions = %d", n)
	}
}
