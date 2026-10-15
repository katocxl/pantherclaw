// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package siem

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// TestHR260_FailingDeliveryRaisesAnOwnedFailureAndASignal: a failing
// destination becomes one owned failure and one siem alert per failing
// episode, whatever the number of retries; a new episode is a new one.
func TestHR260_FailingDeliveryRaisesAnOwnedFailureAndASignal(t *testing.T) {
	f := newExportFixture(t)
	h := ReflexHealth{Failures: &failures.Sink{}, Raiser: &alerts.Raiser{}}
	dest := ids.NewV7()
	since := time.Now().Add(-time.Hour)
	report := func(since time.Time) {
		t.Helper()
		if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			return h.DeliveryFailing(ctx, tx, DeliveryFailure{
				Org: f.org, Destination: dest, Name: "splunk", Code: "http_503", Failures: 10, Since: since, HeldAt: 42,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(sql string) int {
		t.Helper()
		var n int
		if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, sql).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	report(since)
	report(since)
	if n := count("SELECT count(*) FROM pc.operational_failures WHERE kind = 'siem.delivery_failing'"); n != 1 {
		t.Fatalf("failures = %d", n)
	}
	if n := count("SELECT count(*) FROM pc.alerts WHERE source = 'siem'"); n != 1 {
		t.Fatalf("alerts = %d", n)
	}
	report(since.Add(30 * time.Minute))
	if n := count("SELECT count(*) FROM pc.operational_failures WHERE kind = 'siem.delivery_failing'"); n != 2 {
		t.Fatalf("a new episode: failures = %d", n)
	}
}
