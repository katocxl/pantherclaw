// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app

import (
	"context"
	"testing"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR054_DailyScanDispatcherEnqueuesEveryOrgOnePageAtATime (D45): with
// a page smaller than the number of active orgs, the dispatcher enqueues
// one scan per active org, each InsertMany bounded by the page size.
func TestHR054_DailyScanDispatcherEnqueuesEveryOrgOnePageAtATime(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	for range 4 {
		d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", ids.New[ids.Org]())
	}
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name, state) VALUES ($1, 'gone', 'SUSPENDED')", ids.New[ids.Org]())
	want, err := p.CrossOrgList(t.Context(), db.ListActiveOrgs, 100)
	if err != nil {
		t.Fatal(err)
	}
	var batches [][]ids.OrgID
	w := &dailyScanDispatcher{pool: p, pageSize: 2, insert: func(_ context.Context, params []river.InsertManyParams) error {
		var b []ids.OrgID
		for _, prm := range params {
			b = append(b, prm.Args.(DailyScanOrgArgs).Org)
		}
		batches = append(batches, b)
		return nil
	}}
	if err := w.Work(t.Context(), &river.Job[DailyScanDispatchArgs]{}); err != nil {
		t.Fatal(err)
	}
	var got []ids.OrgID
	for _, b := range batches {
		if len(b) == 0 || len(b) > 2 {
			t.Errorf("InsertMany of %d scans, want 1 to 2", len(b))
		}
		got = append(got, b...)
	}
	if len(batches) < 3 || len(got) != len(want) {
		t.Fatalf("%d batches with %d scans, want 3 or more with %d", len(batches), len(got), len(want))
	}
	for i, r := range want {
		if got[i] != r.Org {
			t.Errorf("scan %d for %s, want %s", i, got[i], r.Org)
		}
	}
}
