// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package retention

import (
	"context"
	"testing"

	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR054_RetentionDispatcherEnqueuesEveryDueOrgOnePageAtATime (D45):
// with a page smaller than the number of due orgs, the dispatcher enqueues
// one run per due org, each InsertMany bounded by the page size, instead
// of stopping at the first page.
func TestHR054_RetentionDispatcherEnqueuesEveryDueOrgOnePageAtATime(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	for range 5 {
		d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", ids.New[ids.Org]())
	}
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name, state) VALUES ($1, 'gone', 'SUSPENDED')", ids.New[ids.Org]())
	want, err := p.CrossOrgList(t.Context(), ListDue, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(want) < 5 {
		t.Fatalf("%d due orgs, want 5 or more", len(want))
	}
	var batches [][]ids.OrgID
	w := &dispatcher{pool: p, pageSize: 2, insert: func(_ context.Context, params []river.InsertManyParams) error {
		var b []ids.OrgID
		for _, prm := range params {
			b = append(b, prm.Args.(OrgArgs).Org)
		}
		batches = append(batches, b)
		return nil
	}}
	if err := w.Work(t.Context(), &river.Job[DispatchArgs]{}); err != nil {
		t.Fatal(err)
	}
	var got []ids.OrgID
	for _, b := range batches {
		if len(b) == 0 || len(b) > 2 {
			t.Errorf("InsertMany of %d runs, want 1 to 2", len(b))
		}
		got = append(got, b...)
	}
	if len(batches) < 3 || len(got) != len(want) {
		t.Fatalf("%d batches with %d runs, want 3 or more with %d", len(batches), len(got), len(want))
	}
	for i, r := range want {
		if got[i] != r.Org {
			t.Errorf("run %d for %s, want %s", i, got[i], r.Org)
		}
	}
}
