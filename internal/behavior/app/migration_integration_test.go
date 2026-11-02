// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/migrations"
)

// down is the Down section of one embedded migration.
func down(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatalf("%s has no Down section", name)
	}
	return after
}

// TestHR642_TheBehaviourMigrationsGoDownOverKeptAlerts: with a behaviour
// alert and its evidence in place (00120's foreign keys refer to it), 00303
// and then 00300 go down without error and keep the alert: it is part of the
// record (D526 P7). Covers: F930
func TestHR642_TheBehaviourMigrationsGoDownOverKeptAlerts(t *testing.T) {
	f := newFx(t)
	f.history()
	f.rollup()
	f.txn(f.run, false, "secrets.dump", "ALLOW", time.Now())
	if res := f.rollup(); res.Signals == 0 {
		t.Fatalf("no behaviour alert: %+v", res)
	}
	const kept = `SELECT count(*) FROM pc.alerts a WHERE a.org_id = $1 AND a.source = 'behavior'
		AND EXISTS (SELECT FROM pc.alert_evidence e WHERE e.org_id = a.org_id AND e.alert_id = a.id)`
	before := f.count(kept, f.org)
	if before == 0 {
		t.Fatal("no behaviour alert with evidence")
	}
	for _, name := range []string{"00303_behavior_transactions_index.sql", "00300_behavior_profiles.sql"} {
		f.d.AdminExec(t, down(t, name))
	}
	if after := f.count(kept, f.org); after != before {
		t.Fatalf("behaviour alerts after going down: %d, before %d", after, before)
	}
}
