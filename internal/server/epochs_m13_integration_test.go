// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type epochOrgs struct {
	d                          *dbtest.DB
	active, suspended, deleted ids.OrgID
	bare                       ids.OrgID // no containment row
}

func newEpochOrgs(t *testing.T, d *dbtest.DB) epochOrgs {
	t.Helper()
	o := epochOrgs{d: d, active: ids.New[ids.Org](), suspended: ids.New[ids.Org](), deleted: ids.New[ids.Org](), bare: ids.New[ids.Org]()}
	for org, st := range map[ids.OrgID]string{o.active: "ACTIVE", o.suspended: "SUSPENDED", o.deleted: "DELETED", o.bare: "ACTIVE"} {
		d.AdminExec(t, "INSERT INTO pc.orgs (id, name, state) VALUES ($1, 'org', $2)", org, st)
	}
	for _, org := range []ids.OrgID{o.active, o.suspended, o.deleted} {
		d.AdminExec(t, "INSERT INTO pc.org_containment (org_id, epoch) VALUES ($1, 7)", org)
	}
	d.AdminExec(t, "UPDATE pc.org_containment SET kill_switch = true, engaged_at = now(), engaged_by = 'test' WHERE org_id = $1", o.suspended)
	return o
}

func (o epochOrgs) epoch(t *testing.T, org ids.OrgID) int64 {
	t.Helper()
	var e int64
	o.d.AdminQueryRow(t, "SELECT coalesce((SELECT epoch FROM pc.org_containment WHERE org_id = $1), 0)", []any{org}, &e)
	return e
}

func (o epochOrgs) audits(t *testing.T, org ids.OrgID) int {
	t.Helper()
	var n int
	o.d.AdminQueryRow(t, `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1
		AND kind = 'audit.containment.epoch_bumped_after_restore' AND actor_type = 'operator' AND actor_id LIKE 'cli:%'`, []any{org}, &n)
	return n
}

func (o epochOrgs) all() []ids.OrgID { return []ids.OrgID{o.active, o.suspended, o.deleted, o.bare} }

// TestHR373_BumpEpochsRaisesEveryOrgAndAudits: without --all or --confirm
// nothing changes; with them every org of any state, and one without a
// containment row, gets max(epoch + 1, now in ms) with one audit event in
// its own transaction, the kill switch untouched; a second run raises
// every epoch again.
func TestHR373_BumpEpochsRaisesEveryOrgAndAudits(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI)
	o := newEpochOrgs(t, d)
	if code, _, _ := runKeys(t, cfgPath, "bump-epochs", "--confirm"); code != 2 {
		t.Fatalf("without --all = %d, want usage", code)
	}
	if code, _, errs := runKeys(t, cfgPath, "bump-epochs", "--all"); code != 1 || !strings.Contains(errs, "--confirm") {
		t.Fatalf("without --confirm = %d %s", code, errs)
	}
	if o.epoch(t, o.active) != 7 || o.audits(t, o.active) != 0 {
		t.Fatal("an unconfirmed bump changed an epoch")
	}

	floor := time.Now().Add(-time.Minute).UnixMilli()
	code, out, errs := runKeys(t, cfgPath, "bump-epochs", "--all", "--confirm")
	if code != 0 {
		t.Fatalf("bump-epochs = %d %s %s", code, out, errs)
	}
	first := map[ids.OrgID]int64{}
	for _, org := range o.all() {
		e := o.epoch(t, org)
		if e < floor || e > time.Now().Add(time.Minute).UnixMilli() {
			t.Errorf("org %s: epoch %d, want about now in ms (>= %d)", org, e, floor)
		}
		if n := o.audits(t, org); n != 1 {
			t.Errorf("org %s: %d audit events, want 1", org, n)
		}
		if !strings.Contains(out, org.String()) {
			t.Errorf("org %s not reported: %s", org, out)
		}
		first[org] = e
	}
	var kill bool
	d.AdminQueryRow(t, "SELECT kill_switch FROM pc.org_containment WHERE org_id = $1", []any{o.suspended}, &kill)
	if !kill {
		t.Error("the bump lifted a kill switch")
	}

	// A far-future epoch still rises by one.
	d.AdminExec(t, "UPDATE pc.org_containment SET epoch = $2 WHERE org_id = $1", o.active, int64(1)<<60)
	if code, out, errs := runKeys(t, cfgPath, "bump-epochs", "--all", "--confirm"); code != 0 {
		t.Fatalf("second bump-epochs = %d %s %s", code, out, errs)
	}
	if e := o.epoch(t, o.active); e != int64(1)<<60+1 {
		t.Errorf("a high epoch became %d, want +1", e)
	}
	for _, org := range []ids.OrgID{o.suspended, o.deleted, o.bare} {
		if e := o.epoch(t, org); e <= first[org] {
			t.Errorf("org %s: second run left epoch at %d (was %d)", org, e, first[org])
		}
		if n := o.audits(t, org); n != 2 {
			t.Errorf("org %s: %d audit events after two runs, want 2", org, n)
		}
	}
}

// TestT171_RestoredDatabaseNeverReusesACachedEpoch: a restored database
// carries the epochs of its backup, below what gateways saw after it was
// taken; after the bump every org's epoch is above any of those values, so
// a permit or a containment view from before the restore never matches
// (gateways refuse a permit whose epoch is below theirs, BeginDispatch
// requires the current one).
func TestT171_RestoredDatabaseNeverReusesACachedEpoch(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI)
	o := newEpochOrgs(t, d)
	// After the backup (epoch 7) the live system moved on: kill switch
	// engagements, terminations, ... Gateways cached up to epoch 7+500.
	cached := int64(7 + 500)
	// The restore brings the backup's epoch 7 back.
	if o.epoch(t, o.active) != 7 {
		t.Fatal("setup")
	}
	if code, out, errs := runKeys(t, cfgPath, "bump-epochs", "--all", "--confirm"); code != 0 {
		t.Fatalf("bump-epochs = %d %s %s", code, out, errs)
	}
	for _, org := range o.all() {
		if e := o.epoch(t, org); e <= cached {
			t.Errorf("org %s: epoch %d after the bump, not above the cached %d", org, e, cached)
		}
	}
}
