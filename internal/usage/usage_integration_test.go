// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package usage_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/usage"
)

func newOrg(t *testing.T, p *db.Pool) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return org
}

func as(org ids.OrgID, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: []td.Binding{
			{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}},
		}},
		Credential: tapp.CredAccessToken,
	})
}

// TestHR377_UsageIsMeteredFromRecords: the meter counts the org's own
// agents (not retired before the day, range agents excluded) and stored
// ledger bytes; it keeps the day's highest instances sample; ListUsage
// returns only the caller's org's days, newest first, to entitlements.read;
// and no procedure lets a client write usage.
func TestHR377_UsageIsMeteredFromRecords(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	now := time.Now().UTC()
	svc := usage.New(p, clock.NewFake(now))
	org, other := newOrg(t, p), newOrg(t, p)
	for i, state := range []string{"DISCOVERED", "DISCOVERED", "RETIRED"} {
		retired := "NULL"
		if state == "RETIRED" {
			retired = "now() - interval '3 days'"
		}
		d.AdminExec(t, `INSERT INTO pc.agents (org_id, id, name, state, created_by, created_at, retired_at)
			VALUES ($1, $2, 'a'||$3::text, $4, 'system', now() - interval '5 days', `+retired+`)`, org, ids.NewV7(), strconv.Itoa(i), state)
	}
	d.AdminExec(t, `INSERT INTO pc.agents (org_id, id, name, state, created_by, range_agent) VALUES ($1, $2, 'range', 'DISCOVERED', 'system', true)`,
		org, ids.NewV7())
	d.AdminExec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
		VALUES ($1, $2, 'audit.test', 'system', 'x', decode(repeat('ab', 100), 'hex'))`, org, ids.NewV7())
	// An earlier run sampled seven admitted instances today.
	d.AdminExec(t, `INSERT INTO pc.usage_daily (org_id, day, agents, instances_peak, runs, stored_bytes)
		VALUES ($1, (now() AT TIME ZONE 'UTC')::date, 0, 7, 0, 0)`, org)

	if err := svc.Meter(context.Background(), org); err != nil {
		t.Fatal(err)
	}
	if err := svc.Meter(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	days, err := svc.List(as(org, td.RoleViewer), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(days) != 2 || !days[0].Day.After(days[1].Day) {
		t.Fatalf("days = %+v, want today and yesterday, newest first", days)
	}
	today := days[0]
	if today.Day.Format(time.DateOnly) != now.Format(time.DateOnly) || today.Agents != 2 || today.InstancesPeak != 7 ||
		today.Runs != 0 || today.StoredBytes != 100 {
		t.Fatalf("today = %+v, want 2 agents, peak 7 kept, 100 stored bytes", today)
	}
	if days[1].InstancesPeak != 0 {
		t.Fatalf("yesterday = %+v", days[1])
	}
	// The other org's rows are its own.
	if od, err := svc.List(as(other, td.RoleViewer), 90); err != nil || len(od) != 2 || od[0].Agents != 0 || od[0].StoredBytes != 0 {
		t.Fatalf("other org = %+v, %v", od, err)
	}
	if _, err := svc.List(as(org, td.RoleViewer), 0); pcerr.ReasonOf(err) != "INVALID_DAYS" {
		t.Fatalf("days 0: %v", err)
	}
	if _, err := svc.List(as(org, td.RoleViewer), 91); pcerr.ReasonOf(err) != "INVALID_DAYS" {
		t.Fatalf("days 91: %v", err)
	}
	noRole := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}}, Credential: tapp.CredAccessToken,
	})
	if _, err := svc.List(noRole, 7); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("without entitlements.read: %v", err)
	}
}

// TestHR377_StoredBytesRunIncrementallyAndRecountRebaselines (D45): each
// day reads only that day's rows, the remover's bytes come off the running
// total, and the weekly recount brings in older rows the running total
// never saw, ending at the true total.
func TestHR377_StoredBytesRunIncrementallyAndRecountRebaselines(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	svc := usage.New(p, clock.NewFake(time.Now().UTC()))
	org := newOrg(t, p)
	ctx := context.Background()
	entry := func(age string, n int) {
		t.Helper()
		d.AdminExec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body, occurred_at)
			VALUES ($1, $2, 'audit.test', 'system', 'x', decode(repeat('ab', $3::int), 'hex'), now() - $4::interval)`,
			org, ids.NewV7(), strconv.Itoa(n), age)
	}
	stored := func() int64 {
		t.Helper()
		days, err := svc.List(as(org, td.RoleViewer), 1)
		if err != nil || len(days) != 1 {
			t.Fatalf("today: %+v %v", days, err)
		}
		return days[0].StoredBytes
	}
	entry("10 days", 200) // before the meters started: only a recount sees it
	entry("0 seconds", 100)
	if err := svc.Meter(ctx, org); err != nil {
		t.Fatal(err)
	}
	if got := stored(); got != 100 {
		t.Fatalf("stored = %d, want today's 100 only", got)
	}
	// The remover took 30 bytes out today.
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.usage_daily (org_id, day, bytes_removed) VALUES ($1, (now() AT TIME ZONE 'UTC')::date, 30)
			ON CONFLICT (org_id, day) DO UPDATE SET bytes_removed = pc.usage_daily.bytes_removed + 30`, org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Meter(ctx, org); err != nil {
		t.Fatal(err)
	}
	if got := stored(); got != 70 {
		t.Fatalf("stored = %d, want 100 - 30", got)
	}
	// The recount: the 200 older bytes, plus the 30 removed (from rows the
	// full sum no longer sees), re-baseline the day before yesterday.
	if err := svc.Recount(ctx, org); err != nil {
		t.Fatal(err)
	}
	if got := stored(); got != 300 {
		t.Fatalf("stored after the recount = %d, want 300", got)
	}
}
