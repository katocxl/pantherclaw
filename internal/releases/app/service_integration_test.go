// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/releases/app"
	"github.com/katocxl/pantherclaw/internal/releases/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type env struct {
	pool *db.Pool
	svc  *app.Service
	org  ids.OrgID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{pool: d.AppPool(t), org: ids.New[ids.Org]()}
	e.svc = &app.Service{Pool: e.pool}
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'releases')", e.org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) caller(kind td.PrincipalKind, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: kind, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
}

func (e *env) audited(t *testing.T, name string) int {
	t.Helper()
	var n int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", e.org, "audit."+name).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func reason(err error) string {
	var pe *pcerr.Error
	if errors.As(err, &pe) {
		return string(pe.Code()) + " " + pe.Reason()
	}
	return ""
}

// TestHR207_ChangeWindowsAreSetByPeopleAndDecidedByTheDatabaseClock: a
// person holding release.window.manage creates a window, which retires the
// environment's and repository's current one and takes the next revision;
// a repository's window has its own revisions. Whether a release may be
// approved is decided by the database clock: a one-off window open now
// opens it, a freeze in the environment's window holds the repository's
// too, and an environment with no window has none. Every change is
// audited. An invalid window, a retirement without a reason or a second
// time, an Org Admin and a service account are refused.
func TestHR207_ChangeWindowsAreSetByPeopleAndDecidedByTheDatabaseClock(t *testing.T) {
	e := newEnv(t)
	admin := e.caller(td.KindUser, td.RoleSecurityAdmin)
	weekly := domain.Window{Environment: "production", TimeZone: "Europe/London", Weekly: []domain.Weekly{{Day: "mon", Start: "09:00", Minutes: 480}}}
	first, err := e.svc.Create(admin, weekly)
	if err != nil || first.Revision != 1 || first.State != "ACTIVE" || len(first.Weekly) != 1 {
		t.Fatalf("create %+v %v", first, err)
	}
	now := time.Now()
	open := weekly
	open.OneOff = []domain.Span{{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}
	second, err := e.svc.Create(admin, open)
	if err != nil || second.Revision != 2 {
		t.Fatalf("replace %+v %v", second, err)
	}
	all, err := e.svc.List(admin, "production", true)
	if err != nil || len(all) != 2 || all[0].ID != second.ID || all[1].State != "RETIRED" || all[1].RetiredBy == "" {
		t.Fatalf("list %+v %v", all, err)
	}
	if active, _ := e.svc.List(admin, "", false); len(active) != 1 {
		t.Fatalf("active windows %+v", active)
	}
	repo, err := e.svc.Create(admin, domain.Window{
		Environment: "production", Repository: "acme/payments", TimeZone: "UTC",
		Weekly: []domain.Weekly{{Day: "sun", Start: "03:00", Minutes: 1}},
	})
	if err != nil || repo.Revision != 1 {
		t.Fatalf("a repository's window %+v %v", repo, err)
	}

	d, err := e.svc.Active(admin, "production", "acme/web")
	if err != nil || d.State != domain.Open || len(d.Windows) != 1 || d.At.IsZero() {
		t.Fatalf("the environment's window %+v %v", d, err)
	}
	if d, _ := e.svc.Active(admin, "production", "acme/payments"); len(d.Windows) != 2 || (d.State != domain.Closed && d.State != domain.Open) {
		t.Fatalf("the repository's window %+v", d)
	}
	frozen := open
	frozen.Freezes = []domain.Span{{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}
	if _, err := e.svc.Create(admin, frozen); err != nil {
		t.Fatal(err)
	}
	if d, _ := e.svc.Active(admin, "production", "acme/payments"); d.State != domain.Frozen {
		t.Fatalf("a freeze over the repository's window: %s", d.State)
	}
	if d, _ := e.svc.Active(admin, "canary", ""); d.State != domain.NoWindow || len(d.Windows) != 0 {
		t.Fatalf("no window: %+v", d)
	}
	if n := e.audited(t, "release.window.created"); n != 4 {
		t.Fatalf("%d creations audited", n)
	}

	if _, err := e.svc.Retire(admin, repo.ID, ""); !errors.Is(err, app.ErrReason) {
		t.Errorf("no reason: %v", err)
	}
	if r, err := e.svc.Retire(admin, repo.ID, "the repository moved"); err != nil || r.State != "RETIRED" {
		t.Fatalf("retire %+v %v", r, err)
	}
	if _, err := e.svc.Retire(admin, repo.ID, "again"); !errors.Is(err, app.ErrRetired) {
		t.Errorf("retired twice: %v", err)
	}
	if _, err := e.svc.Retire(admin, ids.NewV7(), "unknown"); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("an unknown window: %v", err)
	}
	if n := e.audited(t, "release.window.retired"); n != 1 {
		t.Fatalf("%d retirements audited", n)
	}
	bad := weekly
	bad.TimeZone = "Mars/Olympus"
	if _, err := e.svc.Create(admin, bad); reason(err) != "invalid_argument CHANGE_WINDOW_INVALID" {
		t.Errorf("an unknown zone: %v", err)
	}
	for name, ctx := range map[string]context.Context{
		"an Org Admin":      e.caller(td.KindUser, td.RoleOrgAdmin),
		"a service account": e.caller(td.KindServiceAccount, td.RoleSecurityAdmin),
	} {
		if _, err := e.svc.Create(ctx, weekly); !denied(err) {
			t.Errorf("%s created a window: %v", name, err)
		}
		if _, err := e.svc.Active(ctx, "production", ""); !denied(err) {
			t.Errorf("%s read the windows: %v", name, err)
		}
	}
}

func denied(err error) bool {
	var pe *pcerr.Error
	return errors.As(err, &pe) && pe.Code() == pcerr.PermissionDenied
}
