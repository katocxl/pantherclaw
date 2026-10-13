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

// TestHR207_AWindowsEnvironmentMatchesWhateverItsCase: GitHub's
// environment names are case-insensitive, so a window created for
// Production is stored for production, replaced by a window for
// PRODUCTION, listed and decided for a release to production in any case.
func TestHR207_AWindowsEnvironmentMatchesWhateverItsCase(t *testing.T) {
	e := newEnv(t)
	admin := e.caller(td.KindUser, td.RoleSecurityAdmin)
	now := time.Now()
	w := domain.Window{Environment: "Production", TimeZone: "UTC", OneOff: []domain.Span{{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}}
	first, err := e.svc.Create(admin, w)
	if err != nil || first.Environment != "production" {
		t.Fatalf("create %+v %v", first, err)
	}
	w.Environment = "PRODUCTION"
	if second, err := e.svc.Create(admin, w); err != nil || second.Revision != 2 || second.Environment != "production" {
		t.Fatalf("a replacement in another case %+v %v", second, err)
	}
	if all, err := e.svc.List(admin, "Production", true); err != nil || len(all) != 2 {
		t.Fatalf("list %+v %v", all, err)
	}
	for _, env := range []string{"production", "Production"} {
		if d, err := e.svc.Active(admin, env, ""); err != nil || d.State != domain.Open || len(d.Windows) != 1 {
			t.Errorf("%s: %+v %v", env, d, err)
		}
	}
}

// TestHR207_ConcurrentWindowsForOneEnvironmentConflict: two windows
// created at once for the same environment cannot both be ACTIVE or take
// the same revision. The Create that commits second fails with
// CHANGE_WINDOW_CHANGED, never an internal error, whether the environment
// had a window to replace or not, and leaves one ACTIVE window.
func TestHR207_ConcurrentWindowsForOneEnvironmentConflict(t *testing.T) {
	e := newEnv(t)
	admin := e.caller(td.KindUser, td.RoleSecurityAdmin)
	w := domain.Window{Environment: "production", TimeZone: "UTC", Weekly: []domain.Weekly{{Day: "mon", Start: "09:00", Minutes: 60}}}
	// competing creates the next window the way Create does and holds its
	// transaction open until release is closed.
	competing := func(inserted, release chan struct{}) error {
		return e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
			var revision int
			if err := tx.QueryRow(ctx, `SELECT coalesce(max(revision), 0) FROM pc.change_windows WHERE environment = 'production'`).Scan(&revision); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE pc.change_windows SET state = 'RETIRED', retired_by = 'test', retired_at = now()
				WHERE environment = 'production' AND state = 'ACTIVE'`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO pc.change_windows (org_id, id, environment, time_zone, weekly, revision, created_by)
				VALUES ($1, $2, 'production', 'UTC', '[{"day":"tue","start":"09:00","minutes":60}]', $3, 'test')`,
				e.org, ids.NewV7(), revision+1); err != nil {
				return err
			}
			close(inserted)
			<-release
			return nil
		})
	}
	for _, replacing := range []bool{false, true} {
		inserted, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		go func() { done <- competing(inserted, release) }()
		<-inserted
		created := make(chan error, 1)
		go func() {
			_, err := e.svc.Create(admin, w)
			created <- err
		}()
		e.waitingForALock(t)
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := <-created; !errors.Is(err, app.ErrChanged) || reason(err) != "aborted CHANGE_WINDOW_CHANGED" {
			t.Fatalf("replacing %v: the second Create: %v", replacing, err)
		}
		if active, err := e.svc.List(admin, "production", false); err != nil || len(active) != 1 {
			t.Fatalf("replacing %v: active windows %+v %v", replacing, active, err)
		}
	}
	if r, err := e.svc.Create(admin, w); err != nil || r.Revision != 3 {
		t.Fatalf("a Create after the race %+v %v", r, err)
	}
}

// waitingForALock waits until a session of the test's database waits for
// a lock.
func (e *env) waitingForALock(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		var n int
		if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
	}
	t.Fatal("no session waits for a lock")
}

func denied(err error) bool {
	var pe *pcerr.Error
	return errors.As(err, &pe) && pe.Code() == pcerr.PermissionDenied
}
