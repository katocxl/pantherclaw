// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package entitlements_test

import (
	"context"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeClock is a settable clock.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

type fixture struct {
	d     *dbtest.DB
	pool  *db.Pool
	clock *fakeClock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d := dbtest.New(t)
	return &fixture{d: d, pool: d.AppPool(t), clock: &fakeClock{now: time.Now()}}
}

// licence is a Team licence (the self-hosted source).
var licence = entitlements.LicenceFunc(func(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Team, Status: billing.StatusValid, Limits: billing.Limits{
		MaxAgents: 50, MaxOrgs: 3, MaxEnvironments: billing.Unlimited, MaxMembers: billing.Unlimited,
	}}, nil
})

func (f *fixture) svc(t *testing.T, mode entitlements.Mode) *entitlements.Service {
	t.Helper()
	s, err := entitlements.New(f.pool, licence, mode, f.clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// org creates an active org.
func (f *fixture) org(t *testing.T) ids.OrgID {
	t.Helper()
	org := ids.New[ids.Org]()
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", org)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return org
}

// admin returns ctx for an Org Admin of org.
func admin(org ids.OrgID) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: []td.Binding{
			{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}},
		}},
		Credential: tapp.CredAccessToken,
	})
}

func (f *fixture) count(t *testing.T, org ids.OrgID, sql string, args ...any) int {
	t.Helper()
	var n int
	err := f.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) audits(t *testing.T, org ids.OrgID, name string) int {
	t.Helper()
	return f.count(t, org, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", org, "audit."+name)
}

func wantReason(t *testing.T, what string, err error, reason string) {
	t.Helper()
	if pcerr.ReasonOf(err) != reason {
		t.Errorf("%s: err = %v, want %s", what, err, reason)
	}
}

func snap(id string, at time.Time, st entitlements.Status) entitlements.Snapshot {
	return entitlements.Snapshot{
		PlanID: "team", Edition: "team", Status: st, EventID: id, EventAt: at,
		Limits: entitlements.Limits{MaxAgents: 10, MaxEnvironments: 2, MaxMembers: 5}, Features: []string{"console"},
	}
}

func (f *fixture) plan(t *testing.T, s *entitlements.Service, org ids.OrgID) entitlements.Plan {
	t.Helper()
	p, err := s.Plan(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
