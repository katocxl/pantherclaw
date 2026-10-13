// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/github/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type env struct {
	pool *db.Pool
	org  ids.OrgID
	svc  *app.Service
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{pool: dbtest.New(t).AppPool(t), org: ids.New[ids.Org]()}
	e.svc = &app.Service{Pool: e.pool}
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'github')", e.org)
	return e
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) person(t *testing.T, subject string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, id, subject)
	return id
}

func (e *env) caller(kind td.PrincipalKind, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: kind, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
}

// TestHR207_GitHubIdentitiesAreLinkedByAPersonAndAudited: a person holding
// github.identity.manage (Org Admin) links a person of the org to a GitHub
// user id and unlinks it, each audited; a GitHub user id links to one
// person, only a person of the org is linked, a service account even with
// the role and a person without the permission link nothing, and anyone who reads
// users lists the links.
func TestHR207_GitHubIdentitiesAreLinkedByAPersonAndAudited(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.person(t, "alice"), e.person(t, "bob")
	admin := e.caller(td.KindUser, td.RoleOrgAdmin)
	link, err := e.svc.Link(admin, alice, "alice-gh", 101)
	if err != nil || link.UserID != alice || link.GithubUserID != 101 || link.GithubLogin != "alice-gh" {
		t.Fatalf("link %+v %v", link, err)
	}
	for name, c := range map[string]struct {
		ctx  context.Context
		user ids.UUID
		gh   int64
		want error
	}{
		"one GitHub user linked twice":     {admin, bob, 101, app.ErrLinked},
		"someone who is no person":         {admin, ids.NewV7(), 102, app.ErrNoPerson},
		"a service account with the role":  {e.caller(td.KindServiceAccount, td.RoleOrgAdmin), bob, 103, app.ErrHumanOnly},
		"an Auditor, who does not hold it": {e.caller(td.KindUser, td.RoleAuditor), bob, 104, nil},
		"a Security Admin, who does not":   {e.caller(td.KindUser, td.RoleSecurityAdmin), bob, 105, nil},
	} {
		_, err := e.svc.Link(c.ctx, c.user, "someone", c.gh)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.Link(admin, bob, "bob-gh", 202); err != nil {
		t.Fatal(err)
	}
	reader := e.caller(td.KindUser, td.RoleAuditor)
	all, _, err := e.svc.List(reader, nil, 0, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("listed %+v %v", all, err)
	}
	mine, _, err := e.svc.List(reader, &alice, 0, "")
	if err != nil || len(mine) != 1 || mine[0].GithubUserID != 101 {
		t.Fatalf("alice's: %+v %v", mine, err)
	}
	if err := e.svc.Unlink(admin, link.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Unlink(admin, link.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("unlinked twice: %v", err)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind IN ('audit.github.identity_linked', 'audit.github.identity_unlinked')`); n != 3 {
		t.Fatalf("%d audited link changes, want 3", n)
	}
}
