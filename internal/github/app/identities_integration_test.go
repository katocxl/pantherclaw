// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/katocxl/pantherclaw/internal/github/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
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

// as is a caller who is the person user, holding role.
func (e *env) as(user ids.UUID, kind td.PrincipalKind, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: kind, ID: user},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
}

// gitHub answers for the tokens of GitHub sign-ins it knows.
type gitHub map[string]app.GitHubUser

func (g gitHub) User(_ context.Context, token string) (app.GitHubUser, error) {
	u, ok := g[token]
	if !ok {
		return app.GitHubUser{}, app.ErrProof
	}
	return u, nil
}

// notices records the notifications the service sends.
type notices struct {
	mu  sync.Mutex
	got []napp.Message
}

func (n *notices) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, m)
	return napp.Enqueued{}, nil
}

// TestHR207_PeopleLinkTheirOwnGitHubAccountsBySigningIn (founder decision
// 2026-10-13, P2f): a person links their own GitHub account only by
// proving it, a GitHub sign-in whose account the server reads from GitHub,
// and the link records when; proving it again renews it. An account linked
// to someone else, a token GitHub refuses, a service account, a person
// without github.identity.prove and a server without GitHub sign-in link
// nothing. A person removes their own link only the same way; a person
// holding github.identity.manage unlinks other people only. Every change is
// audited and notified, and anyone who reads users lists the links.
func TestHR207_PeopleLinkTheirOwnGitHubAccountsBySigningIn(t *testing.T) {
	e := newEnv(t)
	n := &notices{}
	e.svc.Verifier = gitHub{
		"alice-token": {ID: 101, Login: "alice-gh"}, "bob-token": {ID: 202, Login: "bob-gh"}, "admin-token": {ID: 303, Login: "admin-gh"},
	}
	e.svc.Notify = n
	alice, bob, admin := e.person(t, "alice"), e.person(t, "bob"), e.person(t, "admin")
	asAlice, asBob := e.as(alice, td.KindUser, td.RoleDeveloper), e.as(bob, td.KindUser, td.RoleCodeReviewer)
	asAdmin := e.as(admin, td.KindUser, td.RoleOrgAdmin)

	link, err := e.svc.Prove(asAlice, "alice-token", false)
	if err != nil || link.UserID != alice || link.GithubUserID != 101 || link.GithubLogin != "alice-gh" || link.VerifiedAt == nil ||
		link.LinkedBy != (td.PrincipalRef{Kind: td.KindUser, ID: alice}).String() {
		t.Fatalf("alice's link %+v %v", link, err)
	}
	again, err := e.svc.Prove(asAlice, "alice-token", false)
	if err != nil || again.ID == link.ID || e.count(t, "SELECT count(*) FROM pc.github_identities WHERE user_id = $1", alice) != 1 {
		t.Fatalf("renewed %+v %v", again, err)
	}
	for name, c := range map[string]struct {
		ctx   context.Context
		token string
		want  error
	}{
		"alice's account for bob":          {asBob, "alice-token", app.ErrLinked},
		"a token GitHub refuses":           {asBob, "forged", app.ErrProof},
		"a service account with the role":  {e.as(ids.NewV7(), td.KindServiceAccount, td.RoleOrgAdmin), "bob-token", app.ErrHumanOnly},
		"an Auditor, who does not hold it": {e.as(bob, td.KindUser, td.RoleAuditor), "bob-token", nil},
		"unlinking alice's account as bob": {asBob, "alice-token", app.ErrNotYours},
	} {
		_, err := e.svc.Prove(c.ctx, c.token, name == "unlinking alice's account as bob")
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (&app.Service{Pool: e.pool}).Prove(asBob, "bob-token", false); !errors.Is(err, app.ErrNoSignIn) {
		t.Fatalf("without GitHub sign-in: %v", err)
	}
	bobs, err := e.svc.Prove(asBob, "bob-token", false)
	if err != nil {
		t.Fatal(err)
	}
	all, _, err := e.svc.List(e.as(admin, td.KindUser, td.RoleAuditor), nil, 0, "")
	if err != nil || len(all) != 2 {
		t.Fatalf("listed %+v %v", all, err)
	}

	// Unlinking: a manager removes another person's link, never their own;
	// a person removes their own by signing in again.
	adminLink, err := e.svc.Prove(asAdmin, "admin-token", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Unlink(asAdmin, adminLink.ID); !errors.Is(err, app.ErrOwnLink) {
		t.Fatalf("a manager unlinking themselves: %v", err)
	}
	if err := e.svc.Unlink(asBob, again.ID); err == nil {
		t.Fatal("a code reviewer unlinked someone")
	}
	if err := e.svc.Unlink(asAdmin, again.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Unlink(asAdmin, again.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("unlinked twice: %v", err)
	}
	if gone, err := e.svc.Prove(asBob, "bob-token", true); err != nil || gone.ID != bobs.ID {
		t.Fatalf("bob unlinking himself: %+v %v", gone, err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.github_identities"); n != 1 {
		t.Fatalf("%d links left, want the admin's", n)
	}
	// alice linked and renewed, bob linked, the admin linked, alice
	// unlinked by the admin, bob unlinked himself.
	if a := e.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind IN ('audit.github.identity_linked', 'audit.github.identity_unlinked')`); a != 6 ||
		len(n.got) != 6 {
		t.Fatalf("%d audited and %d notified link changes, want 6", a, len(n.got))
	}
	if m := n.got[len(n.got)-1]; m.Type != "security.github_identity_unlinked" || m.Params["github_login"] != "bob-gh" {
		t.Fatalf("last notice %+v", m)
	}
}
