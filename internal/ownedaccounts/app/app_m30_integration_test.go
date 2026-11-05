// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/ownedaccounts/app"
	"github.com/katocxl/pantherclaw/internal/ownedaccounts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// person is a signed-in person with a security key.
type person struct {
	id, key, session ids.UUID
	page             context.Context
}

type world struct {
	t       *testing.T
	pool    *db.Pool
	org     ids.OrgID
	changes *changes.Service
	svc     *app.Service
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, pool: dbtest.New(t).AppPool(t), org: ids.New[ids.Org]()}
	w.changes = changes.New(w.pool, "https://pc.test")
	gate := &protect.Gate{Requests: protect.Ceremony{Changes: w.changes}, Failures: &failures.Sink{}}
	protect.Register(w.changes, gate, &protect.Publishers{Pool: w.pool, Gate: gate})
	w.svc = &app.Service{Pool: w.pool}
	w.svc.RegisterProtect(gate)
	w.exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'owned-m30')", w.org)
	return w
}

func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) person(name string, role td.RoleName) person {
	w.t.Helper()
	p := person{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	w.exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", w.org, p.id, name)
	w.exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		w.org, p.key, p.id, secret[:16], secret)
	w.exec(`INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, w.org, p.session, p.id, secret)
	w.exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		w.org, ids.NewV7(), string(role), p.id)
	sub := td.Subject{
		Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
	}
	p.page = tapp.WithCaller(context.Background(), tapp.Caller{Subject: sub, Credential: tapp.CredBrowserSession, Session: p.session})
	return p
}

// confirm signs the request's binding with p's key and confirms it.
func (w *world) confirm(p person, id ids.UUID) (changes.Request, error) {
	w.t.Helper()
	r, err := w.changes.Get(p.page, id)
	if err != nil {
		return r, err
	}
	cer := ids.NewV7()
	w.exec(`INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge, change_request_id, expires_at)
		VALUES ($1, $2, $3, $4, 'BINDING', $5, $6, now() + interval '5 minutes')`, w.org, cer, p.session, p.id, r.Binding[:], r.ID)
	return w.changes.Confirm(p.page, id, changes.Assertion{Ceremony: cer, Credential: p.key})
}

// owned is the org's listed values of kind as the share step reads them.
func (w *world) owned(kind domain.Kind) []string {
	w.t.Helper()
	got, err := (&pgauthority.Reader{Pool: w.pool}).OwnedAccounts(context.Background(), w.org, string(kind))
	if err != nil {
		w.t.Fatal(err)
	}
	return got
}

func (w *world) audits(name string) int {
	w.t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", w.org, "audit."+name).Scan(&n)
	}); err != nil {
		w.t.Fatal(err)
	}
	return n
}

// TestHR708_AddingAnOwnedAccountWaitsForASecondPerson: an addition is a
// protected change: nothing is listed until a different person confirms it
// with a security key; then the share step reads it, and removal applies at
// once. Both are audited (G0 M30 D933).
//
// Covers: HR-708
func TestHR708_AddingAnOwnedAccountWaitsForASecondPerson(t *testing.T) {
	w := newWorld(t)
	alice, bob := w.person("alice", td.RoleSecurityAdmin), w.person("bob", td.RoleSecurityAdmin)
	held, err := w.svc.Add(alice.page, domain.KindAWSAccount, "111122223333", "our prod account")
	if err != nil || held == nil {
		t.Fatalf("add: %v %v", held, err)
	}
	if got := w.owned(domain.KindAWSAccount); len(got) != 0 {
		t.Fatalf("listed before confirmation: %v", got)
	}
	if _, err := w.confirm(alice, held.Request); err == nil {
		t.Fatal("the author confirmed her own addition")
	}
	if _, err := w.confirm(bob, held.Request); err != nil {
		t.Fatalf("bob confirms: %v", err)
	}
	if got := w.owned(domain.KindAWSAccount); len(got) != 1 || got[0] != "111122223333" {
		t.Fatalf("after confirmation: %v", got)
	}
	if w.audits(auditkind.OrgOwnedAccountAdded) != 1 {
		t.Fatal("the addition is not audited")
	}
	if _, err := w.svc.Add(alice.page, domain.KindAWSAccount, "111122223333", "again"); !errors.Is(err, app.ErrListed) {
		t.Fatalf("adding a listed account: %v", err)
	}
	rows, err := w.svc.List(alice.page)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %v %v", rows, err)
	}
	if err := w.svc.Remove(alice.page, rows[0].ID, "account closed"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if got := w.owned(domain.KindAWSAccount); len(got) != 0 || w.audits(auditkind.OrgOwnedAccountRemoved) != 1 {
		t.Fatalf("after removal: %v", got)
	}
}

// TestHR708_OnlyAPersonWithManageChangesTheList: a malformed value, a
// person without org.owned_accounts.manage and a service account are
// refused, and nothing is filed (G0 M30 D933).
//
// Covers: HR-708
func TestHR708_OnlyAPersonWithManageChangesTheList(t *testing.T) {
	w := newWorld(t)
	alice := w.person("alice", td.RoleSecurityAdmin)
	if _, err := w.svc.Add(alice.page, domain.KindAWSAccount, "1234", "bad"); !errors.Is(err, app.ErrValue) {
		t.Fatalf("malformed value: %v", err)
	}
	if _, err := w.svc.Add(alice.page, "slack_team", "T1", "bad"); !errors.Is(err, app.ErrKind) {
		t.Fatalf("unknown kind: %v", err)
	}
	viewer := w.person("victor", td.RoleViewer)
	if _, err := w.svc.Add(viewer.page, domain.KindGitHubOrg, "acme", "mine"); err == nil {
		t.Fatal("a person without manage filed an addition")
	}
	sa := ids.NewV7()
	robot := tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{
			Org: w.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: sa},
			Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}}},
		},
		Credential: tapp.CredAccessToken, Session: ids.NewV7(),
	})
	if _, err := w.svc.Add(robot, domain.KindGitHubOrg, "acme", "mine"); err == nil {
		t.Fatal("a service account filed an addition")
	}
	if err := w.svc.Remove(robot, ids.NewV7(), "gone"); err == nil {
		t.Fatal("a service account removed an account")
	}
}
