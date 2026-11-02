// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idps"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/tenantctx"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	pvports "github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/provisioning/app"
	"github.com/katocxl/pantherclaw/internal/provisioning/domain"
	"github.com/katocxl/pantherclaw/internal/provisioning/ports"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	oidcIssuer = "https://idp.example.com" // the deployment's provider
	entityID   = "https://saml.example.com/entity"
	samlIssuer = "saml:" + entityID
)

type requests struct {
	mu     sync.Mutex
	opened map[ids.UUID]protect.Request
	voided map[ids.UUID]string
}

func (r *requests) Open(_ context.Context, _ db.TenantTx, q protect.Request) (ids.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := ids.NewV7()
	r.opened[id] = q
	return id, nil
}

func (r *requests) Void(_ context.Context, _ db.TenantTx, id ids.UUID, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.voided[id] = reason
	return nil
}

func (r *requests) Pending(_ context.Context, _ db.TenantTx, id ids.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, open := r.opened[id]
	_, voided := r.voided[id]
	return open && !voided, nil
}

type notes struct{ t *testing.T }

func (n notes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	if _, err := ndomain.Render(m.Type, m.Params); err != nil {
		n.t.Errorf("%s does not render: %v", m.Type, err)
	}
	return napp.Enqueued{}, nil
}

// edition is the org's plan, as the billing service reads it: from the org
// the context names (a tenant transaction, else the caller), and Community
// for any other context, as the deployment's licence would be (D528 M1).
type edition struct {
	org ids.OrgID
	e   billing.Edition
	// maxMembers is the member limit; zero means none.
	maxMembers int
}

func (e *edition) Current(ctx context.Context) (billing.Entitlements, error) {
	org, ok := tenantctx.Org(ctx)
	if !ok {
		if c, err := tapp.CallerFrom(ctx); err == nil {
			org, ok = c.Org, true
		}
	}
	ed := billing.Community
	if ok && org == e.org {
		ed = e.e
	}
	l := billing.CommunityLimits
	if e.maxMembers != 0 {
		l.MaxMembers = e.maxMembers
	}
	return billing.Entitlements{Edition: ed, Limits: l}, nil
}

func ptr[T any](v T) *T { return &v }

type env struct {
	pool    *db.Pool
	org     ids.OrgID
	gate    *protect.Gate
	svc     *app.Service
	edition *edition
	// alice and bob are org admins signing in through the deployment's
	// provider.
	alice, bob ids.UUID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{pool: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), bob: ids.NewV7()}
	e.gate = &protect.Gate{Requests: &requests{opened: map[ids.UUID]protect.Request{}, voided: map[ids.UUID]string{}}}
	e.edition = &edition{org: e.org, e: billing.Enterprise}
	e.svc = &app.Service{
		Pool: e.pool, Gate: e.gate, Editions: e.edition, Notify: notes{t: t},
		IdPs:     &idps.Store{Deployment: []idps.Deployment{{Name: "corp", Issuer: oidcIssuer}}},
		CheckURL: func(string) error { return nil }, Clock: clock.System{},
	}
	e.svc.Register(e.gate)
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'prov')", e.org)
	for _, u := range []ids.UUID{e.alice, e.bob} {
		e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, $4)", e.org, u, oidcIssuer, u.String())
		e.bind(t, u, td.RoleOrgAdmin)
	}
	return e
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatal(err)
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

func (e *env) bind(t *testing.T, u ids.UUID, role td.RoleName) {
	t.Helper()
	e.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		e.org, ids.NewV7(), string(role), u)
}

func (e *env) caller(user ids.UUID, role td.RoleName) tapp.Caller {
	return tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredBrowserSession}
}

func (e *env) admin(user ids.UUID) context.Context {
	return tapp.WithCaller(context.Background(), e.caller(user, td.RoleOrgAdmin))
}

// ledger counts the org's audit records of kind.
func (e *env) ledger(t *testing.T, kind string) int {
	t.Helper()
	return e.count(t, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", e.org, "audit."+kind)
}

// findings are the posture findings of SCIM-deprovisioned users' keys.
func (e *env) findings(t *testing.T) []pvdomain.Finding {
	t.Helper()
	fs, _, err := app.Source{Pool: e.pool}.Findings(context.Background(), pvports.Viewer{Org: e.org, Posture: pvports.Reach{All: true, Org: true}}, pvdomain.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func (e *env) confirm(t *testing.T, f app.Filed, user ids.UUID) error {
	t.Helper()
	return e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.gate.Apply(ctx, tx, f.Request, []ids.UUID{user})
	})
}

// token creates and activates a SCIM token for issuer.
func (e *env) token(t *testing.T, issuer, attr string) (ports.Token, string) {
	t.Helper()
	_, secret, f, err := e.svc.CreateToken(e.admin(e.alice), app.TokenInput{Name: "sync", Issuer: issuer, SubjectAttribute: attr, TTLDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(t, f, e.bob); err != nil {
		t.Fatal(err)
	}
	tok, err := e.svc.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatal(err)
	}
	return tok, secret
}

// TestHR629_SCIMTokenHeldAndBound: a token is PENDING and does nothing
// until a second person confirms; it is stored as a hash, sees only its
// issuer's users, and revoking it ends it at once (D409 point 5).
//
// Covers: F918
func TestHR629_SCIMTokenHeldAndBound(t *testing.T) {
	e := newEnv(t)
	if _, _, _, err := e.svc.CreateToken(e.admin(e.alice), app.TokenInput{
		Name: "x", Issuer: "https://unknown.example.com", SubjectAttribute: domain.SubjectUserName, TTLDays: 30,
	}); !errors.Is(err, app.ErrIssuer) {
		t.Fatalf("a token for an unknown issuer: %v", err)
	}
	tk, secret, f, err := e.svc.CreateToken(e.admin(e.alice), app.TokenInput{
		Name: "sync", Issuer: oidcIssuer, SubjectAttribute: domain.SubjectUserName, TTLDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tk.State != domain.StatePending {
		t.Fatalf("a new token is %s", tk.State)
	}
	if _, err := e.svc.Authenticate(context.Background(), secret); !errors.Is(err, ports.ErrUnauthenticated) {
		t.Fatalf("a PENDING token authenticated: %v", err)
	}
	// Stored as the hash of the bearer, never the bearer.
	cred, err := credential.Parse(credential.SCIMToken, secret)
	if err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.scim_tokens WHERE org_id = $1 AND id = $2 AND secret_hash = $3", e.org, tk.ID, cred.Hash()); n != 1 {
		t.Fatal("the token is not stored as its bearer's hash")
	}
	if err := e.confirm(t, f, e.alice); err == nil {
		t.Fatal("the author confirmed their own token")
	}
	if err := e.confirm(t, f, e.bob); err != nil {
		t.Fatal(err)
	}
	tok, err := e.svc.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("an approved token: %v", err)
	}

	// The token sees its issuer's users only.
	other := ids.NewV7()
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://other.example.com', 'x')", e.org, other)
	if _, err := e.svc.GetUser(context.Background(), tok, other.String()); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("a user of another issuer: %v", err)
	}
	us, err := e.svc.ListUsers(context.Background(), tok, ports.UserFilter{}, ports.Page{StartIndex: 1, Count: 10})
	if err != nil || us.Total != 2 {
		t.Fatalf("listed %d users: %v", us.Total, err)
	}

	if _, err := e.svc.RevokeToken(e.admin(e.alice), tk.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(context.Background(), secret); !errors.Is(err, ports.ErrUnauthenticated) {
		t.Fatalf("a revoked token authenticated: %v", err)
	}
	// A Token made from a revoked bearer does nothing: every call looks the
	// token up again (D528).
	if _, err := e.svc.ListUsers(context.Background(), tok, ports.UserFilter{}, ports.Page{StartIndex: 1, Count: 10}); !errors.Is(err, ports.ErrUnauthenticated) {
		t.Fatalf("a revoked token listed: %v", err)
	}
	if _, err := e.svc.GetUser(context.Background(), ports.NewToken("pc_scim_forged"), e.alice.String()); !errors.Is(err, ports.ErrUnauthenticated) {
		t.Fatalf("a forged token: %v", err)
	}

	// Approving re-checks that the issuer is still a known provider (D528).
	_, secret2, f2, err := e.svc.CreateToken(e.admin(e.alice), app.TokenInput{
		Name: "sync2", Issuer: oidcIssuer, SubjectAttribute: domain.SubjectUserName, TTLDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	known := e.svc.IdPs
	e.svc.IdPs = &idps.Store{Deployment: []idps.Deployment{{Name: "other", Issuer: "https://other.example.com"}}}
	if err := e.confirm(t, f2, e.bob); !errors.Is(err, app.ErrIssuer) {
		t.Fatalf("a token of an unknown issuer was approved: %v", err)
	}
	e.svc.IdPs = known
	if _, err := e.svc.Authenticate(context.Background(), secret2); !errors.Is(err, ports.ErrUnauthenticated) {
		t.Fatalf("the refused token authenticated: %v", err)
	}
}

// TestHR630_GroupsCarryNoAdminRole: a mapping of a role that holds
// role.bind, or of Emergency Responder, is refused when filed; a mapping
// that applies gives the members a provisioned binding, which leaves with
// the membership, and never touches a binding a person made (D409 point 3).
//
// Covers: F919, F920
func TestHR630_GroupsCarryNoAdminRole(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.token(t, oidcIssuer, domain.SubjectUserName)
	g, err := e.svc.CreateGroup(context.Background(), tok, ports.GroupInput{DisplayName: "eng", Members: []string{e.alice.String()}})
	if err != nil {
		t.Fatal(err)
	}
	gid, _ := ids.ParseUUID(g.ID)
	org := td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}
	for _, r := range domain.UnmappableRoles() {
		if _, err := e.svc.AddMapping(e.admin(e.alice), gid, r, org); err == nil {
			t.Errorf("%s was filed for a group", r)
		}
	}
	f, err := e.svc.AddMapping(e.admin(e.alice), gid, td.RoleViewer, org)
	if err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.group_role_mappings WHERE org_id = $1", e.org); n != 0 {
		t.Fatal("a mapping applied before it was confirmed")
	}
	if err := e.confirm(t, f, e.bob); err != nil {
		t.Fatal(err)
	}
	provisioned := func(u ids.UUID) int {
		return e.count(t, "SELECT count(*) FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2 AND provisioned AND role = 'viewer'", e.org, u)
	}
	if provisioned(e.alice) != 1 {
		t.Fatal("the member did not get the mapped role")
	}
	// bob holds viewer from a person; the provisioned viewer binding sits
	// beside it while he is a member (the source is in the binding's key),
	// and leaving the group takes only the provisioned one (D528).
	viewers := func(u ids.UUID) int {
		return e.count(t, "SELECT count(*) FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2 AND role = 'viewer'", e.org, u)
	}
	e.bind(t, e.bob, td.RoleViewer)
	if _, err := e.svc.ChangeGroup(context.Background(), tok, g.ID, ports.GroupChange{AddMembers: []string{e.bob.String()}}); err != nil {
		t.Fatal(err)
	}
	if viewers(e.bob) != 2 || provisioned(e.bob) != 1 {
		t.Fatalf("bob's bindings in the group: %d", viewers(e.bob))
	}
	if _, err := e.svc.ChangeGroup(context.Background(), tok, g.ID, ports.GroupChange{RemoveUsers: []string{e.alice.String(), e.bob.String()}}); err != nil {
		t.Fatal(err)
	}
	if provisioned(e.alice) != 0 {
		t.Fatal("the binding stayed after the member left")
	}
	if viewers(e.bob) != 1 || provisioned(e.bob) != 0 {
		t.Fatalf("bob's own binding: %d", viewers(e.bob))
	}

	// Below Enterprise a removal still applies: only the removal, and the
	// dropped parts are recorded; a change with no removal is refused (D528).
	if _, err := e.svc.ChangeGroup(context.Background(), tok, g.ID, ports.GroupChange{AddMembers: []string{e.alice.String()}}); err != nil {
		t.Fatal(err)
	}
	e.edition.e = billing.Business
	renamed := "eng-renamed"
	if _, err := e.svc.ChangeGroup(context.Background(), tok, g.ID, ports.GroupChange{DisplayName: &renamed, AddMembers: []string{e.bob.String()}}); !errors.Is(err, ports.ErrEdition) {
		t.Fatalf("a change with no removal below Enterprise: %v", err)
	}
	got, err := e.svc.ChangeGroup(context.Background(), tok, g.ID, ports.GroupChange{
		DisplayName: &renamed, AddMembers: []string{e.bob.String()}, RemoveUsers: []string{e.alice.String()},
	})
	if err != nil || got.DisplayName != "eng" || len(got.Members) != 0 {
		t.Fatalf("a removal below Enterprise: %+v %v", got, err)
	}
	if provisioned(e.alice) != 0 || provisioned(e.bob) != 0 {
		t.Fatal("the removal below Enterprise left or added a binding")
	}
	if n := e.ledger(t, "scim.parts_dropped"); n != 1 {
		t.Fatalf("%d dropped parts recorded", n)
	}
	if _, err := e.svc.ReplaceGroup(context.Background(), tok, g.ID, ports.GroupInput{DisplayName: "eng", Members: []string{e.bob.String()}}); !errors.Is(err, ports.ErrEdition) {
		t.Fatalf("a replace that only adds below Enterprise: %v", err)
	}
}

// TestHR631_MappingChangesHeldAndRecheckedAsAsker: removing a mapping is
// held for a second person like adding one, and a held mapping applies only
// if every check still passes for the person who asked, never for the one
// who confirmed (D409 point 6).
//
// Covers: F920
func TestHR631_MappingChangesHeldAndRecheckedAsAsker(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tok, _ := e.token(t, oidcIssuer, domain.SubjectUserName)
	g, err := e.svc.CreateGroup(ctx, tok, ports.GroupInput{DisplayName: "ops", Members: []string{e.alice.String()}})
	if err != nil {
		t.Fatal(err)
	}
	gid, _ := ids.ParseUUID(g.ID)
	org := td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}
	mappings := func() int {
		return e.count(t, "SELECT count(*) FROM pc.group_role_mappings WHERE org_id = $1", e.org)
	}
	provisioned := func() int {
		return e.count(t, "SELECT count(*) FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2 AND provisioned", e.org, e.alice)
	}
	f, err := e.svc.AddMapping(e.admin(e.alice), gid, td.RoleViewer, org)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(t, f, e.bob); err != nil {
		t.Fatal(err)
	}
	var mapping ids.UUID
	if err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.group_role_mappings WHERE org_id = $1", e.org).Scan(&mapping)
	}); err != nil {
		t.Fatal(err)
	}

	// The removal is held.
	rf, err := e.svc.RemoveMapping(e.admin(e.alice), mapping)
	if err != nil {
		t.Fatal(err)
	}
	if mappings() != 1 || provisioned() != 1 {
		t.Fatal("a mapping removal applied before it was confirmed")
	}
	if err := e.confirm(t, rf, e.alice); err == nil {
		t.Fatal("the author confirmed their own removal")
	}
	if err := e.confirm(t, rf, e.bob); err != nil {
		t.Fatal(err)
	}
	if mappings() != 0 || provisioned() != 0 {
		t.Fatal("the confirmed removal left the mapping or its binding")
	}

	// The apply checks the bind ceiling of the person who asked: the stored
	// change, applied for an asker who cannot bind the role, gives nothing.
	f, err = e.svc.AddMapping(e.admin(e.alice), gid, td.RoleViewer, org)
	if err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT payload FROM pc.protected_changes WHERE org_id = $1 AND id = $2", e.org, f.Change).Scan(&payload)
	}); err != nil {
		t.Fatal(err)
	}
	err = e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.svc.ApplyMappingAdd(ctx, tx, e.caller(e.alice, td.RoleViewer), payload)
	})
	if err == nil || errors.Is(err, protect.ErrInvalid) {
		t.Fatalf("applied for an asker without role.bind: %v", err)
	}
	if mappings() != 0 || provisioned() != 0 {
		t.Fatal("a mapping applied above the asker's ceiling")
	}

	// alice loses Org Admin: bob's confirmation of her change does not apply it.
	e.exec(t, "DELETE FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2 AND role = 'org_admin'", e.org, e.alice)
	if err := e.confirm(t, f, e.bob); err == nil {
		t.Fatal("a mapping applied for an asker who lost the authority")
	}
	if mappings() != 0 || provisioned() != 0 {
		t.Fatal("a mapping applied for an asker who lost the authority")
	}

	// Asked by someone within the ceiling, the same mapping applies.
	e.bind(t, e.alice, td.RoleOrgAdmin)
	f, err = e.svc.AddMapping(e.admin(e.bob), gid, td.RoleViewer, org)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(t, f, e.alice); err != nil {
		t.Fatal(err)
	}
	if mappings() != 1 || provisioned() != 1 {
		t.Fatal("the mapping did not apply for an asker within the ceiling")
	}
}

// TestSCIMGroupNameRace: two creates of the same group name at once give
// one group and a conflict, from the table's constraint (D528).
//
// Covers: F919
func TestSCIMGroupNameRace(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.token(t, oidcIssuer, domain.SubjectUserName)
	const n = 4
	errs := make(chan error, n)
	var start sync.WaitGroup
	start.Add(1)
	for range n {
		go func() {
			start.Wait()
			_, err := e.svc.CreateGroup(context.Background(), tok, ports.GroupInput{DisplayName: "race"})
			errs <- err
		}()
	}
	start.Done()
	created := 0
	for range n {
		switch err := <-errs; {
		case err == nil:
			created++
		case errors.Is(err, ports.ErrConflict):
		default:
			t.Errorf("a concurrent create: %v", err)
		}
	}
	if created != 1 {
		t.Fatalf("%d groups created", created)
	}
}

// TestHR632_Deprovision: deprovisioning ends sessions at once, leaves API
// keys active and lists them in the posture queue (D409 point 4); it is
// refused for the last admin, with the refusal recorded; SCIM never
// re-enables a user a person disabled.
//
// Covers: F918
func TestHR632_Deprovision(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.token(t, oidcIssuer, domain.SubjectUserName)
	ctx := context.Background()

	// Deprovisioning bob is fine: alice is left.
	sa, key := ids.NewV7(), ids.NewV7()
	e.exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'ci', 'test')", e.org, sa)
	e.exec(t, `INSERT INTO pc.api_keys (org_id, id, service_account_id, name, secret_hash, hint, scopes, created_by, expires_at)
		VALUES ($1, $2, $3, 'deploy', $4, 'abcd', ARRAY['team.read'], $5, now() + interval '90 days')`,
		e.org, key, sa, make([]byte, 32), "user:"+e.bob.String())
	e.exec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'corp', $4, now() + interval '12 hours')`, e.org, ids.NewV7(), e.bob, make([]byte, 32))
	e.exec(t, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, repeat('d', 43), '{}', $4, now() + interval '8 hours')`, e.org, ids.NewV7(), e.bob, make([]byte, 32))
	if e.count(t, "SELECT count(*) FROM pc.sessions WHERE org_id = $1 AND user_id = $2 AND state = 'ACTIVE'", e.org, e.bob) != 1 ||
		e.count(t, "SELECT count(*) FROM pc.cli_sessions WHERE org_id = $1 AND user_id = $2 AND state = 'ACTIVE'", e.org, e.bob) != 1 {
		t.Fatal("the sessions are not set up")
	}
	off := false
	if _, err := e.svc.ChangeUser(ctx, tok, e.bob.String(), ports.UserChange{Active: &off}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.sessions WHERE org_id = $1 AND user_id = $2 AND state = 'ACTIVE'", e.org, e.bob); n != 0 {
		t.Fatal("a deprovisioned user's browser session is active")
	}
	if n := e.count(t, "SELECT count(*) FROM pc.cli_sessions WHERE org_id = $1 AND user_id = $2 AND state = 'ACTIVE'", e.org, e.bob); n != 0 {
		t.Fatal("a deprovisioned user's CLI session is active")
	}
	if n := e.count(t, "SELECT count(*) FROM pc.api_keys WHERE org_id = $1 AND id = $2 AND state = 'ACTIVE'", e.org, key); n != 1 {
		t.Fatal("deprovisioning revoked the person's API key")
	}
	finding := func(when string) {
		t.Helper()
		fs := e.findings(t)
		if len(fs) != 1 || fs[0].SourceID != key.String() || fs[0].Fix.Kind != pvdomain.FixRotateSecret {
			t.Fatalf("posture findings %s: %+v", when, fs)
		}
	}
	finding("after deprovisioning")

	// Alice is the last admin: refused, rolled back, recorded.
	if _, err := e.svc.ChangeUser(ctx, tok, e.alice.String(), ports.UserChange{Active: &off}); !errors.Is(err, ports.ErrLastAdmin) {
		t.Fatalf("the last admin was deprovisioned: %v", err)
	}
	if err := e.svc.DeleteUser(ctx, tok, e.alice.String()); !errors.Is(err, ports.ErrLastAdmin) {
		t.Fatalf("the last admin was deleted: %v", err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.users WHERE org_id = $1 AND id = $2 AND state = 'ACTIVE'", e.org, e.alice); n != 1 {
		t.Fatal("the refused change was kept")
	}
	if n := e.ledger(t, "scim.user_deprovision_refused"); n != 2 {
		t.Fatalf("%d refusals recorded", n)
	}

	// An admin remains, but none with a way to sign in: carl's provider is
	// gone. Refused the same way (HR-484).
	carl := ids.NewV7()
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://gone.example.com', 'carl')", e.org, carl)
	e.bind(t, carl, td.RoleOrgAdmin)
	if _, err := e.svc.ChangeUser(ctx, tok, e.alice.String(), ports.UserChange{Active: &off}); !errors.Is(err, ports.ErrLastAdmin) {
		t.Fatalf("the last admin with a sign-in path was deprovisioned: %v", err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.users WHERE org_id = $1 AND id = $2 AND state = 'ACTIVE'", e.org, e.alice); n != 1 {
		t.Fatal("the refused change was kept")
	}
	if n := e.ledger(t, "scim.user_deprovision_refused"); n != 3 {
		t.Fatalf("%d refusals recorded", n)
	}

	// SCIM re-enables the user it disabled, never one a person disabled.
	// The key stays in the posture queue whatever happens to the person
	// later, while it is active (D528).
	on := true
	if _, err := e.svc.ChangeUser(ctx, tok, e.bob.String(), ports.UserChange{Active: &on}); err != nil {
		t.Fatal(err)
	}
	finding("after SCIM re-enabled the user")
	if _, err := e.svc.ChangeUser(ctx, tok, e.bob.String(), ports.UserChange{Active: &off}); err != nil {
		t.Fatal(err)
	}
	e.exec(t, "UPDATE pc.scim_users SET disabled_by_scim = false, updated_at = now() WHERE org_id = $1 AND user_id = $2", e.org, e.bob)
	if _, err := e.svc.ChangeUser(ctx, tok, e.bob.String(), ports.UserChange{Active: &on}); !errors.Is(err, ports.ErrDisabledHere) {
		t.Fatalf("SCIM re-enabled a user a person disabled: %v", err)
	}
	e.exec(t, "UPDATE pc.users SET state = 'ACTIVE' WHERE org_id = $1 AND id = $2", e.org, e.bob)
	finding("after a person re-enabled the user")
	e.exec(t, "UPDATE pc.api_keys SET state = 'REVOKED', revoked_at = now() WHERE org_id = $1 AND id = $2", e.org, key)
	if fs := e.findings(t); len(fs) != 0 {
		t.Fatalf("a revoked key is still a finding: %+v", fs)
	}
}

// TestSCIMUsersAndEditions: create, conflict, the immutable subject, and
// removing in every edition while adding needs Enterprise (D409 point 7).
//
// Covers: F918
func TestSCIMUsersAndEditions(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.token(t, oidcIssuer, domain.SubjectUserName)
	ctx := context.Background()
	// No active given: a created user is active.
	u, err := e.svc.CreateUser(ctx, tok, ports.UserInput{UserName: "carol", ExternalID: "c-1", Email: "carol@example.com"})
	if err != nil || u.UserName != "carol" || u.ExternalID != "c-1" || !u.Active {
		t.Fatalf("created %+v %v", u, err)
	}
	if _, err := e.svc.CreateUser(ctx, tok, ports.UserInput{UserName: "carol", Active: ptr(true)}); !errors.Is(err, ports.ErrConflict) {
		t.Fatalf("a second carol: %v", err)
	}
	other := "dave"
	if _, err := e.svc.ChangeUser(ctx, tok, u.ID, ports.UserChange{UserName: &other}); !errors.Is(err, ports.ErrImmutable) {
		t.Fatalf("the subject changed: %v", err)
	}
	us, err := e.svc.ListUsers(ctx, tok, ports.UserFilter{ExternalID: "c-1"}, ports.Page{StartIndex: 1, Count: 10})
	if err != nil || us.Total != 1 || us.Items[0].ID != u.ID {
		t.Fatalf("filtered %+v %v", us, err)
	}
	// userName is not case-exact (RFC 7643 4.1.1).
	us, err = e.svc.ListUsers(ctx, tok, ports.UserFilter{UserName: "CaRoL"}, ports.Page{StartIndex: 1, Count: 10})
	if err != nil || us.Total != 1 || us.Items[0].ID != u.ID {
		t.Fatalf("filtered by userName in another case %+v %v", us, err)
	}

	// A PUT without active keeps the stored state (D528).
	if _, err := e.svc.ChangeUser(ctx, tok, u.ID, ports.UserChange{Active: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.ReplaceUser(ctx, tok, u.ID, ports.UserInput{UserName: "carol", ExternalID: "c-1", Email: "carol@example.org"})
	if err != nil || r.Active || r.Email != "carol@example.org" {
		t.Fatalf("a PUT without active: %+v %v", r, err)
	}
	if r, err = e.svc.ChangeUser(ctx, tok, u.ID, ports.UserChange{Active: ptr(true)}); err != nil || !r.Active {
		t.Fatalf("re-enabled %+v %v", r, err)
	}

	// An active user counts against the plan's member limit (HR-360).
	e.edition.maxMembers = 3 // alice, bob, carol
	if _, err := e.svc.CreateUser(ctx, tok, ports.UserInput{UserName: "erin", Active: ptr(true)}); !errors.Is(err, ports.ErrPlanLimit) {
		t.Fatalf("created past the member limit: %v", err)
	}
	e.edition.maxMembers = 0

	// Below Enterprise: adding is refused; a request with a removal applies
	// the removal only, answers with the stored user and records what it
	// dropped (D528).
	e.edition.e = billing.Business
	if _, err := e.svc.CreateUser(ctx, tok, ports.UserInput{UserName: "erin", Active: ptr(true)}); !errors.Is(err, ports.ErrEdition) {
		t.Fatalf("created below Enterprise: %v", err)
	}
	if _, err := e.svc.ChangeUser(ctx, tok, u.ID, ports.UserChange{Email: ptr("x@example.com")}); !errors.Is(err, ports.ErrEdition) {
		t.Fatalf("a change with no removal below Enterprise: %v", err)
	}
	if _, err := e.svc.ReplaceUser(ctx, tok, u.ID, ports.UserInput{UserName: "carol", ExternalID: "c-1", Email: "x@example.com", Active: ptr(true)}); !errors.Is(err, ports.ErrEdition) {
		t.Fatalf("a PUT with no removal below Enterprise: %v", err)
	}
	r, err = e.svc.ReplaceUser(ctx, tok, u.ID, ports.UserInput{UserName: "carol", ExternalID: "c-1", Email: "x@example.com", Active: ptr(false)})
	if err != nil || r.Active || r.Email != "carol@example.org" {
		t.Fatalf("a deprovisioning PUT below Enterprise: %+v %v", r, err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.users WHERE org_id = $1 AND id::text = $2 AND state = 'DISABLED'", e.org, u.ID); n != 1 {
		t.Fatal("the removal below Enterprise did not apply")
	}
	if n := e.ledger(t, "scim.parts_dropped"); n != 1 {
		t.Fatalf("%d dropped parts recorded", n)
	}
	if err := e.svc.DeleteUser(ctx, tok, u.ID); err != nil {
		t.Fatalf("deleting below Enterprise: %v", err)
	}
	if _, err := e.svc.GetUser(ctx, tok, u.ID); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("a deleted user is visible: %v", err)
	}
}

func testCert(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

type web struct {
	out authnapp.BrowserSignIn
	err error
}

func (w *web) FinishExternalSignIn(_ http.ResponseWriter, _ *http.Request, out authnapp.BrowserSignIn, err error) {
	w.out, w.err = out, err
}
func (w *web) ClientMeta(*http.Request) authnapp.ClientMeta { return authnapp.ClientMeta{} }

// forged is a sign-in handle the core did not make.
type forged struct{}

func (forged) SignInHandle() {}

// TestHR633_634_SAMLConnectionAndSignIn: a connection is a held change; an
// ACTIVE one starts a single-use sign-in bound to the browser, accepts an
// assertion id once, and signs in only its own existing users.
//
// Covers: F921, F922
func TestHR633_634_SAMLConnectionAndSignIn(t *testing.T) {
	e := newEnv(t)
	c, f, err := e.svc.CreateConnection(e.admin(e.alice), domain.Connection{
		Name: "okta", EntityID: entityID, SSOURL: "https://saml.example.com/sso", Certificates: []string{testCert(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	si := &app.SignIn{Pool: e.pool, Browser: authnapp.NewBrowser(e.pool, "https://pc.example.test", nil, clock.System{}, nil), Web: &web{}}
	ctx := context.Background()
	if _, err := si.Connection(ctx, e.org.String(), c.ID.String()); !errors.Is(err, ports.ErrSignInUnavailable) {
		t.Fatalf("a PENDING connection: %v", err)
	}
	if err := e.confirm(t, f, e.bob); err != nil {
		t.Fatal(err)
	}
	conn, err := si.Connection(ctx, e.org.String(), c.ID.String())
	if err != nil || conn.IdPEntityID != entityID || len(conn.Certificates) != 1 {
		t.Fatalf("connection %+v %v", conn, err)
	}

	st, err := si.StartSignIn(ctx, e.org.String(), c.ID.String(), "_req1", "/app/", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := si.ConsumeSignIn(ctx, e.org.String(), c.ID.String(), st.RelayState, "another-browser"); !errors.Is(err, ports.ErrSignInUnavailable) {
		t.Fatalf("another browser consumed the sign-in: %v", err)
	}
	consume := func(req string) ports.SignInHandle {
		t.Helper()
		st, err := si.StartSignIn(ctx, e.org.String(), c.ID.String(), req, "/app/", "")
		if err != nil {
			t.Fatal(err)
		}
		p, err := si.ConsumeSignIn(ctx, e.org.String(), c.ID.String(), st.RelayState, st.Binding)
		if err != nil || p.RequestID != req || p.Handle == nil {
			t.Fatalf("consumed %+v %v", p, err)
		}
		if _, err := si.ConsumeSignIn(ctx, e.org.String(), c.ID.String(), st.RelayState, st.Binding); !errors.Is(err, ports.ErrSignInUnavailable) {
			t.Fatalf("a sign-in was consumed twice: %v", err)
		}
		return p.Handle
	}
	w := si.Web.(*web)
	r := httptest.NewRequest(http.MethodPost, "/app/ext/saml/acs", nil)
	finish := func(h ports.SignInHandle, v ports.Verified) {
		*w = web{}
		si.FinishSignIn(httptest.NewRecorder(), r, h, v)
	}
	refused := func(what string) {
		t.Helper()
		if !errors.Is(w.err, authnapp.ErrSignInUnavailable) || w.out.Secret != "" {
			t.Fatalf("%s: %+v %v", what, w.out, w.err)
		}
	}
	exp := time.Now().Add(5 * time.Minute)
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, 'frank')", e.org, ids.NewV7(), samlIssuer)
	frank := ports.Verified{Subject: "frank"}

	// A handle the core did not make does nothing (D528).
	if err := si.RecordAssertion(ctx, forged{}, "_a0", exp); !errors.Is(err, ports.ErrSignInUnavailable) {
		t.Fatalf("a forged handle recorded: %v", err)
	}
	finish(forged{}, frank)
	refused("a forged handle")

	// One assertion per sign-in; an unknown subject is refused; a used
	// sign-in does not finish again.
	h := consume("_req2")
	if err := si.RecordAssertion(ctx, h, "_a1", exp); err != nil {
		t.Fatal(err)
	}
	if err := si.RecordAssertion(ctx, h, "_a9", exp); !errors.Is(err, ports.ErrReplayed) {
		t.Fatalf("a second assertion for one sign-in: %v", err)
	}
	finish(h, ports.Verified{Subject: "nobody"})
	if w.out.Reason != "NOT_A_MEMBER" {
		t.Fatalf("an unknown subject: %+v %v", w.out, w.err)
	}
	finish(h, frank)
	refused("a used sign-in")

	// A sign-in whose assertion was not recorded does not finish, and is
	// spent.
	h = consume("_req3")
	finish(h, frank)
	refused("an unrecorded sign-in")
	if err := si.RecordAssertion(ctx, h, "_a2", exp); !errors.Is(err, ports.ErrReplayed) {
		t.Fatalf("recorded after a refused finish: %v", err)
	}

	// An assertion id is accepted once, across sign-ins.
	if err := si.RecordAssertion(ctx, consume("_req4"), "_a1", exp); !errors.Is(err, ports.ErrReplayed) {
		t.Fatalf("a replayed assertion: %v", err)
	}

	// An AuthnInstant more than five minutes ahead is refused; one within
	// it signs in (D528).
	h = consume("_req5")
	if err := si.RecordAssertion(ctx, h, "_a3", exp); err != nil {
		t.Fatal(err)
	}
	finish(h, ports.Verified{Subject: "frank", AuthenticatedAt: time.Now().Add(10 * time.Minute)})
	refused("an AuthnInstant ten minutes ahead")
	h = consume("_req6")
	if err := si.RecordAssertion(ctx, h, "_a4", exp); err != nil {
		t.Fatal(err)
	}
	finish(h, ports.Verified{Subject: "frank", AuthenticatedAt: time.Now().Add(time.Minute)})
	if w.err != nil || w.out.Reason != "" || w.out.Secret == "" {
		t.Fatalf("a member: %+v %v", w.out, w.err)
	}

	// Disabling the connection is a held change too, and the sign-in stops.
	df, err := e.svc.DisableConnection(e.admin(e.alice), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(t, df, e.bob); err != nil {
		t.Fatal(err)
	}
	if _, err := si.Connection(ctx, e.org.String(), c.ID.String()); !errors.Is(err, ports.ErrSignInUnavailable) {
		t.Fatalf("a DISABLED connection: %v", err)
	}
	var n int64
	if err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		n, err = dbq.New(tx).CountSAMLConnections(ctx, e.org)
		return err
	}); err != nil || n != 0 {
		t.Fatalf("live connections %d %v", n, err)
	}
}
