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
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idps"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
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

type edition struct{ e billing.Edition }

func (e *edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

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
	e.edition = &edition{e: billing.Enterprise}
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

func (e *env) admin(user ids.UUID) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredBrowserSession})
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
	if n := e.count(t, "SELECT count(*) FROM pc.scim_tokens WHERE secret_hash = $1", []byte(secret)); n != 0 {
		t.Fatal("the secret is stored in the clear")
	}
	if err := e.confirm(t, f, e.alice); err == nil {
		t.Fatal("the author confirmed their own token")
	}
	if err := e.confirm(t, f, e.bob); err != nil {
		t.Fatal(err)
	}
	tok, err := e.svc.Authenticate(context.Background(), secret)
	if err != nil || tok.Issuer != oidcIssuer {
		t.Fatalf("an approved token: %+v %v", tok, err)
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
	// bob holds viewer from a person; joining and leaving the group keeps it.
	e.bind(t, e.bob, td.RoleViewer)
	if _, err := e.svc.ChangeGroup(context.Background(), tok, g.ID, ports.GroupChange{AddMembers: []string{e.bob.String()}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ChangeGroup(context.Background(), tok, g.ID, ports.GroupChange{RemoveUsers: []string{e.alice.String(), e.bob.String()}}); err != nil {
		t.Fatal(err)
	}
	if provisioned(e.alice) != 0 {
		t.Fatal("the binding stayed after the member left")
	}
	if n := e.count(t, "SELECT count(*) FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2 AND role = 'viewer'", e.org, e.bob); n != 1 {
		t.Fatalf("bob's own binding: %d", n)
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
	off := false
	if _, err := e.svc.ChangeUser(ctx, tok, e.bob.String(), ports.UserChange{Active: &off}); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.sessions WHERE org_id = $1 AND user_id = $2 AND state = 'ACTIVE'", e.org, e.bob); n != 0 {
		t.Fatal("a deprovisioned user's session is active")
	}
	if n := e.count(t, "SELECT count(*) FROM pc.api_keys WHERE org_id = $1 AND id = $2 AND state = 'ACTIVE'", e.org, key); n != 1 {
		t.Fatal("deprovisioning revoked the person's API key")
	}
	fs, _, err := app.Source{Pool: e.pool}.Findings(ctx, pvports.Viewer{Org: e.org, Posture: pvports.Reach{All: true, Org: true}}, pvdomain.Filter{})
	if err != nil || len(fs) != 1 || fs[0].SourceID != key.String() || fs[0].Fix.Kind != pvdomain.FixRotateSecret {
		t.Fatalf("posture findings %+v %v", fs, err)
	}

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
	if n := e.count(t, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.scim.user_deprovision_refused'", e.org); n != 2 {
		t.Fatalf("%d refusals recorded", n)
	}

	// SCIM re-enables the user it disabled, never one a person disabled.
	on := true
	if _, err := e.svc.ChangeUser(ctx, tok, e.bob.String(), ports.UserChange{Active: &on}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ChangeUser(ctx, tok, e.bob.String(), ports.UserChange{Active: &off}); err != nil {
		t.Fatal(err)
	}
	e.exec(t, "UPDATE pc.scim_users SET disabled_by_scim = false WHERE org_id = $1 AND user_id = $2", e.org, e.bob)
	if _, err := e.svc.ChangeUser(ctx, tok, e.bob.String(), ports.UserChange{Active: &on}); !errors.Is(err, ports.ErrDisabledHere) {
		t.Fatalf("SCIM re-enabled a user a person disabled: %v", err)
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
	u, err := e.svc.CreateUser(ctx, tok, ports.UserInput{UserName: "carol", ExternalID: "c-1", Email: "carol@example.com", Active: true})
	if err != nil || u.UserName != "carol" || u.ExternalID != "c-1" || !u.Active {
		t.Fatalf("created %+v %v", u, err)
	}
	if _, err := e.svc.CreateUser(ctx, tok, ports.UserInput{UserName: "carol", Active: true}); !errors.Is(err, ports.ErrConflict) {
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

	e.edition.e = billing.Business
	if _, err := e.svc.CreateUser(ctx, tok, ports.UserInput{UserName: "erin", Active: true}); !errors.Is(err, ports.ErrEdition) {
		t.Fatalf("created below Enterprise: %v", err)
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

type web struct{ out authnapp.BrowserSignIn }

func (w *web) FinishExternalSignIn(_ http.ResponseWriter, _ *http.Request, out authnapp.BrowserSignIn, _ error) {
	w.out = out
}
func (w *web) ClientMeta(*http.Request) authnapp.ClientMeta { return authnapp.ClientMeta{} }

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

	st, err := si.StartSignIn(ctx, e.org.String(), c.ID.String(), "_req1", "/app", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := si.ConsumeSignIn(ctx, e.org.String(), c.ID.String(), st.RelayState, "another-browser"); !errors.Is(err, ports.ErrSignInUnavailable) {
		t.Fatalf("another browser consumed the sign-in: %v", err)
	}
	st, _ = si.StartSignIn(ctx, e.org.String(), c.ID.String(), "_req2", "/app", "")
	p, err := si.ConsumeSignIn(ctx, e.org.String(), c.ID.String(), st.RelayState, st.Binding)
	if err != nil || p.RequestID != "_req2" {
		t.Fatalf("consumed %+v %v", p, err)
	}
	if _, err := si.ConsumeSignIn(ctx, e.org.String(), c.ID.String(), st.RelayState, st.Binding); !errors.Is(err, ports.ErrSignInUnavailable) {
		t.Fatalf("a sign-in was consumed twice: %v", err)
	}
	exp := time.Now().Add(5 * time.Minute)
	if err := si.RecordAssertion(ctx, e.org.String(), c.ID.String(), "_a1", exp); err != nil {
		t.Fatal(err)
	}
	if err := si.RecordAssertion(ctx, e.org.String(), c.ID.String(), "_a1", exp); !errors.Is(err, ports.ErrReplayed) {
		t.Fatalf("a replayed assertion: %v", err)
	}

	// Existing users only: an unknown subject is refused, a user of the
	// connection's issuer signs in.
	w := si.Web.(*web)
	r := httptest.NewRequest(http.MethodPost, "/app/ext/saml/acs", nil)
	si.FinishSignIn(httptest.NewRecorder(), r, ports.Verified{OrgID: e.org.String(), ConnectionID: c.ID.String(), Subject: "nobody", Next: "/app"})
	if w.out.Reason != "NOT_A_MEMBER" {
		t.Fatalf("an unknown subject: %+v", w.out)
	}
	e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, 'frank')", e.org, ids.NewV7(), samlIssuer)
	si.FinishSignIn(httptest.NewRecorder(), r, ports.Verified{OrgID: e.org.String(), ConnectionID: c.ID.String(), Subject: "frank", Next: "/app"})
	if w.out.Reason != "" || w.out.Secret == "" {
		t.Fatalf("a member: %+v", w.out)
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
