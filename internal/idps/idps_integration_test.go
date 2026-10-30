// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package idps_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idps"
	"github.com/katocxl/pantherclaw/internal/keystore"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/protect"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	orgIssuer  = "https://idp.example.com"  // the org's own provider
	corpIssuer = "https://corp.example.com" // the deployment's provider "corp"
)

// requests is an in-memory change ceremony.
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

func (r *requests) get(id ids.UUID) protect.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.opened[id]
}

// notes records notifications after checking they render.
type notes struct {
	t    *testing.T
	mu   sync.Mutex
	sent []napp.Message
}

func (n *notes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	if _, err := ndomain.Render(m.Type, m.Params); err != nil {
		n.t.Errorf("%s does not render: %v", m.Type, err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, m)
	return napp.Enqueued{}, nil
}

func (n *notes) last() napp.Message {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.sent) == 0 {
		return napp.Message{}
	}
	return n.sent[len(n.sent)-1]
}

type edition struct{ e billing.Edition }

func (e *edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

type env struct {
	pool    *db.Pool
	org     ids.OrgID
	reqs    *requests
	gate    *protect.Gate
	svc     *idps.Service
	store   *idps.Store
	notes   *notes
	edition *edition
	// alice and bob are org admins: alice signs in through the org's
	// provider's issuer, bob through the deployment's. carol is a Security
	// Admin.
	alice, bob, carol ids.UUID
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	p := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(p); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{pool: d.AppPool(t), org: ids.New[ids.Org](), alice: ids.NewV7(), bob: ids.NewV7(), carol: ids.NewV7()}
	e.reqs = &requests{opened: map[ids.UUID]protect.Request{}, voided: map[ids.UUID]string{}}
	e.gate = &protect.Gate{Requests: e.reqs}
	e.store = &idps.Store{
		Envelope:   pccrypto.NewEnvelope(keystore.NewDEKStore(e.pool, kp)),
		Deployment: []idps.Deployment{{Name: "corp", Issuer: corpIssuer}},
	}
	e.notes = &notes{t: t}
	e.edition = &edition{e: billing.Enterprise}
	e.svc = &idps.Service{Pool: e.pool, Store: e.store, Gate: e.gate, Editions: e.edition, Notify: e.notes}
	e.svc.Register(e.gate)
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'idps')", e.org)
	for _, u := range []struct {
		id     ids.UUID
		issuer string
		role   td.RoleName
	}{{e.alice, orgIssuer, td.RoleOrgAdmin}, {e.bob, corpIssuer, td.RoleOrgAdmin}, {e.carol, corpIssuer, td.RoleSecurityAdmin}} {
		e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, $4)", e.org, u.id, u.issuer, u.id.String())
		e.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			e.org, ids.NewV7(), string(u.role), u.id)
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

func (e *env) as(user ids.UUID, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredBrowserSession})
}

func (e *env) admin(user ids.UUID) context.Context { return e.as(user, td.RoleOrgAdmin) }

// confirm applies a filed change as user (the change ceremony's Apply).
func (e *env) confirm(t *testing.T, f idps.Filed, user ids.UUID) error {
	t.Helper()
	return e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.gate.Apply(ctx, tx, f.Request, []ids.UUID{user})
	})
}

func (e *env) change(t *testing.T, id ids.UUID) dbq.PcProtectedChange {
	t.Helper()
	var out dbq.PcProtectedChange
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetProtectedChange(ctx, e.org, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func input(name string) idps.Input {
	return idps.Input{Name: name, Issuer: orgIssuer, ClientID: "pc-client", ClientSecret: pclog.NewSecret([]byte("s3cr3t-value-for-test"))}
}

// active creates the org's provider and has bob confirm it.
func (e *env) active(t *testing.T, name string) idps.Provider {
	t.Helper()
	p, f, err := e.svc.Create(e.admin(e.alice), input(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(t, f, e.bob); err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *env) resolved(t *testing.T, r *idps.Resolver, org ids.OrgID) []string {
	t.Helper()
	own, _, err := r.OrgProviders(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range own {
		names = append(names, p.Name())
	}
	return names
}

// TestHR481_ProtectedInEveryMode: creating, changing, disabling a provider
// and the own-providers-only setting each wait for a second person
// holding identity_provider.manage, with CUSTODY off and on; the author
// can't confirm their own; nothing signs in before the confirmation; every
// org admin is told when a change is filed and when it applies; a Security
// Admin and a service account can't file one (G0 M18 D155, D161, D162).
//
// Covers: PN-012.7
func TestHR481_ProtectedInEveryMode(t *testing.T) {
	for _, mode := range []protect.Mode{protect.ModeOff, protect.ModeDistinctPublisher} {
		t.Run(string(mode), func(t *testing.T) {
			e := newEnv(t)
			if mode == protect.ModeDistinctPublisher {
				e.exec(t, `INSERT INTO pc.protected_change_settings (org_id, category, mode, updated_by) VALUES ($1, 'CUSTODY', $2, $3)`,
					e.org, string(mode), e.alice)
			}
			r := &idps.Resolver{Pool: e.pool, Store: e.store}
			p, f, err := e.svc.Create(e.admin(e.alice), input("acme"))
			if err != nil {
				t.Fatal(err)
			}
			if p.State != idps.StatePending || len(e.resolved(t, r, e.org)) != 0 {
				t.Fatalf("a provider signs in before its confirmation: %+v", p)
			}
			ch := e.change(t, f.Change)
			if ch.State != protect.StatePending || ch.Category != string(protect.Custody) || ch.Surface != string(protect.SurfaceIdentityProviderPut) {
				t.Fatalf("filed change: %+v", ch)
			}
			n := e.notes.last()
			if n.Type != "identity_provider.change_requested" || !slices.Contains(n.Personal, e.alice) || !slices.Contains(n.Personal, e.bob) ||
				n.Params["request"] != f.Request.String() {
				t.Fatalf("admins not told of the request: %+v", n)
			}
			if err := e.confirm(t, f, e.alice); err == nil {
				t.Fatal("the author confirmed their own change")
			}
			if err := e.confirm(t, f, e.bob); err != nil {
				t.Fatal(err)
			}
			if got := e.resolved(t, r, e.org); !slices.Equal(got, []string{"acme"}) {
				t.Fatalf("confirmed provider not resolved: %v", got)
			}
			if n := e.notes.last(); n.Type != "identity_provider.change_applied" || n.Params["publisher"] != e.bob.String() ||
				!slices.Contains(n.Personal, e.alice) || !slices.Contains(n.Personal, e.bob) {
				t.Fatalf("admins not told of the applied change: %+v", n)
			}

			// A change and a disable are protected the same way.
			in := input("acme")
			in.TrustEmail = true
			f2, err := e.svc.Update(e.admin(e.bob), p.ID, in)
			if err != nil {
				t.Fatal(err)
			}
			if got, _ := e.svc.Get(e.as(e.carol, td.RoleSecurityAdmin), p.ID); got.TrustEmail {
				t.Fatal("a change applied before its confirmation")
			}
			f3, err := e.svc.Disable(e.admin(e.bob), p.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got := e.resolved(t, r, e.org); len(got) != 1 {
				t.Fatalf("a disable applied before its confirmation: %v", got)
			}
			for _, f := range []idps.Filed{f2, f3} {
				if c := e.change(t, f.Change); c.State != protect.StatePending {
					t.Fatalf("not held: %+v", c)
				}
			}
			f4, err := e.svc.SetOwnOnly(e.admin(e.alice), true)
			if err != nil {
				t.Fatal(err)
			}
			if c := e.change(t, f4.Change); c.State != protect.StatePending || c.Surface != string(protect.SurfaceIdentityProviderOwnOnly) {
				t.Fatalf("own providers only not held: %+v", c)
			}

			// Only a person holding identity_provider.manage files one.
			if _, _, err := e.svc.Create(e.as(e.carol, td.RoleSecurityAdmin), input("other")); err == nil {
				t.Fatal("a Security Admin filed a provider")
			}
			sa := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
				Org: e.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
				Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
			}, Credential: tapp.CredAccessToken})
			if _, _, err := e.svc.Create(sa, input("robot")); !errors.Is(err, idps.ErrHuman) {
				t.Fatalf("a service account filed a provider: %v", err)
			}
		})
	}
	for _, s := range []protect.Surface{
		protect.SurfaceIdentityProviderPut, protect.SurfaceIdentityProviderDisable, protect.SurfaceIdentityProviderOwnOnly,
	} {
		if !s.AlwaysProtected() || s.Permission() != td.PermIdentityProviderManage {
			t.Errorf("%s: always %v, permission %s", s, s.AlwaysProtected(), s.Permission())
		}
	}
}

// TestHR482_SecretSealed: the client secret is stored sealed with the
// org's DEK, bound to its row, is in no protected change's payload or
// summary in the clear, and is never returned (G0 M18 D155).
//
// Covers: PN-012.7
func TestHR482_SecretSealed(t *testing.T) {
	e := newEnv(t)
	in := input("acme")
	p, f, err := e.svc.Create(e.admin(e.alice), in)
	if err != nil {
		t.Fatal(err)
	}
	upd := input("acme")
	upd.ClientSecret = pclog.NewSecret([]byte("an0ther-s3cr3t-value"))
	f2, err := e.svc.Update(e.admin(e.alice), p.ID, upd)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT client_secret FROM pc.org_identity_providers WHERE id = $1", p.ID).Scan(&sealed)
	}); err != nil {
		t.Fatal(err)
	}
	for _, plain := range [][]byte{in.ClientSecret.Reveal(), upd.ClientSecret.Reveal()} {
		if bytes.Contains(sealed, plain) {
			t.Fatal("the stored secret is in the clear")
		}
		for _, id := range []ids.UUID{f.Change, f2.Change} {
			c := e.change(t, id)
			if bytes.Contains(c.Payload, plain) || bytes.Contains(c.Summary, plain) {
				t.Fatalf("a protected change carries the secret in the clear: %s", c.Payload)
			}
		}
	}
	// The sealed blob is bound to its row: moved to another provider it
	// doesn't open, so a resolver leaves that provider out.
	other := e.active(t, "other")
	e.exec(t, "UPDATE pc.org_identity_providers SET client_secret = $2 WHERE id = $1", other.ID, sealed)
	r := &idps.Resolver{Pool: e.pool, Store: e.store}
	if got := e.resolved(t, r, e.org); slices.Contains(got, "other") {
		t.Fatal("a secret sealed for another provider opened")
	}
	// Nothing a reader gets carries it.
	ps, _, err := e.svc.List(e.as(e.carol, td.RoleSecurityAdmin))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ps)
	if bytes.Contains(b, in.ClientSecret.Reveal()) || bytes.Contains(b, sealed) {
		t.Fatal("a listing returned the secret")
	}
}

// TestHR483_PrivateIssuersRefused: http, loopback and private issuers are
// refused before anything is stored, and the creation probe reads the
// discovery document through the egress guard (G0 M18 D155).
//
// Covers: PN-012.7
func TestHR483_PrivateIssuersRefused(t *testing.T) {
	e := newEnv(t)
	for _, iss := range []string{"http://idp.example.com", "https://127.0.0.1", "https://10.0.0.5", "https://localhost", "https://169.254.169.254"} {
		in := input("acme")
		in.Issuer = iss
		if _, _, err := e.svc.Create(e.admin(e.alice), in); !errors.Is(err, idps.ErrInvalid) {
			t.Errorf("%s: %v", iss, err)
		}
	}
	e.svc.Probe = idps.DiscoveryProbe(nil)
	in := input("acme")
	in.Issuer = "https://pantherclaw-probe.invalid"
	if _, _, err := e.svc.Create(e.admin(e.alice), in); !errors.Is(err, idps.ErrDiscovery) {
		t.Fatalf("an unreachable issuer: %v", err)
	}
	if ps, _, _ := e.svc.List(e.admin(e.alice)); len(ps) != 0 {
		t.Fatalf("refused providers were stored: %+v", ps)
	}
}

// TestHR484_LastAdminPathKept: disabling the last provider an admin signs
// in with, or turning own-providers-only on with no admin left a path, is
// refused when filed and again when confirmed; a change that strands one
// of two admins is filed with that admin listed in the request and the
// notification (G0 M18 D155, D162).
//
// Covers: PN-012.7
func TestHR484_LastAdminPathKept(t *testing.T) {
	e := newEnv(t)
	p := e.active(t, "acme")

	// Disabling acme strands alice (bob still has corp): filed, listed.
	f, err := e.svc.Disable(e.admin(e.bob), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.Stranded, []ids.UUID{e.alice}) {
		t.Fatalf("stranded %v, want alice", f.Stranded)
	}
	if got := e.reqs.get(f.Request).Summary["stranded_admins"]; got != e.alice.String() {
		t.Fatalf("the request lists %q", got)
	}
	if got := e.notes.last().Params["stranded"]; !strings.Contains(got, e.alice.String()) {
		t.Fatalf("the notification lists %q", got)
	}

	// Own providers only would strand bob, but alice keeps acme: filed.
	f2, err := e.svc.SetOwnOnly(e.admin(e.alice), true)
	if err != nil || !slices.Equal(f2.Stranded, []ids.UUID{e.bob}) {
		t.Fatalf("own only: %v %v", f2.Stranded, err)
	}
	// Confirm the disable first: now own-only would leave nobody.
	if err := e.confirm(t, f, e.alice); err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(t, f2, e.bob); !errors.Is(err, idps.ErrLockOut) {
		t.Fatalf("own only confirmed with no admin left: %v", err)
	}
	if _, err := e.svc.SetOwnOnly(e.admin(e.alice), true); !errors.Is(err, idps.ErrLockOut) {
		t.Fatalf("own only filed with no admin left: %v", err)
	}

	// With only alice able to sign in, she can't disable her only provider.
	e2 := newEnv(t)
	e2.store.Deployment = nil // bob signs in through nothing left
	q := e2.active(t, "acme")
	if _, err := e2.svc.Disable(e2.admin(e2.alice), q.ID); !errors.Is(err, idps.ErrLockOut) {
		t.Fatalf("the last provider was filed for disabling: %v", err)
	}
}

// fakeIssuer serves an OpenID discovery document for orgIssuer over TLS;
// the client it returns reaches it whatever host it dials.
func fakeIssuer(t *testing.T) *http.Client {
	t.Helper()
	doc := map[string]any{
		"issuer": orgIssuer, "authorization_endpoint": orgIssuer + "/auth", "token_endpoint": orgIssuer + "/token",
		"jwks_uri": orgIssuer + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, doc)
	}))
	t.Cleanup(srv.Close)
	c := srv.Client()
	tr := c.Transport.(*http.Transport).Clone()
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // G402: the test server stands in for idp.example.com
	c.Transport = tr
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// TestD161_DowngradeKeepsSignIn: after a downgrade below Enterprise an
// ACTIVE provider still starts a sign-in to its org; creating, changing
// and confirming a pending activation are refused, while disabling and
// reading still work (G0 M18 D161).
//
// Covers: PN-012.7
func TestD161_DowngradeKeepsSignIn(t *testing.T) {
	e := newEnv(t)
	p := e.active(t, "acme")
	_, pending, err := e.svc.Create(e.admin(e.alice), input("later"))
	if err != nil {
		t.Fatal(err)
	}
	e.edition.e = billing.Community

	r := &idps.Resolver{Pool: e.pool, Store: e.store, HTTPClient: fakeIssuer(t)}
	b := authnapp.NewBrowser(e.pool, "https://pc.example.test", nil, clock.System{}, nil).WithOrgProviders(r)
	red, err := b.Start(context.Background(), authnapp.BrowserStart{Org: e.org.String(), Provider: "acme"})
	if err != nil || !strings.HasPrefix(red.URL, orgIssuer+"/auth?") {
		t.Fatalf("a downgraded org's active provider no longer signs in: %q %v", red.URL, err)
	}

	if _, _, err := e.svc.Create(e.admin(e.alice), input("new")); !errors.Is(err, idps.ErrEdition) {
		t.Fatalf("create below Enterprise: %v", err)
	}
	if _, err := e.svc.Update(e.admin(e.alice), p.ID, input("acme")); !errors.Is(err, idps.ErrEdition) {
		t.Fatalf("change below Enterprise: %v", err)
	}
	if err := e.confirm(t, pending, e.bob); !errors.Is(err, idps.ErrEdition) {
		t.Fatalf("activation confirmed below Enterprise: %v", err)
	}
	if ps, _, err := e.svc.List(e.as(e.carol, td.RoleSecurityAdmin)); err != nil || len(ps) != 2 {
		t.Fatalf("read below Enterprise: %v %v", ps, err)
	}
	f, err := e.svc.Disable(e.admin(e.bob), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(t, f, e.alice); err != nil {
		t.Fatalf("disable below Enterprise: %v", err)
	}
	if got := e.resolved(t, r, e.org); len(got) != 0 {
		t.Fatalf("a disabled provider still resolves: %v", got)
	}
}

// TestT207_ProviderTakeover: an admin can't swap the issuer of a provider
// that has been active, take a deployment provider's name, or have a
// provider confirmed for a state it no longer has; another org never
// resolves it (G0 M18 D155).
//
// Covers: PN-012.7
func TestT207_ProviderTakeover(t *testing.T) {
	e := newEnv(t)
	p := e.active(t, "acme")
	swap := input("acme")
	swap.Issuer = "https://evil.example.net"
	if _, err := e.svc.Update(e.admin(e.alice), p.ID, swap); !errors.Is(err, idps.ErrIssuerFixed) {
		t.Fatalf("issuer swap: %v", err)
	}
	// Even a stored change can't swap it when applied.
	err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.store.Put(ctx, tx, tapp.Caller{}.Actor(), e.alice, p.ID, idps.Change{Name: "acme", Issuer: swap.Issuer, ClientID: "c"})
	})
	if !errors.Is(err, idps.ErrIssuerFixed) {
		t.Fatalf("stored issuer swap: %v", err)
	}
	if _, _, err := e.svc.Create(e.admin(e.alice), input("corp")); !errors.Is(err, idps.ErrNameTaken) {
		t.Fatalf("a deployment provider's name: %v", err)
	}

	// A change filed against one state voids when the provider changed.
	ch := input("acme")
	ch.ClientID = "attacker-client"
	f, err := e.svc.Update(e.admin(e.alice), p.ID, ch)
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.svc.Disable(e.admin(e.alice), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(t, d, e.bob); err != nil {
		t.Fatal(err)
	}
	var void *protect.VoidError
	if err := e.confirm(t, f, e.bob); !errors.As(err, &void) || void.VoidReason() != protect.ReasonSubjectChanged {
		t.Fatalf("a change confirmed after its provider changed: %v", err)
	}

	// Another org resolves none of ours.
	other := ids.New[ids.Org]()
	if err := e.pool.InTenantTx(context.Background(), other, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", other)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e2 := e.active(t, "acme2")
	r := &idps.Resolver{Pool: e.pool, Store: e.store}
	if got := e.resolved(t, r, other); len(got) != 0 {
		t.Fatalf("another org resolved %v (%s)", got, e2.ID)
	}
}
