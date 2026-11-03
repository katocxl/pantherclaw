// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/idaccess/app"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The admin flows (G0 M26 D400-D402, D408; HR-623): each addition is a
// two-person protected change filed only by a person holding
// identity_provider.manage, in a paid edition, audited and told to every
// org admin; each removal applies at once and is audited; nothing crosses
// to another org.

// adminRequests is an in-memory change ceremony.
type adminRequests struct {
	mu     sync.Mutex
	opened map[ids.UUID]protect.Request
}

func (r *adminRequests) Open(_ context.Context, _ db.TenantTx, q protect.Request) (ids.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := ids.NewV7()
	r.opened[id] = q
	return id, nil
}

func (r *adminRequests) Void(context.Context, db.TenantTx, ids.UUID, string) error { return nil }

func (r *adminRequests) Pending(_ context.Context, _ db.TenantTx, id ids.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.opened[id]
	return ok, nil
}

// adminNotes records notifications after checking they render.
type adminNotes struct {
	t    *testing.T
	mu   sync.Mutex
	sent []napp.Message
}

func (n *adminNotes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	if _, err := ndomain.Render(m.Type, m.Params); err != nil {
		n.t.Errorf("%s does not render: %v", m.Type, err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sent = append(n.sent, m)
	return napp.Enqueued{}, nil
}

func (n *adminNotes) last() napp.Message {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.sent) == 0 {
		return napp.Message{}
	}
	return n.sent[len(n.sent)-1]
}

type adminEdition struct{ e billing.Edition }

func (e *adminEdition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

// adminOrg is one org: alice and bob are org admins, carol a Security
// Admin, agent an agent.
type adminOrg struct {
	org               ids.OrgID
	alice, bob, carol ids.UUID
	agent             ids.UUID
}

type adminEnv struct {
	pool    *db.Pool
	gate    *protect.Gate
	svc     *app.Admin
	notes   *adminNotes
	edition *adminEdition
	a, b    adminOrg
}

func newAdminEnv(t *testing.T) *adminEnv {
	t.Helper()
	e := &adminEnv{pool: dbtest.New(t).AppPool(t), notes: &adminNotes{t: t}, edition: &adminEdition{e: billing.Enterprise}}
	e.gate = &protect.Gate{Requests: &adminRequests{opened: map[ids.UUID]protect.Request{}}}
	e.svc = &app.Admin{Pool: e.pool, Gate: e.gate, Editions: e.edition, Notify: e.notes, PublicURL: publicURL, Documents: docs{}}
	for _, u := range []string{
		"https://editor.example/oauth/client.json", "https://second.example/c.json", "https://other.example/c.json",
	} {
		e.svc.Documents.(docs)[u] = ports.ClientMetadata{ClientID: u, Name: "Editor", RedirectURIs: []string{"http://127.0.0.1:4567/callback"}}
	}
	e.svc.Register(e.gate)
	e.a, e.b = e.newOrg(t), e.newOrg(t)
	return e
}

func (e *adminEnv) newOrg(t *testing.T) adminOrg {
	t.Helper()
	o := adminOrg{org: ids.New[ids.Org](), alice: ids.NewV7(), bob: ids.NewV7(), carol: ids.NewV7(), agent: ids.NewV7()}
	team, env := ids.NewV7(), ids.NewV7()
	e.exec(t, o.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'm26-admin')", o.org)
	for _, u := range []struct {
		id   ids.UUID
		role td.RoleName
	}{{o.alice, td.RoleOrgAdmin}, {o.bob, td.RoleOrgAdmin}, {o.carol, td.RoleSecurityAdmin}} {
		e.exec(t, o.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.example.com', $3)", o.org, u.id, u.id.String())
		e.exec(t, o.org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			o.org, ids.NewV7(), string(u.role), u.id)
	}
	e.exec(t, o.org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", o.org, team)
	e.exec(t, o.org, `INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')`,
		o.org, env, team)
	e.exec(t, o.org, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by,
		claimed_at) VALUES ($1, $2, 'coder', $3, $4, $5, 'ci', 'CLAIMED', 'test', now())`, o.org, o.agent, team, env, o.alice)
	return o
}

func (e *adminEnv) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *adminEnv) count(t *testing.T, org ids.OrgID, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *adminEnv) str(t *testing.T, org ids.OrgID, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := e.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&s)
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *adminEnv) audits(t *testing.T, org ids.OrgID, name string) int {
	t.Helper()
	return e.count(t, org, "SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = $2", org, "audit."+name)
}

func as(o adminOrg, user ids.UUID, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: o.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: o.org.UUID()}}},
	}, Credential: tapp.CredBrowserSession})
}

func admin(o adminOrg, user ids.UUID) context.Context { return as(o, user, td.RoleOrgAdmin) }

// robot is an org-admin service account of o.
func robot(o adminOrg) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: o.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: o.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
}

func (e *adminEnv) confirm(o adminOrg, f app.Filed, user ids.UUID) error {
	return e.pool.InTenantTx(context.Background(), o.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.gate.Apply(ctx, tx, f.Request, []ids.UUID{user})
	})
}

func (e *adminEnv) decline(t *testing.T, o adminOrg, f app.Filed) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), o.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.gate.Closed(ctx, tx, f.Request, changes.StateDeclined, "DECLINED")
	}); err != nil {
		t.Fatal(err)
	}
}

// filed checks a held change of surface and the request told to o's admins.
func (e *adminEnv) filed(t *testing.T, o adminOrg, f app.Filed, surface protect.Surface) {
	t.Helper()
	if s := e.str(t, o.org, "SELECT state || '/' || category || '/' || surface FROM pc.protected_changes WHERE id = $1", f.Change); s !=
		protect.StatePending+"/"+string(protect.Custody)+"/"+string(surface) {
		t.Fatalf("filed change: %s", s)
	}
	n := e.notes.last()
	if n.Type != "idaccess.change_requested" || n.Org != o.org || !slices.Contains(n.Personal, o.alice) || !slices.Contains(n.Personal, o.bob) ||
		n.Params["request"] != f.Request.String() {
		t.Fatalf("admins not told of the request: %+v", n)
	}
}

// applied checks the change applied by publisher and the admins were told.
func (e *adminEnv) applied(t *testing.T, o adminOrg, f app.Filed, publisher ids.UUID) {
	t.Helper()
	if s := e.str(t, o.org, "SELECT state FROM pc.protected_changes WHERE id = $1", f.Change); s != protect.StateApplied {
		t.Fatalf("change %s", s)
	}
	if n := e.notes.last(); n.Type != "idaccess.change_applied" || n.Params["publisher"] != publisher.String() {
		t.Fatalf("admins not told of the applied change: %+v", n)
	}
}

// refusedCallers checks that a Security Admin, a service account and an
// unpaid edition file nothing through file.
func (e *adminEnv) refusedCallers(t *testing.T, o adminOrg, file func(context.Context) error) {
	t.Helper()
	before := e.count(t, o.org, "SELECT count(*) FROM pc.protected_changes")
	if err := file(as(o, o.carol, td.RoleSecurityAdmin)); err == nil {
		t.Error("a Security Admin filed an addition")
	}
	if err := file(robot(o)); !errors.Is(err, app.ErrHuman) {
		t.Errorf("a service account filed an addition: %v", err)
	}
	e.edition.e = billing.Community
	if err := file(admin(o, o.alice)); !errors.Is(err, app.ErrEdition) {
		t.Errorf("the free edition filed an addition: %v", err)
	}
	e.edition.e = billing.Enterprise
	if n := e.count(t, o.org, "SELECT count(*) FROM pc.protected_changes"); n != before {
		t.Fatalf("refused callers filed %d changes", n-before)
	}
}

func issuerInput(issuer string) app.IssuerInput {
	return app.IssuerInput{Name: "okta", Issuer: issuer, Algorithms: []string{"RS256"}}
}

// TestHR623_AnIssuerIsATwoPersonChange: only a person holding
// identity_provider.manage in a paid edition files an issuer; it stays
// PENDING until a second person confirms; filing and applying are audited
// and told to every org admin; a confirmation needs the edition again;
// disabling applies at once; a declined issuer lapses; another org sees and
// touches none of it.
//
// Covers: F911
func TestHR623_AnIssuerIsATwoPersonChange(t *testing.T) {
	e := newAdminEnv(t)
	a, b := e.a, e.b
	e.refusedCallers(t, a, func(ctx context.Context) error {
		_, _, err := e.svc.CreateIssuer(ctx, issuerInput("https://acme.okta.com"))
		return err
	})

	iss, f, err := e.svc.CreateIssuer(admin(a, a.alice), issuerInput("https://acme.okta.com"))
	if err != nil || iss.State != "PENDING" || iss.Audience != publicURL+"/orgs/"+a.org.String() {
		t.Fatalf("create: %+v %v", iss, err)
	}
	e.filed(t, a, f, protect.SurfaceAssertionIssuer)
	if e.audits(t, a.org, "protected_change.requested") != 1 {
		t.Fatal("the request is not audited")
	}
	if err := e.confirm(a, f, a.alice); err == nil {
		t.Fatal("the author confirmed their own issuer")
	}
	if err := e.confirm(a, f, a.bob); err != nil {
		t.Fatal(err)
	}
	e.applied(t, a, f, a.bob)
	if s := e.str(t, a.org, "SELECT state FROM pc.org_assertion_issuers WHERE id = $1", iss.ID); s != "ACTIVE" {
		t.Fatalf("issuer %s", s)
	}
	if e.audits(t, a.org, "protected_change.applied") != 1 {
		t.Fatal("the application is not audited")
	}

	// The edition is checked again when a change applies.
	_, f2, err := e.svc.CreateIssuer(admin(a, a.alice), app.IssuerInput{Name: "okta-two", Issuer: "https://acme2.okta.com", Algorithms: []string{"RS256"}})
	if err != nil {
		t.Fatal(err)
	}
	e.edition.e = billing.Community
	if err := e.confirm(a, f2, a.bob); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("applied without the edition: %v", err)
	}
	e.edition.e = billing.Enterprise
	e.decline(t, a, f2)
	if e.count(t, a.org, "SELECT count(*) FROM pc.org_assertion_issuers WHERE issuer = 'https://acme2.okta.com' AND state = 'DISABLED'") != 1 ||
		e.audits(t, a.org, "idaccess.lapsed") != 1 {
		t.Fatal("a declined issuer did not lapse")
	}

	// Another org sees nothing and can disable nothing.
	if l, err := e.svc.ListIssuers(admin(b, b.alice)); err != nil || len(l) != 0 {
		t.Fatalf("another org lists %d issuers: %v", len(l), err)
	}
	if _, err := e.svc.DisableIssuer(admin(b, b.alice), iss.ID); !errors.Is(err, app.ErrFound) {
		t.Fatalf("another org disabled an issuer: %v", err)
	}
	if _, err := e.svc.DisableIssuer(robot(a), iss.ID); !errors.Is(err, app.ErrHuman) {
		t.Fatalf("a service account disabled an issuer: %v", err)
	}

	// Disabling applies at once, in any edition.
	e.edition.e = billing.Community
	if d, err := e.svc.DisableIssuer(admin(a, a.bob), iss.ID); err != nil || d.State != "DISABLED" {
		t.Fatalf("disable: %+v %v", d, err)
	}
	if e.audits(t, a.org, "idaccess.issuer_disabled") != 1 || e.notes.last().Type != "idaccess.removed" {
		t.Fatal("the disable is not audited or told")
	}
}

// TestHR623_AClientBindingIsATwoPersonChange: a binding of an issuer's
// client id to an agent is filed, confirmed and removed like an issuer; it
// is never re-pointed; another org can bind neither the issuer nor the
// agent.
//
// Covers: F911
func TestHR623_AClientBindingIsATwoPersonChange(t *testing.T) {
	e := newAdminEnv(t)
	a, b := e.a, e.b
	iss, fi, err := e.svc.CreateIssuer(admin(a, a.alice), issuerInput("https://acme.okta.com"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(a, fi, a.bob); err != nil {
		t.Fatal(err)
	}
	e.refusedCallers(t, a, func(ctx context.Context) error {
		_, _, err := e.svc.BindClient(ctx, iss.ID, "0oa-client", a.agent)
		return err
	})

	bind, f, err := e.svc.BindClient(admin(a, a.alice), iss.ID, "0oa-client", a.agent)
	if err != nil || bind.State != "PENDING" {
		t.Fatalf("bind: %+v %v", bind, err)
	}
	e.filed(t, a, f, protect.SurfaceAssertionClient)
	if err := e.confirm(a, f, a.alice); err == nil {
		t.Fatal("the author confirmed their own binding")
	}
	if err := e.confirm(a, f, a.bob); err != nil {
		t.Fatal(err)
	}
	e.applied(t, a, f, a.bob)
	if s := e.str(t, a.org, "SELECT state FROM pc.org_assertion_clients WHERE id = $1", bind.ID); s != "ACTIVE" {
		t.Fatalf("binding %s", s)
	}
	if _, _, err := e.svc.BindClient(admin(a, a.alice), iss.ID, "0oa-client", a.agent); !errors.Is(err, app.ErrState) {
		t.Fatalf("a client id bound twice: %v", err)
	}

	// Another org binds neither this org's issuer nor its agent.
	if _, _, err := e.svc.BindClient(admin(b, b.alice), iss.ID, "0oa-other", b.agent); !errors.Is(err, app.ErrFound) {
		t.Fatalf("another org bound to this org's issuer: %v", err)
	}
	if l, err := e.svc.ListClients(admin(b, b.alice), iss.ID); err != nil || len(l) != 0 {
		t.Fatalf("another org lists %d bindings: %v", len(l), err)
	}
	if _, err := e.svc.RemoveClient(admin(b, b.alice), bind.ID); !errors.Is(err, app.ErrFound) {
		t.Fatalf("another org removed a binding: %v", err)
	}

	// A declined binding lapses; removal applies at once.
	b2, f2, err := e.svc.BindClient(admin(a, a.alice), iss.ID, "0oa-second", a.agent)
	if err != nil {
		t.Fatal(err)
	}
	e.decline(t, a, f2)
	if s := e.str(t, a.org, "SELECT state FROM pc.org_assertion_clients WHERE id = $1", b2.ID); s != "REMOVED" {
		t.Fatalf("a declined binding is %s", s)
	}
	if r, err := e.svc.RemoveClient(admin(a, a.bob), bind.ID); err != nil || r.State != "REMOVED" {
		t.Fatalf("remove: %+v %v", r, err)
	}
	if e.audits(t, a.org, "idaccess.client_removed") != 1 {
		t.Fatal("the removal is not audited")
	}
}

// TestHR623_TurningMcpAuthorizationOnIsATwoPersonChange: the opt-in is off
// by default, is filed and confirmed like an addition, needs the edition
// when it applies, and turns off at once; another org's setting is its own.
//
// Covers: F912
func TestHR623_TurningMcpAuthorizationOnIsATwoPersonChange(t *testing.T) {
	e := newAdminEnv(t)
	a, b := e.a, e.b
	if m, err := e.svc.GetMcpAccess(admin(a, a.alice)); err != nil || m.Enabled {
		t.Fatalf("on by default: %+v %v", m, err)
	}
	e.refusedCallers(t, a, func(ctx context.Context) error {
		_, err := e.svc.EnableMcpAccess(ctx, "https://gw.example.com")
		return err
	})
	if _, err := e.svc.EnableMcpAccess(admin(a, a.alice), "https://127.0.0.1:8443"); !errors.Is(err, app.ErrURL) {
		t.Fatalf("a loopback gateway: %v", err)
	}

	f, err := e.svc.EnableMcpAccess(admin(a, a.alice), "https://gw.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	e.filed(t, a, f, protect.SurfaceMcpAccess)
	if m, _ := e.svc.GetMcpAccess(admin(a, a.alice)); m.Enabled {
		t.Fatal("on before its confirmation")
	}
	e.edition.e = billing.Community
	if err := e.confirm(a, f, a.bob); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("applied without the edition: %v", err)
	}
	e.edition.e = billing.Enterprise
	if err := e.confirm(a, f, a.alice); err == nil {
		t.Fatal("the author confirmed their own opt-in")
	}
	if err := e.confirm(a, f, a.bob); err != nil {
		t.Fatal(err)
	}
	e.applied(t, a, f, a.bob)
	if m, err := e.svc.GetMcpAccess(admin(a, a.alice)); err != nil || !m.Enabled || m.GatewayURL != "https://gw.example.com" ||
		m.Issuer != publicURL+"/orgs/"+a.org.String() {
		t.Fatalf("after the confirmation: %+v %v", m, err)
	}

	// Another org's setting is its own, and it can't turn this one off.
	if m, err := e.svc.GetMcpAccess(admin(b, b.alice)); err != nil || m.Enabled {
		t.Fatalf("another org sees the opt-in: %+v %v", m, err)
	}
	if _, err := e.svc.DisableMcpAccess(admin(b, b.alice)); err != nil {
		t.Fatal(err)
	}
	if m, _ := e.svc.GetMcpAccess(admin(a, a.alice)); !m.Enabled {
		t.Fatal("another org turned the opt-in off")
	}
	if _, err := e.svc.DisableMcpAccess(robot(a)); !errors.Is(err, app.ErrHuman) {
		t.Fatalf("a service account turned it off: %v", err)
	}

	// Off applies at once, in any edition.
	e.edition.e = billing.Community
	if _, err := e.svc.DisableMcpAccess(admin(a, a.bob)); err != nil {
		t.Fatal(err)
	}
	if m, _ := e.svc.GetMcpAccess(admin(a, a.alice)); m.Enabled {
		t.Fatal("still on")
	}
	if e.audits(t, a.org, "idaccess.mcp_access_disabled") != 1 {
		t.Fatal("turning it off is not audited")
	}
}

// TestHR625_AnAllowListedClientIsATwoPersonChange: an MCP client is filed
// with its own mcp_client instance waiting for admission; only the
// confirmation admits it; a declined client lapses and its instance is
// revoked; removal revokes the instance at once; another org touches
// neither the client nor the agent.
//
// Covers: F913
func TestHR625_AnAllowListedClientIsATwoPersonChange(t *testing.T) {
	e := newAdminEnv(t)
	a, b := e.a, e.b
	const clientURL = "https://editor.example/oauth/client.json"
	e.refusedCallers(t, a, func(ctx context.Context) error {
		_, _, err := e.svc.AllowMcpClient(ctx, clientURL, a.agent)
		return err
	})
	if _, _, err := e.svc.AllowMcpClient(admin(a, a.alice), "https://editor.example", a.agent); !errors.Is(err, app.ErrURL) {
		t.Fatalf("a client URL with no path: %v", err)
	}

	c, f, err := e.svc.AllowMcpClient(admin(a, a.alice), clientURL, a.agent)
	if err != nil || c.State != "PENDING" || c.ClientName != "Editor" || !slices.Equal(c.RedirectUris, []string{"http://127.0.0.1:4567/callback"}) ||
		len(c.DocumentDigest) != 32 {
		t.Fatalf("allow: %+v %v", c, err)
	}
	e.filed(t, a, f, protect.SurfaceMcpClient)
	// The confirming person sees the document's name and redirect URIs.
	if s := e.str(t, a.org, "SELECT summary->>'client_name' || '|' || (summary->>'redirect_uris') FROM pc.protected_changes WHERE id = $1",
		f.Change); s != "Editor|http://127.0.0.1:4567/callback" {
		t.Fatalf("the change summary: %s", s)
	}
	// The waitlist never admits a client's instance, even before its deadline.
	var admitted int64
	if err := e.pool.InTenantTx(context.Background(), a.org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "UPDATE pc.agent_instances SET expires_at = now() + interval '1 day' WHERE id = $1", c.InstanceID); err != nil {
			return err
		}
		by := a.bob.String()
		_, err := dbq.New(tx).AdmitInstance(ctx, &by, a.org, c.InstanceID)
		if db.IsNoRows(err) {
			return nil
		}
		admitted++
		return err
	}); err != nil || admitted != 0 {
		t.Fatalf("the waitlist admitted a client's instance: %v", err)
	}
	instance := func(id ids.UUID) string {
		return e.str(t, a.org, "SELECT state || '/' || enrolled_via FROM pc.agent_instances WHERE id = $1", id)
	}
	if s := instance(c.InstanceID); s != "PENDING_ADMISSION/mcp_client" {
		t.Fatalf("the client's instance before the confirmation: %s", s)
	}
	if err := e.confirm(a, f, a.alice); err == nil {
		t.Fatal("the author confirmed their own client")
	}
	if err := e.confirm(a, f, a.bob); err != nil {
		t.Fatal(err)
	}
	e.applied(t, a, f, a.bob)
	if s := instance(c.InstanceID); s != "ADMITTED/mcp_client" {
		t.Fatalf("the client's instance after the confirmation: %s", s)
	}

	// Another org touches neither this client nor this agent.
	if _, _, err := e.svc.AllowMcpClient(admin(b, b.alice), "https://other.example/c.json", a.agent); !errors.Is(err, app.ErrFound) {
		t.Fatalf("another org allow-listed this org's agent: %v", err)
	}
	if l, err := e.svc.ListMcpClients(admin(b, b.alice)); err != nil || len(l) != 0 {
		t.Fatalf("another org lists %d clients: %v", len(l), err)
	}
	if _, err := e.svc.RemoveMcpClient(admin(b, b.alice), c.ID); !errors.Is(err, app.ErrFound) {
		t.Fatalf("another org removed a client: %v", err)
	}

	// A declined client lapses with its instance.
	c2, f2, err := e.svc.AllowMcpClient(admin(a, a.alice), "https://second.example/c.json", a.agent)
	if err != nil {
		t.Fatal(err)
	}
	e.decline(t, a, f2)
	if s := instance(c2.InstanceID); s != "REVOKED/mcp_client" {
		t.Fatalf("a declined client's instance: %s", s)
	}

	// Removal applies at once and revokes the instance.
	e.edition.e = billing.Community
	if r, err := e.svc.RemoveMcpClient(admin(a, a.bob), c.ID); err != nil || r.State != "REMOVED" {
		t.Fatalf("remove: %+v %v", r, err)
	}
	if s := instance(c.InstanceID); s != "REVOKED/mcp_client" {
		t.Fatalf("a removed client's instance: %s", s)
	}
	if e.audits(t, a.org, "idaccess.mcp_client_removed") != 1 {
		t.Fatal("the removal is not audited")
	}
}

// TestHR625_TakingAChangedDocumentIsATwoPersonChange: an active client's
// changed document is taken only through a new two-person change; until it
// applies the client keeps the confirmed document; the same document is
// not filed again; a declined change leaves the client as it was.
//
// Covers: F913
func TestHR625_TakingAChangedDocumentIsATwoPersonChange(t *testing.T) {
	e := newAdminEnv(t)
	a, b := e.a, e.b
	const clientURL = "https://editor.example/oauth/client.json"
	c, f, err := e.svc.AllowMcpClient(admin(a, a.alice), clientURL, a.agent)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.confirm(a, f, a.bob); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := e.svc.RefreshMcpClientDocument(admin(a, a.alice), c.ID); !errors.Is(err, app.ErrDocumentSame) {
		t.Fatalf("the same document: %v", err)
	}
	d := e.svc.Documents.(docs)
	d[clientURL] = ports.ClientMetadata{ClientID: clientURL, Name: "Editor 2", RedirectURIs: []string{"http://127.0.0.1:4567/callback", "http://127.0.0.1:9/new"}}
	e.refusedCallers(t, a, func(ctx context.Context) error {
		_, _, _, err := e.svc.RefreshMcpClientDocument(ctx, c.ID)
		return err
	})
	if _, _, _, err := e.svc.RefreshMcpClientDocument(admin(b, b.alice), c.ID); !errors.Is(err, app.ErrFound) {
		t.Fatalf("another org refreshed a client: %v", err)
	}
	stored := func() string {
		return e.str(t, a.org, "SELECT client_name || '|' || array_to_string(redirect_uris, ' ') FROM pc.mcp_clients WHERE id = $1", c.ID)
	}

	_, doc, declined, err := e.svc.RefreshMcpClientDocument(admin(a, a.alice), c.ID)
	if err != nil || doc.Name != "Editor 2" {
		t.Fatalf("refresh: %+v %v", doc, err)
	}
	e.filed(t, a, declined, protect.SurfaceMcpClient)
	e.decline(t, a, declined)
	if s := stored(); s != "Editor|http://127.0.0.1:4567/callback" {
		t.Fatalf("after a declined refresh: %s", s)
	}
	if s := e.str(t, a.org, "SELECT state FROM pc.mcp_clients WHERE id = $1", c.ID); s != "ACTIVE" {
		t.Fatalf("a declined refresh changed the client: %s", s)
	}

	_, _, f2, err := e.svc.RefreshMcpClientDocument(admin(a, a.alice), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s := stored(); s != "Editor|http://127.0.0.1:4567/callback" {
		t.Fatalf("before the confirmation: %s", s)
	}
	if err := e.confirm(a, f2, a.alice); err == nil {
		t.Fatal("the author confirmed their own refresh")
	}
	if err := e.confirm(a, f2, a.bob); err != nil {
		t.Fatal(err)
	}
	e.applied(t, a, f2, a.bob)
	if s := stored(); s != "Editor 2|http://127.0.0.1:4567/callback http://127.0.0.1:9/new" {
		t.Fatalf("after the confirmation: %s", s)
	}
	if n := e.audits(t, a.org, "protected_change.applied"); n != 2 {
		t.Fatalf("applied changes audited: %d", n)
	}
}
