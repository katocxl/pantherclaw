// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/app"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/protect"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

const mcpPackage = "acme.mcp-payments"

// requests is an in-memory change ceremony.
type requests struct {
	mu     sync.Mutex
	opened map[ids.UUID]protect.Request
}

func (r *requests) Open(_ context.Context, _ db.TenantTx, q protect.Request) (ids.UUID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := ids.NewV7()
	r.opened[id] = q
	return id, nil
}

func (r *requests) Void(context.Context, db.TenantTx, ids.UUID, string) error { return nil }

func (r *requests) Pending(_ context.Context, _ db.TenantTx, id ids.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, open := r.opened[id]
	return open, nil
}

type edition struct{ e billing.Edition }

func (e *edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: e.e}, nil
}

type person struct {
	id, key, session ids.UUID
	ctx              context.Context
}

type env struct {
	d       *dbtest.DB
	pool    *db.Pool
	org     ids.OrgID
	gateway ids.UUID
	conns   *capp.Service
	gate    *protect.Gate
	svc     *app.Service
	cont    *rapp.Containment
	edition *edition
	// alice and bob are Security Admins with security keys.
	alice, bob person
	admin      context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{d: d, pool: d.AppPool(t), edition: &edition{e: billing.Team}}
	e.gate = &protect.Gate{Requests: &requests{opened: map[ids.UUID]protect.Request{}}}
	e.conns = capp.New(e.pool, nil, "https://pc.example.test", "https://gw.example.test:8443").WithCatalog(app.Gate{})
	e.cont = &rapp.Containment{Pool: e.pool}
	e.svc = &app.Service{Pool: e.pool, Editions: e.edition, Connections: e.conns, Containment: e.cont, Versions: &defspg.Store{Pool: e.pool}}
	e.svc.RegisterProtect(e.gate)
	return e.withOrg(t, "catalog")
}

// withOrg is a new org in the same database.
func (e *env) withOrg(t *testing.T, name string) *env {
	t.Helper()
	o := *e
	o.org, o.gateway = ids.New[ids.Org](), ids.NewV7()
	o.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, $2)", o.org, name)
	o.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", o.org, o.gateway)
	o.pin(t)
	o.alice, o.bob = o.person(t, "alice"), o.person(t, "bob")
	o.admin = o.as(ids.NewV7(), td.RoleGatewayAdmin)
	return &o
}

func (e *env) pin(t *testing.T) {
	t.Helper()
	raw := string(mockpayments.Package)
	for _, r := range [][2]string{
		{"name: " + mockpayments.Name + "\n", "name: " + mcpPackage + "\n"},
		{
			"    dispatch:\n      http:\n        method: GET\n        path: /v1/refunds/{target.id}\n",
			"    dispatch:\n      mcp:\n        tool: get_refund\n        arguments:\n          refund: target.id\n        upstream_digest: sha256:" +
				strings.Repeat("0f", 32) + "\n",
		},
	} {
		if strings.Count(raw, r[0]) != 1 {
			t.Fatalf("mock payments package: %q not found once", r[0])
		}
		raw = strings.Replace(raw, r[0], r[1], 1)
	}
	pkg, ver, b := ids.NewV7(), ids.NewV7(), []byte(raw)
	e.exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, $3)", e.org, pkg, mcpPackage)
	e.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.0.0', $4, $5, 'ACTIVE')`, e.org, ver, pkg, manifest.FileDigest(b), b)
	e.exec(t, "INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, '1.0.0', $4)",
		e.org, pkg, ver, manifest.FileDigest(b))
}

func (e *env) person(t *testing.T, name string) person {
	t.Helper()
	p := person{id: ids.NewV7(), key: ids.NewV7(), session: ids.NewV7()}
	secret := make([]byte, 32)
	copy(secret, p.id[:])
	e.d.AdminExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", e.org, p.id, name)
	e.d.AdminExec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		e.org, ids.NewV7(), string(td.RoleSecurityAdmin), p.id)
	e.d.AdminExec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		e.org, p.key, p.id, secret[:16], secret)
	e.d.AdminExec(t, `INSERT INTO pc.sessions (org_id, id, user_id, secret_hash, provider, auth_time, roles_digest, expires_at)
		VALUES ($1, $2, $3, $4, 'keycloak', now(), $4, now() + interval '12 hours')`, e.org, p.session, p.id, secret)
	e.d.AdminExec(t, "UPDATE pc.sessions SET step_up_at = now(), step_up_credential_id = $1 WHERE id = $2", p.key, p.session)
	p.ctx = tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: td.Subject{
			Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: p.id},
			Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
		},
		Credential: tapp.CredBrowserSession, Session: p.session,
	})
	return p
}

func (e *env) as(user ids.UUID, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
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

func (e *env) int64(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) epoch(t *testing.T) int64 {
	t.Helper()
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org)
	return e.int64(t, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", e.org)
}

// approved proposes and approves a server of a URL host.
func (e *env) approved(t *testing.T, name, host, prefix string) dbq.PcMcpServer {
	t.Helper()
	s, err := e.svc.Propose(e.alice.ctx, domain.Proposal{
		Name: name, Title: name, Transport: domain.TransportHTTP, Spec: domain.Spec{Host: host, PathPrefix: prefix},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err = e.svc.Approve(e.alice.ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *env) create(name, url string) (capp.Connection, error) {
	return e.conns.Create(e.admin, capp.CreateInput{
		Name: name, Kind: capp.KindMCP, Package: mcpPackage, BaseURL: url, Gateway: e.gateway, AccessMode: capp.AccessNone,
	})
}

func (e *env) mustCreate(t *testing.T, name, url string) capp.Connection {
	t.Helper()
	c, err := e.create(name, url)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *env) state(t *testing.T, id ids.UUID) dbq.PcConnection {
	t.Helper()
	var out dbq.PcConnection
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetConnection(ctx, e.org, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *env) enforce(t *testing.T, who person) app.ModeResult {
	t.Helper()
	p, err := e.svc.PreviewMode(who.ctx, domain.ModeEnforce)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.svc.SetMode(who.ctx, domain.ModeEnforce, p.Digest, "turning it on")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// confirm applies a held change as a person (the change ceremony's Apply).
func (e *env) confirm(held *protect.PendingError, who ids.UUID) error {
	return e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return e.gate.Apply(ctx, tx, held.Request, []ids.UUID{who})
	})
}

func (e *env) mode(t *testing.T) domain.Mode {
	t.Helper()
	s, err := e.svc.GetSettings(e.alice.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return domain.Mode(s.Mode)
}

func is(err, want error) bool { return errors.Is(err, want) }

// TestF872_TheCatalogueHoldsProposalsAndDecisions: a server moves from
// proposed to approved or denied, an org sees only its own, the edition and
// the permissions gate it, and the mode starts at WATCH.
//
// Covers: F872
func TestF872_TheCatalogueHoldsProposalsAndDecisions(t *testing.T) {
	e := newEnv(t)
	if m := e.mode(t); m != domain.ModeWatch {
		t.Fatalf("default mode %s", m)
	}
	s, err := e.svc.Propose(e.alice.ctx, domain.Proposal{
		Name: "github", Title: "GitHub", Transport: domain.TransportHTTP, Notes: "needed for reviews", Spec: domain.Spec{Host: "MCP.Example.test:443", PathPrefix: "/gh/"},
	})
	if err != nil || s.Status != string(domain.StatusProposed) || *s.UrlHost != "mcp.example.test" || *s.UrlPathPrefix != "/gh" {
		t.Fatalf("propose: %+v %v", s, err)
	}
	if _, err := e.svc.Propose(e.alice.ctx, domain.Proposal{Name: "github", Title: "again", Transport: domain.TransportHTTP, Spec: domain.Spec{Host: "x.test"}}); !is(err, app.ErrNameUsed) {
		t.Fatalf("a repeated name: %v", err)
	}
	if _, err := e.svc.Propose(e.alice.ctx, domain.Proposal{Name: "wild", Title: "w", Transport: domain.TransportHTTP, Spec: domain.Spec{Host: "*.example.test"}}); !is(err, domain.ErrMatch) {
		t.Fatalf("a wildcard: %v", err)
	}
	if _, err := e.svc.Propose(e.as(ids.NewV7(), td.RoleAuditor), domain.Proposal{Name: "a", Title: "a", Transport: domain.TransportHTTP, Spec: domain.Spec{Host: "x.test"}}); err == nil {
		t.Fatal("an auditor proposed")
	}
	if rows, _, err := e.svc.List(e.as(ids.NewV7(), td.RoleAuditor), 10, "", nil); err != nil || len(rows) != 1 {
		t.Fatalf("an auditor reads: %d %v", len(rows), err)
	}
	other := e.withOrg(t, "other")
	if _, err := other.svc.Get(other.alice.ctx, s.ID); !is(err, app.ErrNotFound) {
		t.Fatalf("another org's server: %v", err)
	}
	if _, err := other.svc.Approve(other.alice.ctx, s.ID); !is(err, app.ErrNotFound) {
		t.Fatalf("another org approved: %v", err)
	}
	if s, err = e.svc.Deny(e.alice.ctx, s.ID); err != nil || s.Status != string(domain.StatusDenied) || s.DecidedAt == nil {
		t.Fatalf("deny: %+v %v", s, err)
	}
	if _, err := e.svc.Deny(e.alice.ctx, s.ID); !is(err, app.ErrStatus) {
		t.Fatalf("deny twice: %v", err)
	}
	if s, err = e.svc.Approve(e.alice.ctx, s.ID); err != nil || s.Status != string(domain.StatusApproved) {
		t.Fatalf("approve: %+v %v", s, err)
	}
	if _, err := e.svc.Deny(e.alice.ctx, s.ID); !is(err, app.ErrStatus) {
		t.Fatalf("denying an approved server: %v", err)
	}
	rows, _, err := e.svc.List(e.alice.ctx, 10, "", []string{string(domain.StatusDenied)})
	if err != nil || len(rows) != 0 {
		t.Fatalf("filtered: %d %v", len(rows), err)
	}
	e.edition.e = billing.Community
	if _, _, err := e.svc.List(e.alice.ctx, 10, "", nil); !is(err, app.ErrEdition) {
		t.Fatalf("on Community: %v", err)
	}
}

// TestHR585_EnforceRefusesWhatIsNotAnExactMatch: ENFORCE refuses to create,
// move or restore a connection to anything but an approved server, a
// near-match included. WATCH stops nothing. A denied entry beats an approved
// one for the same URL. The refusal lives on the connection's lifecycle
// (T-253).
//
// Covers: F874
func TestHR585_EnforceRefusesWhatIsNotAnExactMatch(t *testing.T) {
	e := newEnv(t)
	e.approved(t, "good", "mcp.example.test", "/mcp")
	loose := e.mustCreate(t, "loose", "https://other.example.test/mcp")
	e.enforce(t, e.alice)

	if q := e.state(t, loose.ID); q.State != capp.StateQuarantined || q.QuarantineReason == nil || *q.QuarantineReason != capp.QuarantineCatalogNotApproved {
		t.Fatalf("the switch left %s %v", q.State, q.QuarantineReason)
	}
	for _, url := range []string{
		"https://mcp.example.test/mcp-evil", "https://mcp.example.test/other", "https://evil-mcp.example.test/mcp",
		"https://mcp.example.test.evil.test/mcp",
	} {
		if _, err := e.create("near", url); !is(err, app.ErrNotApproved) {
			t.Errorf("%s: %v", url, err)
		}
	}
	ok := e.mustCreate(t, "ok", "https://mcp.example.test/mcp/sse")
	bad := "https://evil.example.test/mcp"
	if _, err := e.conns.Update(e.admin, capp.UpdateInput{ID: ok.ID, Revision: ok.Revision, BaseURL: &bad}); !is(err, app.ErrNotApproved) {
		t.Fatalf("a move to an unapproved server: %v", err)
	}
	if _, err := e.conns.Restore(e.admin, loose.ID); !is(err, app.ErrNotApproved) {
		t.Fatalf("restoring an unapproved server: %v", err)
	}
	dup, err := e.svc.Propose(e.alice.ctx, domain.Proposal{Name: "dup", Title: "dup", Transport: domain.TransportHTTP, Spec: domain.Spec{Host: "mcp.example.test", PathPrefix: "/mcp"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Deny(e.alice.ctx, dup.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.create("denied", "https://mcp.example.test/mcp"); !is(err, app.ErrNotApproved) {
		t.Fatalf("a denied entry for the same URL: %v", err)
	}

	w := newEnv(t)
	if _, err := w.create("watching", "https://anything.example.test/mcp"); err != nil {
		t.Fatalf("WATCH stopped a connection: %v", err)
	}
}

// TestF874_TheSwitchIsPreviewedAndAllInOneTransaction: a switch to ENFORCE
// confirms a current preview; a stale one changes nothing; the switch raises
// the epoch and quarantines what the preview listed, and touches neither
// matching connections nor other orgs.
//
// Covers: F874
func TestF874_TheSwitchIsPreviewedAndAllInOneTransaction(t *testing.T) {
	e := newEnv(t)
	e.approved(t, "good", "mcp.example.test", "")
	good := e.mustCreate(t, "good", "https://mcp.example.test/a")
	bad := e.mustCreate(t, "bad", "https://bad.example.test/a")
	other := e.withOrg(t, "other")
	theirs := other.mustCreate(t, "theirs", "https://bad.example.test/a")

	p, err := e.svc.PreviewMode(e.alice.ctx, domain.ModeEnforce)
	if err != nil || len(p.Quarantines) != 1 || p.Quarantines[0].ID != bad.ID || p.SecondPerson {
		t.Fatalf("preview: %+v %v", p, err)
	}
	if _, err := e.svc.SetMode(e.alice.ctx, domain.ModeEnforce, nil, "x"); !is(err, app.ErrPreviewStale) {
		t.Fatalf("no digest: %v", err)
	}
	late := e.mustCreate(t, "late", "https://late.example.test/a")
	if _, err := e.svc.SetMode(e.alice.ctx, domain.ModeEnforce, p.Digest, "x"); !is(err, app.ErrPreviewStale) {
		t.Fatalf("a stale digest: %v", err)
	}
	if m := e.mode(t); m != domain.ModeWatch || e.state(t, bad.ID).State != capp.StateActive {
		t.Fatalf("a refused switch changed something: %s", m)
	}
	before := e.epoch(t)
	r := e.enforce(t, e.alice)
	if len(r.Quarantined) != 2 || e.epoch(t) <= before || e.mode(t) != domain.ModeEnforce {
		t.Fatalf("the switch: %+v, epoch %d after %d", r, e.epoch(t), before)
	}
	for id, want := range map[ids.UUID]string{bad.ID: capp.StateQuarantined, late.ID: capp.StateQuarantined, good.ID: capp.StateActive} {
		if got := e.state(t, id).State; got != want {
			t.Errorf("%s is %s", id, got)
		}
	}
	if got := other.state(t, theirs.ID).State; got != capp.StateActive {
		t.Fatalf("the switch reached another org: %s", got)
	}
}

// TestHR586_WeakeningEnforceAlwaysWaitsForASecondPerson: leaving ENFORCE
// files a protected change whatever TOOL_MEANING's mode, changes nothing until
// someone else confirms it, is refused to its author and as an emergency, and
// needs a person with a step-up. Without a Gate it fails closed (T-253).
//
// Covers: F874
func TestHR586_WeakeningEnforceAlwaysWaitsForASecondPerson(t *testing.T) {
	e := newEnv(t)
	e.approved(t, "good", "mcp.example.test", "")
	e.enforce(t, e.alice)

	if _, err := e.svc.SetMode(e.as(e.alice.id, td.RoleSecurityAdmin), domain.ModeWatch, nil, "x"); !is(err, rapp.ErrStepUp) {
		t.Fatalf("no step-up: %v", err)
	}
	sa := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	if _, err := e.svc.SetMode(sa, domain.ModeWatch, nil, "x"); err == nil {
		t.Fatal("a service account changed the mode")
	}
	r, err := e.svc.SetMode(e.alice.ctx, domain.ModeWatch, nil, "too noisy")
	if err != nil || r.Held == nil {
		t.Fatalf("leaving ENFORCE: %+v %v", r, err)
	}
	if m := e.mode(t); m != domain.ModeEnforce {
		t.Fatalf("a filed change applied at once: %s", m)
	}
	if err := e.confirm(r.Held, e.alice.id); err == nil {
		t.Fatal("the author confirmed their own weakening")
	}
	if m := e.mode(t); m != domain.ModeEnforce {
		t.Fatalf("after the author's confirm: %s", m)
	}
	if err := e.confirm(r.Held, e.bob.id); err != nil {
		t.Fatalf("a second person: %v", err)
	}
	if m := e.mode(t); m != domain.ModeWatch {
		t.Fatalf("after a second person: %s", m)
	}

	nogate := &app.Service{Pool: e.pool, Editions: e.edition, Connections: e.conns}
	e.enforce(t, e.alice)
	if _, err := nogate.SetMode(e.alice.ctx, domain.ModeOff, nil, "x"); !is(err, protect.ErrUnavailable) {
		t.Fatalf("without a Gate: %v", err)
	}
	if m := e.mode(t); m != domain.ModeEnforce {
		t.Fatalf("without a Gate: %s", m)
	}
}

// TestF874_AConnectionChangeTakesTheModeBeforeTheConnection: a change waits on
// the mode's row holding no lock on the connection, the order a switch to
// ENFORCE locks them in, so the two can never deadlock (D262).
//
// Covers: F874
func TestF874_AConnectionChangeTakesTheModeBeforeTheConnection(t *testing.T) {
	e := newEnv(t)
	c := e.mustCreate(t, "a", "https://mcp.example.test/x")
	moved := "https://mcp.example.test/y"
	done := make(chan error, 1)
	err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "SELECT 1 FROM pc.mcp_catalog_settings WHERE org_id = $1 FOR UPDATE", e.org); err != nil {
			return err
		}
		go func() {
			_, err := e.conns.Update(e.admin, capp.UpdateInput{ID: c.ID, Revision: c.Revision, BaseURL: &moved})
			done <- err
		}()
		time.Sleep(500 * time.Millisecond)
		_, err := tx.Exec(ctx, "SELECT 1 FROM pc.connections WHERE org_id = $1 AND id = $2 FOR UPDATE NOWAIT", e.org, c.ID)
		return err
	})
	if err != nil {
		t.Fatalf("the waiting change held the connection: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// scanned records a local MCP server a scan found, on a discovered agent.
func (e *env) scanned(t *testing.T, observed string) (agent, discovery ids.UUID) {
	t.Helper()
	agent, discovery = ids.NewV7(), ids.NewV7()
	key := make([]byte, 32)
	copy(key, discovery[:])
	e.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, $3, 'DISCOVERED', 'system')", e.org, agent, agent.String())
	e.exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed) VALUES ($1, $2, $3, 'scan', $4, $5)`,
		e.org, discovery, agent, key, observed)
	return agent, discovery
}

// TestF879_UnapprovedServersReachTheQueueOnlyOnceACatalogueExists: nothing
// until a server is APPROVED, then every running connection and scanned server
// that matches none, each only to a viewer who may read it under both
// permissions.
//
// Covers: F879
func TestF879_UnapprovedServersReachTheQueueOnlyOnceACatalogueExists(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := &app.Source{Pool: e.pool, Editions: e.edition}
	all := ports.Viewer{Org: e.org, Posture: ports.Reach{All: true, Org: true}}
	findings := func(v ports.Viewer) map[string]pvdomain.Finding {
		t.Helper()
		got, truncated, err := src.Findings(ctx, v, pvdomain.Filter{})
		if err != nil || truncated {
			t.Fatalf("findings: %v %v", truncated, err)
		}
		out := map[string]pvdomain.Finding{}
		for _, f := range got {
			if f.Kind != app.KindUnapprovedServer || f.Source != pvdomain.SourceCatalog || f.Fix.Kind != pvdomain.FixReviewServer {
				t.Fatalf("finding %+v", f)
			}
			out[f.SourceID] = f
		}
		return out
	}

	stray := e.mustCreate(t, "stray", "https://stray.example.test/mcp")
	agent, stranger := e.scanned(t, `{"kind":"mcp_server","name":"stranger","url_host":"stray.example.test"}`)
	if got := findings(all); len(got) != 0 {
		t.Fatalf("an empty catalogue reported: %v", got)
	}

	e.approved(t, "good", "mcp.example.test", "")
	e.mustCreate(t, "fine", "https://mcp.example.test/any")
	e.scanned(t, `{"kind":"mcp_server","name":"known","url_host":"mcp.example.test"}`)
	got := findings(all)
	conn, scan := "connection:"+stray.ID.String(), "discovery:"+stranger.String()
	if len(got) != 2 || got[conn].ConnectionID == nil || *got[conn].ConnectionID != stray.ID ||
		got[scan].AgentID == nil || *got[scan].AgentID != agent {
		t.Fatalf("findings %+v", got)
	}

	// A name a scan reports stays out of the title, whatever it says (D260).
	if strings.Contains(got[scan].Title, "stranger") || got[scan].Detail["name"] != "stranger" {
		t.Fatalf("finding %+v", got[scan])
	}

	if got := findings(ports.Viewer{Org: e.org, Posture: ports.Reach{Agents: []ids.UUID{agent}}}); len(got) != 1 || got[scan].AgentID == nil {
		t.Fatalf("no org scope: %+v", got)
	}
	if got := findings(ports.Viewer{Org: e.org, Posture: ports.Reach{Org: true}}); len(got) != 1 || got[conn].ConnectionID == nil {
		t.Fatalf("no agents: %+v", got)
	}
	under := all
	under.Under = func(_ context.Context, p td.Permission) (ports.Reach, error) {
		if p != td.PermCatalogRead {
			t.Fatalf("under %s", p)
		}
		return ports.Reach{Agents: []ids.UUID{}}, nil
	}
	// Below the source's scope the queue says RESTRICTED, never an empty
	// COMPLETE (D255, D268).
	if got, _, err := src.Findings(ctx, under, pvdomain.Filter{}); len(got) != 0 || pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("without catalog.read: %+v %v", got, err)
	}
	unrelated := ports.Viewer{Org: e.org, Posture: ports.Reach{Agents: []ids.UUID{ids.NewV7()}}}
	if got, _, err := src.Findings(ctx, unrelated, pvdomain.Filter{}); len(got) != 0 || pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("no org scope and nothing of theirs: %+v %v", got, err)
	}

	e.edition.e = billing.Community
	if _, _, err := src.Findings(ctx, all, pvdomain.Filter{}); !is(err, app.ErrEdition) {
		t.Fatalf("community: %v", err)
	}
	e.edition.e = billing.Team

	other := e.withOrg(t, "other")
	if got := findings(ports.Viewer{Org: other.org, Posture: ports.Reach{All: true, Org: true}}); len(got) != 0 {
		t.Fatalf("another org: %+v", got)
	}
}
