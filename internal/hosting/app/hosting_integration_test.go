// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/hosting/app"
	"github.com/katocxl/pantherclaw/internal/hosting/domain"
	"github.com/katocxl/pantherclaw/internal/hosting/profile"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

type env struct {
	pool *db.Pool
	ca   *ca.Authority
	svc  *app.Service
	gws  *gwapp.Service
}

func newEnv(t *testing.T, ed billing.Edition) *env {
	t.Helper()
	d := dbtest.New(t)
	pool := d.AppPool(t)
	reg := keys.NewRegistry()
	k, err := keys.GenerateSigningKey(keys.PurposeGatewayCA)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Put(k); err != nil {
		t.Fatal(err)
	}
	authority, err := ca.New(reg)
	if err != nil {
		t.Fatal(err)
	}
	kek := filepath.Join(t.TempDir(), "kek")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{kek})
	if err != nil {
		t.Fatal(err)
	}
	envl := pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))
	return &env{
		pool: pool, ca: authority,
		svc: app.New(pool, authority, envl, edition(ed), "https://gw-api.example.test:8443", clock.System{}),
		gws: gwapp.New(pool, authority, "https://gw-api.example.test:8443", nil),
	}
}

func (e *env) org(t *testing.T) (ids.OrgID, context.Context) {
	t.Helper()
	org := ids.New[ids.Org]()
	if err := e.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'hosting')", org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return org, tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func (e *env) host(t *testing.T, name string, capacity int32) app.HostIdentity {
	t.Helper()
	pub, _ := key(t)
	hc, err := e.svc.AddHost(context.Background(), name, name+".example.test", capacity, 4000, 8192, pub)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(hc.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ca.ParseHostIdentity(cert)
	if err != nil || id != hc.Identity {
		t.Fatalf("host identity %+v %v", id, err)
	}
	return id
}

func csr(t *testing.T) []byte {
	t.Helper()
	_, priv := key(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// provisioned requests and provisions one hosted gateway of org.
func (e *env) provisioned(t *testing.T, org ids.OrgID, ctx context.Context, slug string) ids.UUID {
	t.Helper()
	h, err := e.svc.Request(ctx, slug, profile.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.ProvisionOrg(context.Background(), org); err != nil || n != 1 {
		t.Fatalf("provision: %d %v", n, err)
	}
	return h.ID
}

// TestHR499_OneHostedGatewayPerOrgAndOneOrgPerCertificate: an org gets at
// most one live hosted gateway, a slug names one across orgs, and the
// certificate its process enrolls with names exactly that org.
//
// Covers: PN-010.4
func TestHR499_OneHostedGatewayPerOrgAndOneOrgPerCertificate(t *testing.T) {
	e := newEnv(t, billing.Team)
	host := e.host(t, "h1", 10)
	a, actx := e.org(t)
	b, bctx := e.org(t)
	hosted := e.provisioned(t, a, actx, "acme")
	if _, err := e.svc.Request(actx, "acme-two", profile.Limits{}); !errors.Is(err, domain.ErrOneOnly) {
		t.Fatalf("second hosted gateway: %v", err)
	}
	// Another org may use the slug, but never on the same host: one name,
	// one process.
	if _, err := e.svc.Request(bctx, "acme", profile.Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ProvisionOrg(context.Background(), b); !errors.Is(err, domain.ErrNoCapacity) {
		t.Fatalf("a second acme on one host: %v", err)
	}
	other := e.host(t, "h2", 10)
	if n, err := e.svc.ProvisionOrg(context.Background(), b); err != nil || n != 1 {
		t.Fatalf("b on the second host: %d %v", n, err)
	}
	if as, err := e.svc.Assignments(context.Background(), other, "test"); err != nil || len(as) != 1 || as[0].Org != b || as[0].Hostname != "acme.gw.h2.example.test" {
		t.Fatalf("second host runs %+v %v", as, err)
	}
	tok, err := e.svc.PullToken(context.Background(), host, a, hosted)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := e.gws.Enroll(context.Background(), tok.Secret.Reveal(), csr(t))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(enrolled.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ca.ParseIdentity(cert)
	if err != nil || id.Org != a {
		t.Fatalf("certificate names %+v %v, want org %s", id, err, a)
	}
	h, err := e.svc.Get(actx, hosted)
	if err != nil || h.GatewayID == nil || *h.GatewayID != id.Gateway {
		t.Fatalf("record %+v %v", h, err)
	}
}

// TestHR499_EditionAndQuota: hosted gateways need the Team edition, and a
// request beyond the edition's quota is refused.
//
// Covers: PN-010.4
func TestHR499_EditionAndQuota(t *testing.T) {
	e := newEnv(t, billing.Community)
	_, ctx := e.org(t)
	if _, err := e.svc.Request(ctx, "free", profile.Limits{}); !errors.Is(err, domain.ErrEdition) {
		t.Fatalf("community: %v", err)
	}
	e = newEnv(t, billing.Team)
	_, ctx = e.org(t)
	if _, err := e.svc.Request(ctx, "big", profile.Limits{MemoryMiB: 1024}); !errors.Is(err, domain.ErrQuota) {
		t.Fatalf("over quota: %v", err)
	}
	if _, err := e.svc.Request(ctx, "Bad_Slug", profile.Limits{}); !errors.Is(err, domain.ErrSlug) {
		t.Fatalf("slug: %v", err)
	}
}

// TestHR502_TheTokenIsPulledOnceByItsHost: the enrollment token is handed
// out once, to the host the gateway is placed on, and the record forgets
// it; a second pull, or another host's, gets nothing.
//
// Covers: PN-010.4
func TestHR502_TheTokenIsPulledOnceByItsHost(t *testing.T) {
	e := newEnv(t, billing.Team)
	host := e.host(t, "h1", 10)
	a, actx := e.org(t)
	hosted := e.provisioned(t, a, actx, "acme")
	other := e.host(t, "h2", 10) // placed after: acme stays on h1
	if _, err := e.svc.PullToken(context.Background(), other, a, hosted); !errors.Is(err, app.ErrNotAssigned) {
		t.Fatalf("another host pulled: %v", err)
	}
	tok, err := e.svc.PullToken(context.Background(), host, a, hosted)
	if err != nil || tok.Secret.Reveal() == "" || tok.CAFingerprint == "" {
		t.Fatalf("pull: %v", err)
	}
	if _, err := e.svc.PullToken(context.Background(), host, a, hosted); !errors.Is(err, app.ErrTokenGone) {
		t.Fatalf("second pull: %v", err)
	}
	h, err := e.svc.Get(actx, hosted)
	if err != nil || h.TokenSealed != nil || h.State != domain.StateEnrolled {
		t.Fatalf("record keeps the token: %+v %v", h, err)
	}
}

// TestHR503_DeprovisionRevokesFirst: deprovisioning revokes the gateway,
// its certificates and the org's outstanding permits (epoch) in the same
// transaction that hands the process to its host to stop; the gateway's
// next call is refused before the process is gone.
//
// Covers: PN-010.4
func TestHR503_DeprovisionRevokesFirst(t *testing.T) {
	e := newEnv(t, billing.Team)
	host := e.host(t, "h1", 10)
	a, actx := e.org(t)
	hosted := e.provisioned(t, a, actx, "acme")
	tok, err := e.svc.PullToken(context.Background(), host, a, hosted)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := e.gws.Enroll(context.Background(), tok.Secret.Reveal(), csr(t))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(enrolled.Certificate)
	gid, _ := ca.ParseIdentity(cert)
	if err := e.gws.Authenticate(context.Background(), gid); err != nil {
		t.Fatal(err)
	}
	epoch := func() int64 {
		var n int64
		_ = e.pool.InTenantTx(context.Background(), a, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT coalesce((SELECT epoch FROM pc.org_containment WHERE org_id = $1), 0)", a).Scan(&n)
		})
		return n
	}
	before := epoch()
	h, err := e.svc.Deprovision(actx, hosted, "test")
	if err != nil || h.State != domain.StateDeprovisioning {
		t.Fatalf("deprovision: %+v %v", h, err)
	}
	if epoch() <= before {
		t.Error("the containment epoch did not move")
	}
	time.Sleep(1100 * time.Millisecond) // past the certificate cache
	if err := e.gws.Authenticate(context.Background(), gid); err == nil {
		t.Fatal("the deprovisioning gateway still authenticates")
	}
	if a, err := e.svc.Assignments(context.Background(), host, "test"); err != nil || len(a) != 1 || a[0].State != domain.StateDeprovisioning {
		t.Fatalf("assignments %+v %v", a, err)
	}
	if err := e.svc.Stopped(context.Background(), host, a, hosted); err != nil {
		t.Fatal(err)
	}
	if h, _ := e.svc.Get(actx, hosted); h.State != domain.StateDeprovisioned {
		t.Fatalf("state %s", h.State)
	}
	// The org may ask again once the old one is gone.
	if _, err := e.svc.Request(actx, "acme", profile.Limits{}); err != nil {
		t.Fatalf("request after deprovision: %v", err)
	}
}

// TestT217_AHostSeesOnlyWhatItRuns: a host's assignments hold only the
// hosted gateways placed on it, never a token, and a host whose
// certificate was not issued (or another host's id) is refused.
//
// Covers: PN-010.4
func TestT217_AHostSeesOnlyWhatItRuns(t *testing.T) {
	e := newEnv(t, billing.Team)
	h1 := e.host(t, "h1", 1)
	h2 := e.host(t, "h2", 1)
	a, actx := e.org(t)
	b, bctx := e.org(t)
	ha := e.provisioned(t, a, actx, "acme")
	hb := e.provisioned(t, b, bctx, "beta")
	got := map[ids.UUID]ids.UUID{}
	for _, h := range []app.HostIdentity{h1, h2} {
		if err := e.svc.AuthenticateHost(context.Background(), h); err != nil {
			t.Fatal(err)
		}
		as, err := e.svc.Assignments(context.Background(), h, "test")
		if err != nil || len(as) != 1 {
			t.Fatalf("host %s: %+v %v", h.Host, as, err)
		}
		got[as[0].ID] = h.Host
	}
	if got[ha] == got[hb] || got[ha].IsZero() || got[hb].IsZero() {
		t.Fatalf("capacity 1 placed both on one host: %v", got)
	}
	forged := app.HostIdentity{Host: h1.Host, Cert: ids.NewV7()}
	if err := e.svc.AuthenticateHost(context.Background(), forged); !errors.Is(err, app.ErrHostCredentials) {
		t.Fatalf("unknown certificate: %v", err)
	}
	swapped := app.HostIdentity{Host: h2.Host, Cert: h1.Cert}
	if err := e.svc.AuthenticateHost(context.Background(), swapped); !errors.Is(err, app.ErrHostCredentials) {
		t.Fatalf("another host's certificate: %v", err)
	}
	// A third org finds no room and stays REQUESTED.
	c, cctx := e.org(t)
	if _, err := e.svc.Request(cctx, "gamma", profile.Limits{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ProvisionOrg(context.Background(), c); !errors.Is(err, domain.ErrNoCapacity) {
		t.Fatalf("over capacity: %v", err)
	}
}

// TestTenancy_hosted_gateways: another org neither reads nor changes an
// org's hosted gateway records, and the hosting tables are invisible in a
// tenant transaction.
func TestTenancy_hosted_gateways(t *testing.T) {
	e := newEnv(t, billing.Team)
	e.host(t, "h1", 10)
	a, actx := e.org(t)
	b, _ := e.org(t)
	e.provisioned(t, a, actx, "acme")
	count := func(org ids.OrgID, sql string) int {
		var n int
		if err := e.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, sql).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(b, "SELECT count(*) FROM pc.hosted_gateways"); n != 0 {
		t.Fatalf("another org sees %d hosted gateways", n)
	}
	if err := e.pool.InTenantTx(context.Background(), b, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.hosted_gateways SET version = 'mine'")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if n := count(a, "SELECT count(*) FROM pc.hosted_gateways WHERE version IS NULL"); n != 1 {
		t.Fatal("another org changed our record")
	}
	if n := count(a, "SELECT count(*) FROM pc.hosting_hosts"); n != 0 {
		t.Fatalf("a tenant transaction sees %d hosts", n)
	}
	if n := count(a, "SELECT count(*) FROM pc.hosting_host_certs"); n != 0 {
		t.Fatalf("a tenant transaction sees %d host certificates", n)
	}
}

// enrolledGateway provisions org's hosted gateway on host, pulls its token
// and enrolls it, returning the gateway's identity.
func (e *env) enrolledGateway(t *testing.T, host app.HostIdentity, org ids.OrgID, ctx context.Context, slug string) ca.Identity {
	t.Helper()
	hosted := e.provisioned(t, org, ctx, slug)
	tok, err := e.svc.PullToken(context.Background(), host, org, hosted)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, err := e.gws.Enroll(context.Background(), tok.Secret.Reveal(), csr(t))
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(enrolled.Certificate)
	id, err := ca.ParseIdentity(cert)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestT216_AGatewayGetsOnlyItsOwnOrgsHostname: a hosted gateway's
// agent-facing certificate names exactly its own org's <slug>.gw.<host
// domain>, taken from the record that names it; another org's gateway
// gets its own name only, and a gateway no hosted record names gets
// nothing (D210).
//
// Covers: PN-010.4
func TestT216_AGatewayGetsOnlyItsOwnOrgsHostname(t *testing.T) {
	e := newEnv(t, billing.Team)
	host := e.host(t, "h1", 10)
	a, actx := e.org(t)
	b, bctx := e.org(t)
	ga := e.enrolledGateway(t, host, a, actx, "acme")
	gb := e.enrolledGateway(t, host, b, bctx, "beta")
	for id, want := range map[ca.Identity]string{ga: "acme.gw.h1.example.test", gb: "beta.gw.h1.example.test"} {
		pub, _ := key(t)
		c, err := e.svc.IssueServerCertificate(context.Background(), id, pub)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(c.Certificate)
		if err != nil || c.Hostname != want || len(cert.DNSNames) != 1 || cert.DNSNames[0] != want {
			t.Fatalf("gateway of org %s got %v (%s), want %s: %v", id.Org, cert.DNSNames, c.Hostname, want, err)
		}
	}
	// A customer-hosted gateway of org a: no record names it.
	g, err := e.gws.CreateGateway(actx, "own")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := key(t)
	if _, err := e.svc.IssueServerCertificate(context.Background(), ca.Identity{Org: a, Gateway: g.ID, Cert: ids.NewV7()}, pub); !errors.Is(err, app.ErrNotHosted) {
		t.Fatalf("an unhosted gateway: %v", err)
	}
	// Org a's gateway id under org b's identity is not found either.
	if _, err := e.svc.IssueServerCertificate(context.Background(), ca.Identity{Org: b, Gateway: ga.Gateway, Cert: ga.Cert}, pub); !errors.Is(err, app.ErrNotHosted) {
		t.Fatalf("another org's gateway: %v", err)
	}
}

// TestHR499_ADowngradeGatesOnlyNewRequests: after a downgrade to Community,
// the org reads and deprovisions its hosted gateway, but cannot request a
// new one (D212).
//
// Covers: PN-010.4
func TestHR499_ADowngradeGatesOnlyNewRequests(t *testing.T) {
	e := newEnv(t, billing.Team)
	e.host(t, "h1", 10)
	a, actx := e.org(t)
	hosted := e.provisioned(t, a, actx, "acme")
	down := app.New(e.pool, e.ca, nil, edition(billing.Community), "", clock.System{})
	if _, err := down.Get(actx, hosted); err != nil {
		t.Fatalf("read after downgrade: %v", err)
	}
	if _, err := down.Deprovision(actx, hosted, "downgrade"); err != nil {
		t.Fatalf("deprovision after downgrade: %v", err)
	}
	if _, err := down.Request(actx, "again", profile.Limits{}); !errors.Is(err, domain.ErrEdition) {
		t.Fatalf("request after downgrade: %v", err)
	}
}
