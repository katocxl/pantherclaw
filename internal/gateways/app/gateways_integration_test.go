// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type env struct {
	pool  *db.Pool
	svc   *app.Service
	org   ids.OrgID
	admin context.Context // a person holding Gateway Admin
}

func newEnv(t *testing.T) *env {
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
	e := &env{pool: pool, svc: app.New(pool, authority, "https://gw-api.example.test:8443", nil), org: ids.New[ids.Org]()}
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'gateways')", e.org)
	e.admin = e.caller(td.KindUser, td.RoleGatewayAdmin)
	return e
}

func (e *env) caller(kind td.PrincipalKind, role td.RoleName) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: kind, ID: ids.NewV7()},
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

func csr(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// enroll creates a gateway, mints a token and enrolls with it.
func (e *env) enroll(t *testing.T, name string) (app.Enrolled, app.Identity) {
	t.Helper()
	g, err := e.svc.CreateGateway(e.admin, name)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := e.svc.CreateEnrollmentToken(e.admin, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	en, err := e.svc.Enroll(context.Background(), tok.Secret.Reveal(), csr(t))
	if err != nil {
		t.Fatal(err)
	}
	return en, identityOf(t, en.Certificate)
}

func identityOf(t *testing.T, der []byte) app.Identity {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ca.ParseIdentity(cert)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestHR180_EnrollmentTokensAreSingleUseAndIssueOneCertificate: a token
// enrolls exactly once; the certificate names its org and gateway and
// chains to the CA whose pin came with the token; a reused, expired,
// malformed or revoked gateway's token is refused with one generic error,
// and a reuse is audited.
func TestHR180_EnrollmentTokensAreSingleUseAndIssueOneCertificate(t *testing.T) {
	e := newEnv(t)
	g, err := e.svc.CreateGateway(e.admin, "edge")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := e.svc.CreateEnrollmentToken(e.admin, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tok.CAFingerprint != ca.Fingerprint(e.svc.CA().Certificate()) || tok.GatewayAPIURL == "" {
		t.Fatalf("token response %+v", tok)
	}
	en, err := e.svc.Enroll(context.Background(), tok.Secret.Reveal(), csr(t))
	if err != nil {
		t.Fatal(err)
	}
	if ca.Fingerprint(en.CACertificate) != tok.CAFingerprint || en.Org != e.org || en.Gateway != g.ID {
		t.Fatalf("enrolled %+v", en)
	}
	id := identityOf(t, en.Certificate)
	if id.Org != e.org || id.Gateway != g.ID {
		t.Fatalf("identity %+v", id)
	}
	if err := e.svc.Authenticate(context.Background(), id); err != nil {
		t.Fatalf("a fresh certificate does not authenticate: %v", err)
	}

	if _, err := e.svc.Enroll(context.Background(), tok.Secret.Reveal(), csr(t)); !errors.Is(err, app.ErrEnrollment) {
		t.Fatalf("reused token: %v", err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.security.gateway_enrollment_reused'"); n != 1 {
		t.Fatalf("reuse audited %d times", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.gateway_certs WHERE gateway_id = $1", g.ID); n != 1 {
		t.Fatalf("%d certificates after a reuse", n)
	}

	// An expired token: valid shape, stored, but past its 15 minutes.
	old, err := credential.New(credential.GatewayEnrollmentToken, "", e.org)
	if err != nil {
		t.Fatal(err)
	}
	e.exec(t, `INSERT INTO pc.gateway_enrollment_tokens (org_id, id, gateway_id, token_hash, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, 'test', now() - interval '20 minutes', now() - interval '5 minutes')`, e.org, ids.NewV7(), g.ID, old.Hash())
	if _, err := e.svc.Enroll(context.Background(), old.Reveal(), csr(t)); !errors.Is(err, app.ErrEnrollment) {
		t.Fatalf("expired token: %v", err)
	}
	for name, bad := range map[string]string{"malformed": "pcg_nope", "another kind": "pce_" + tok.Secret.Reveal()[4:]} {
		if _, err := e.svc.Enroll(context.Background(), bad, csr(t)); !errors.Is(err, app.ErrEnrollment) {
			t.Errorf("%s token: %v", name, err)
		}
	}
	// A request not signed by its key.
	fresh, _ := e.svc.CreateEnrollmentToken(e.admin, g.ID)
	bad := csr(t)
	bad[len(bad)-1] ^= 1
	if _, err := e.svc.Enroll(context.Background(), fresh.Secret.Reveal(), bad); !errors.Is(err, app.ErrEnrollment) {
		t.Fatalf("unsigned request: %v", err)
	}
	// A revoked gateway's outstanding token no longer enrolls.
	if _, err := e.svc.RevokeGateway(e.admin, g.ID, "decommissioned"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Enroll(context.Background(), fresh.Secret.Reveal(), csr(t)); !errors.Is(err, app.ErrEnrollment) {
		t.Fatalf("token of a revoked gateway: %v", err)
	}
}

// TestHR181_EveryCallChecksTheCertificateRow: revoking a certificate or its
// gateway refuses the next call; a renewal keeps the old certificate for
// the grace period only; an identity naming another gateway is refused.
func TestHR181_EveryCallChecksTheCertificateRow(t *testing.T) {
	e := newEnv(t)
	_, id := e.enroll(t, "edge")
	_, other := e.enroll(t, "edge-2")
	ctx := context.Background()

	forged := app.Identity{Org: id.Org, Gateway: other.Gateway, Cert: id.Cert}
	if err := e.svc.Authenticate(ctx, forged); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("a certificate row claimed by another gateway: %v", err)
	}
	if err := e.svc.Authenticate(ctx, app.Identity{Org: ids.New[ids.Org](), Gateway: id.Gateway, Cert: id.Cert}); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("a certificate presented for another org: %v", err)
	}

	renewed, err := e.svc.Renew(ctx, id, csr(t))
	if err != nil {
		t.Fatal(err)
	}
	next := identityOf(t, renewed.Certificate)
	if next.Gateway != id.Gateway || next.Cert == id.Cert {
		t.Fatalf("renewed identity %+v", next)
	}
	if err := e.svc.Authenticate(ctx, id); err != nil {
		t.Fatalf("the superseded certificate is refused within its grace: %v", err)
	}
	if _, err := e.svc.Renew(ctx, id, csr(t)); !errors.Is(err, app.ErrRenewal) {
		t.Fatalf("renewing a superseded certificate: %v", err)
	}
	// Past the grace period (move the supersession back in time).
	e.exec(t, "UPDATE pc.gateway_certs SET superseded_at = now() - interval '11 minutes' WHERE id = $1", id.Cert)
	fresh := app.New(e.pool, e.svc.CA(), "", nil) // no cache
	if err := fresh.Authenticate(ctx, id); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("the superseded certificate is accepted after its grace: %v", err)
	}

	if err := e.svc.RevokeCertificate(e.admin, next.Gateway, next.Cert); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Authenticate(ctx, next); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("a revoked certificate authenticates: %v", err)
	}

	if err := e.svc.Authenticate(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.RevokeGateway(e.admin, other.Gateway, "lost"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Authenticate(ctx, other); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("a revoked gateway authenticates: %v", err)
	}
}

// TestHR181_RevokingCoversASupersededCertificate: after a renewal the old
// certificate still authenticates for its grace period, so revoking it, or
// its gateway, must cover it too.
func TestHR181_RevokingCoversASupersededCertificate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	renew := func(name string) (app.Identity, app.Identity) {
		_, id := e.enroll(t, name)
		renewed, err := e.svc.Renew(ctx, id, csr(t))
		if err != nil {
			t.Fatal(err)
		}
		return id, identityOf(t, renewed.Certificate)
	}

	old, _ := renew("edge")
	if err := e.svc.RevokeCertificate(e.admin, old.Gateway, old.Cert); err != nil {
		t.Fatalf("revoking a superseded certificate: %v", err)
	}
	if err := app.New(e.pool, e.svc.CA(), "", nil).Authenticate(ctx, old); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("a revoked superseded certificate authenticates within its grace: %v", err)
	}

	old, next := renew("edge-2")
	if _, err := e.svc.RevokeGateway(e.admin, old.Gateway, "lost"); err != nil {
		t.Fatalf("revoking a gateway that renewed: %v", err)
	}
	fresh := app.New(e.pool, e.svc.CA(), "", nil) // no cache
	for _, id := range []app.Identity{old, next} {
		if err := fresh.Authenticate(ctx, id); !errors.Is(err, app.ErrGatewayCredentials) {
			t.Fatalf("certificate %s of a revoked gateway authenticates: %v", id.Cert, err)
		}
	}
	if n := e.count(t, "SELECT count(*) FROM pc.gateway_certs WHERE gateway_id = $1 AND state <> 'REVOKED'", old.Gateway); n != 0 {
		t.Fatalf("%d certificates of the revoked gateway are not revoked", n)
	}
}

// TestHR002_RevokingAGatewayRaisesTheEpoch: its outstanding permits then
// fail BeginDispatch.
func TestHR002_RevokingAGatewayRaisesTheEpoch(t *testing.T) {
	e := newEnv(t)
	_, id := e.enroll(t, "edge")
	e.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org)
	before := e.count(t, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", e.org)
	if _, err := e.svc.RevokeGateway(e.admin, id.Gateway, "lost"); err != nil {
		t.Fatal(err)
	}
	if after := e.count(t, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", e.org); after != before+1 {
		t.Fatalf("epoch %d → %d", before, after)
	}
	if _, err := e.svc.RevokeGateway(e.admin, id.Gateway, "again"); !errors.Is(err, app.ErrGatewayRevoked) {
		t.Fatalf("revoking twice: %v", err)
	}
}

// TestHR182_RevokingAGatewayRetiresItsBrokerKeys: the revocation retires
// the gateway's active broker key in its transaction and audits how many;
// another gateway's key stays active, and the revoked gateway cannot
// register a new one.
func TestHR182_RevokingAGatewayRetiresItsBrokerKeys(t *testing.T) {
	e := newEnv(t)
	_, id := e.enroll(t, "edge")
	_, other := e.enroll(t, "other")
	ctx := context.Background()
	key := func() []byte {
		k, err := pccrypto.GenerateSealKey()
		if err != nil {
			t.Fatal(err)
		}
		return k.PublicKey().Bytes()
	}
	for _, g := range []app.Identity{id, other} {
		if _, err := e.svc.RegisterBrokerKey(ctx, g, key()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.RevokeGateway(e.admin, id.Gateway, "stolen"); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.broker_keys WHERE gateway_id = $1 AND state = 'ACTIVE'", id.Gateway); n != 0 {
		t.Fatalf("%d broker keys of the revoked gateway are active", n)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.broker_keys WHERE gateway_id = $1 AND state = 'ACTIVE'", other.Gateway); n != 1 {
		t.Fatalf("%d broker keys of the other gateway are active", n)
	}
	if n := e.count(t, `SELECT (convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'broker_keys')::int FROM pc.ledger_entries
		WHERE kind = 'audit.gateway.revoked' ORDER BY occurred_at DESC, id DESC LIMIT 1`); n != 1 {
		t.Fatalf("revocation audited %d retired broker keys", n)
	}
	if _, err := e.svc.RegisterBrokerKey(ctx, id, key()); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("a revoked gateway registered a broker key: %v", err)
	}
}

// TestHR182_BrokerKeysAreRegisteredByTheirGatewayAndVersioned: the active
// key registered again changes nothing; a new key is the next version and
// moves the configuration version; a retired key cannot come back.
func TestHR182_BrokerKeysAreRegisteredByTheirGatewayAndVersioned(t *testing.T) {
	e := newEnv(t)
	_, id := e.enroll(t, "edge")
	ctx := context.Background()
	key := func() []byte {
		k, err := pccrypto.GenerateSealKey()
		if err != nil {
			t.Fatal(err)
		}
		return k.PublicKey().Bytes()
	}
	a, b := key(), key()
	k1, err := e.svc.RegisterBrokerKey(ctx, id, a)
	if err != nil || k1.Version != 1 || k1.Fingerprint != app.Fingerprint(a) {
		t.Fatalf("first key %+v %v", k1, err)
	}
	cfg := e.count(t, "SELECT config_version FROM pc.gateways WHERE id = $1", id.Gateway)
	again, err := e.svc.RegisterBrokerKey(ctx, id, a)
	if err != nil || again.ID != k1.ID {
		t.Fatalf("same key again: %+v %v", again, err)
	}
	k2, err := e.svc.RegisterBrokerKey(ctx, id, b)
	if err != nil || k2.Version != 2 {
		t.Fatalf("second key %+v %v", k2, err)
	}
	if got := e.count(t, "SELECT config_version FROM pc.gateways WHERE id = $1", id.Gateway); got != cfg+1 {
		t.Fatalf("config version %d → %d", cfg, got)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.broker_keys WHERE gateway_id = $1 AND state = 'ACTIVE'", id.Gateway); n != 1 {
		t.Fatalf("%d active broker keys", n)
	}
	if _, err := e.svc.RegisterBrokerKey(ctx, id, a); !errors.Is(err, app.ErrBrokerKeyReused) {
		t.Fatalf("a retired key again: %v", err)
	}
	// ML-KEM coefficients above the modulus, and a key of the wrong length.
	for name, k := range map[string][]byte{"bad encoding": bytes.Repeat([]byte{0xff}, 1216), "short": make([]byte, 32)} {
		if _, err := e.svc.RegisterBrokerKey(ctx, id, k); !errors.Is(err, app.ErrBrokerKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHR183_GatewayManagementIsForPeople: a service account bound to
// Gateway Admin, and Org Admin, cannot create gateways or mint tokens; Org
// Admin can read them.
func TestHR183_GatewayManagementIsForPeople(t *testing.T) {
	e := newEnv(t)
	sa := e.caller(td.KindServiceAccount, td.RoleGatewayAdmin)
	if _, err := e.svc.CreateGateway(sa, "edge"); err == nil {
		t.Fatal("a service account created a gateway")
	}
	orgAdmin := e.caller(td.KindUser, td.RoleOrgAdmin)
	if _, err := e.svc.CreateGateway(orgAdmin, "edge"); err == nil {
		t.Fatal("Org Admin created a gateway")
	}
	g, err := e.svc.CreateGateway(e.admin, "edge")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.GetGateway(orgAdmin, g.ID); err != nil {
		t.Fatalf("Org Admin cannot read a gateway: %v", err)
	}
	if _, err := e.svc.CreateGateway(e.admin, "edge"); !errors.Is(err, app.ErrNameTaken) {
		t.Fatalf("a second active gateway with one name: %v", err)
	}
}

// TestT037_GatewaysOfAnotherOrgAreNotFound: ids of another org's gateways
// are NotFound to every use case.
func TestT037_GatewaysOfAnotherOrgAreNotFound(t *testing.T) {
	e := newEnv(t)
	_, id := e.enroll(t, "edge")
	other := &env{pool: e.pool, svc: e.svc, org: ids.New[ids.Org]()}
	other.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", other.org)
	intruder := other.caller(td.KindUser, td.RoleGatewayAdmin)
	if _, err := e.svc.GetGateway(intruder, id.Gateway); !errors.Is(err, app.ErrGatewayNotFound) {
		t.Errorf("get: %v", err)
	}
	if _, err := e.svc.CreateEnrollmentToken(intruder, id.Gateway); !errors.Is(err, app.ErrGatewayNotFound) {
		t.Errorf("token: %v", err)
	}
	if _, err := e.svc.RevokeGateway(intruder, id.Gateway, "x"); !errors.Is(err, app.ErrGatewayNotFound) {
		t.Errorf("revoke: %v", err)
	}
	if err := e.svc.RevokeCertificate(intruder, id.Gateway, id.Cert); !errors.Is(err, app.ErrCertNotFound) {
		t.Errorf("revoke certificate: %v", err)
	}
	if err := e.svc.Authenticate(context.Background(), id); err != nil {
		t.Fatalf("the gateway was harmed by another org's calls: %v", err)
	}
}

// TestIntGatewaysListInPages: the first page starts at the beginning (the
// zero cursor is SQL NULL), pages follow each other, and revoked gateways
// are listed only on request.
func TestIntGatewaysListInPages(t *testing.T) {
	e := newEnv(t)
	var made []ids.UUID
	for _, name := range []string{"a", "b", "c"} {
		g, err := e.svc.CreateGateway(e.admin, name)
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, g.ID)
	}
	if _, err := e.svc.RevokeGateway(e.admin, made[2], "test"); err != nil {
		t.Fatal(err)
	}
	first, _, next, err := e.svc.ListGateways(e.admin, 1, "", false)
	if err != nil || len(first) != 1 || first[0].ID != made[0] || next == "" {
		t.Fatalf("first page: %d %q %v", len(first), next, err)
	}
	second, _, next, err := e.svc.ListGateways(e.admin, 1, next, false)
	if err != nil || len(second) != 1 || second[0].ID != made[1] || next != "" {
		t.Fatalf("second page: %d %q %v", len(second), next, err)
	}
	all, _, _, err := e.svc.ListGateways(e.admin, 0, "", true)
	if err != nil || len(all) != 3 {
		t.Fatalf("with revoked: %d %v", len(all), err)
	}
}
