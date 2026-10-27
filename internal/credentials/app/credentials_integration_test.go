// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/credentials/app"
	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	gapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

type notes struct {
	mu    sync.Mutex
	types []string
}

func (n *notes) Enqueue(_ context.Context, _ db.TenantTx, m napp.Message) (napp.Enqueued, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.types = append(n.types, m.Type)
	return napp.Enqueued{}, nil
}

func (n *notes) count(typ string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, t := range n.types {
		if t == typ {
			c++
		}
	}
	return c
}

type env struct {
	pool    *db.Pool
	svc     *app.Service
	conns   *capp.Service
	notes   *notes
	org     ids.OrgID
	gateway ids.UUID
	key     *pccrypto.SealPrivateKey
	keyID   ids.UUID
	sealer  context.Context // a person who seals and manages
	conn    capp.Connection
}

func newEnv(t *testing.T) *env {
	t.Helper()
	d := dbtest.New(t)
	e := &env{pool: d.AppPool(t), notes: &notes{}}
	e.svc = app.New(e.pool, e.notes)
	e.conns = capp.New(e.pool, e.notes, "https://pc.example.test", "https://gw.example.test:8443")
	return e.withOrg(t)
}

// withOrg is a new org in the same database: a gateway with a registered
// broker key, the mock-payments package pinned and one held connection.
func (e *env) withOrg(t *testing.T) *env {
	t.Helper()
	o := &env{pool: e.pool, svc: e.svc, conns: e.conns, notes: e.notes, org: ids.New[ids.Org](), gateway: ids.NewV7()}
	o.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'credentials')", o.org)
	o.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", o.org, o.gateway)
	o.key, o.keyID = o.registerBrokerKey(t)
	pkg, ver := ids.NewV7(), ids.NewV7()
	raw := mockpayments.Package
	o.exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, $3)", o.org, pkg, mockpayments.Name)
	o.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`, o.org, ver, pkg, mockpayments.Version, manifest.FileDigest(raw), raw)
	o.exec(t, "INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, $4, $5)",
		o.org, pkg, ver, mockpayments.Version, manifest.FileDigest(raw))
	o.sealer = o.caller(td.KindUser, td.RoleGatewayAdmin)
	c, err := o.conns.Create(o.sealer, capp.CreateInput{
		Name: "payments", Kind: capp.KindHTTP, Package: mockpayments.Name, BaseURL: "https://payments.example.test", Gateway: o.gateway,
		AccessMode: capp.AccessHeld, CredentialHeader: "Authorization", CredentialScheme: "Bearer",
	})
	if err != nil {
		t.Fatal(err)
	}
	o.conn = c
	return o
}

// registerBrokerKey retires the gateway's broker key and registers a new
// one, as the gateway does over mTLS (slice 4).
func (e *env) registerBrokerKey(t *testing.T) (*pccrypto.SealPrivateKey, ids.UUID) {
	t.Helper()
	key, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, id := ids.NewV7(), ids.NewV7()
	serial := make([]byte, 16)
	_, _ = rand.Read(serial)
	e.exec(t, `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, 'ENROLL', now(), now() + interval '24 hours')`, e.org, cert, e.gateway, serial, strings.Repeat("A", 43))
	pub := key.PublicKey().Bytes()
	sum := sha256.Sum256(pub)
	e.exec(t, "UPDATE pc.broker_keys SET state = 'RETIRED', retired_at = now() WHERE gateway_id = $1 AND state = 'ACTIVE'", e.gateway)
	e.exec(t, `INSERT INTO pc.broker_keys (org_id, id, gateway_id, version, public_key, fingerprint, cert_id)
		VALUES ($1, $2, $3, (SELECT coalesce(max(version), 0) + 1 FROM pc.broker_keys WHERE gateway_id = $3), $4, $5, $6)`,
		e.org, id, e.gateway, pub, "sha256:"+hex.EncodeToString(sum[:]), cert)
	return key, id
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

func (e *env) epoch(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org); err != nil {
			return err
		}
		return tx.QueryRow(ctx, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", e.org).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// seal does what pclaw seal does.
func (e *env) seal(t *testing.T, secret string) (app.SealingKey, app.PutInput) {
	t.Helper()
	k, err := e.svc.GetSealingKey(e.sealer, e.conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := pccrypto.Seal(pub, k.Binding.Info(), domain.AAD, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	brokerKey, _ := ids.ParseUUID(k.Binding.BrokerKey)
	return k, app.PutInput{
		Connection: e.conn.ID, BrokerKey: brokerKey, Version: k.Binding.Version, Sealed: sealed,
		AllowedHosts: k.Binding.AllowedHosts, Header: k.Binding.Header, Scheme: k.Binding.Scheme,
	}
}

func is(err, want error) bool { return errors.Is(err, want) }

func denied(err error) bool {
	var pe *pcerr.Error
	return errors.As(err, &pe) && pe.Code() == pcerr.PermissionDenied
}

// TestHR182_ASealedCredentialIsBoundToItsConnectionAndOpensOnTheGateway:
// the sealing key names the gateway's active broker key, the next version
// and the connection's binding; the server stores the blob, which only the
// broker key opens, and returns metadata only.
func TestHR182_ASealedCredentialIsBoundToItsConnectionAndOpensOnTheGateway(t *testing.T) {
	e := newEnv(t)
	k, in := e.seal(t, "sk_live_first")
	if k.Binding.Version != 1 || k.Binding.BrokerKey != e.keyID.String() || k.Binding.Org != e.org.String() ||
		strings.Join(k.Binding.AllowedHosts, ",") != "payments.example.test" || k.Binding.Header != "Authorization" || k.Binding.Scheme != "Bearer" ||
		k.Gateway != e.gateway {
		t.Fatalf("sealing key %+v", k)
	}
	m, err := e.svc.PutCredential(e.sealer, in)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != 1 || m.State != "ACTIVE" || m.BrokerKeyFingerprint != k.Fingerprint {
		t.Fatalf("stored %+v", m)
	}
	var stored []byte
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT sealed FROM pc.credentials WHERE id = $1", m.ID).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := pccrypto.Open(e.key, k.Binding.Info(), domain.AAD, stored); err != nil || string(got) != "sk_live_first" {
		t.Fatalf("the gateway cannot open what was stored: %q %v", got, err)
	}
	if e.notes.count("security.connection_weakened") != 0 {
		t.Fatal("a first credential is not a replacement")
	}
	if _, err := e.svc.PutCredential(e.sealer, in); !is(err, app.ErrStale) {
		t.Fatalf("the same version twice: %v", err)
	}
}

// TestHR183_ReplacingIsWeakeningAndRevokingRaisesTheEpoch: a new version
// supersedes the active one and is notified; revoking raises the epoch.
func TestHR183_ReplacingIsWeakeningAndRevokingRaisesTheEpoch(t *testing.T) {
	e := newEnv(t)
	_, first := e.seal(t, "one")
	if _, err := e.svc.PutCredential(e.sealer, first); err != nil {
		t.Fatal(err)
	}
	_, second := e.seal(t, "two")
	if second.Version != 2 {
		t.Fatalf("next version %d", second.Version)
	}
	if _, err := e.svc.PutCredential(e.sealer, second); err != nil {
		t.Fatal(err)
	}
	if e.notes.count("security.connection_weakened") != 1 {
		t.Fatal("replacing a credential is not notified")
	}
	list, err := e.svc.ListCredentials(e.caller(td.KindUser, td.RoleDeveloper), e.conn.ID)
	if err != nil || len(list) != 2 || list[0].Version != 2 || list[0].State != "ACTIVE" || list[1].State != "SUPERSEDED" {
		t.Fatalf("list %+v %v", list, err)
	}
	epoch := e.epoch(t)
	if err := e.svc.RevokeCredential(e.sealer, e.conn.ID, 2); err != nil || e.epoch(t) != epoch+1 {
		t.Fatalf("revoke: %v", err)
	}
	if err := e.svc.RevokeCredential(e.sealer, e.conn.ID, 2); !is(err, app.ErrCredentialNotFound) {
		t.Fatalf("revoke twice: %v", err)
	}
}

// TestHR182_UploadsMustMatchTheCurrentBinding: a blob for a superseded
// broker key, a changed host list or placement, or a wrong version is
// refused, as is anything that is not a sealed credential.
func TestHR182_UploadsMustMatchTheCurrentBinding(t *testing.T) {
	e := newEnv(t)
	_, in := e.seal(t, "x")

	bad := in
	bad.Sealed = append([]byte{0x03}, in.Sealed[1:]...) // no such blob version (1 and 2 exist, D35)
	if _, err := e.svc.PutCredential(e.sealer, bad); !is(err, app.ErrFormat) {
		t.Errorf("format: %v", err)
	}
	bad = in
	bad.AllowedHosts = []string{"evil.example.test"}
	if _, err := e.svc.PutCredential(e.sealer, bad); !is(err, app.ErrBinding) {
		t.Errorf("hosts: %v", err)
	}
	bad = in
	bad.Header = "X-Api-Key"
	if _, err := e.svc.PutCredential(e.sealer, bad); !is(err, app.ErrBinding) {
		t.Errorf("header: %v", err)
	}
	bad = in
	bad.Version = 7
	if _, err := e.svc.PutCredential(e.sealer, bad); !is(err, app.ErrStale) {
		t.Errorf("version: %v", err)
	}
	e.registerBrokerKey(t) // the gateway rotated its broker key meanwhile
	if _, err := e.svc.PutCredential(e.sealer, in); !is(err, app.ErrStaleKey) {
		t.Errorf("rotated broker key: %v", err)
	}
	if _, err := e.svc.GetSealingKey(e.sealer, e.conn.ID); err != nil {
		t.Errorf("sealing after a rotation: %v", err)
	}
}

// TestHR182_ARevokedGatewaysBrokerKeyIsNeverSealedTo: revoking a gateway
// retires its broker keys in the same transaction, audited, because its
// private key may have left with it. Its connections then get no sealing
// key and take no upload, not even one sealed before the revocation; so
// does a gateway revoked while its key stayed active. Another gateway of
// the org is unaffected.
func TestHR182_ARevokedGatewaysBrokerKeyIsNeverSealedTo(t *testing.T) {
	e := newEnv(t)
	live := *e
	live.gateway = ids.NewV7()
	live.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'live', 'test')", live.org, live.gateway)
	live.key, live.keyID = live.registerBrokerKey(t)
	c, err := e.conns.Create(e.sealer, capp.CreateInput{
		Name: "payments-live", Kind: capp.KindHTTP, Package: mockpayments.Name, BaseURL: "https://live.example.test", Gateway: live.gateway,
		AccessMode: capp.AccessHeld, CredentialHeader: "Authorization", CredentialScheme: "Bearer",
	})
	if err != nil {
		t.Fatal(err)
	}
	live.conn = c

	_, before := e.seal(t, "sealed before the revocation")
	if _, err := gapp.New(e.pool, nil, "", nil).RevokeGateway(e.sealer, e.gateway, "stolen"); err != nil {
		t.Fatal(err)
	}
	var active, retired int
	var audited *string
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'ACTIVE'), count(*) FILTER (WHERE state = 'RETIRED')
			FROM pc.broker_keys WHERE gateway_id = $1`, e.gateway).Scan(&active, &retired); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT convert_from(body, 'UTF8')::jsonb -> 'details' ->> 'broker_keys' FROM pc.ledger_entries
			WHERE kind = 'audit.gateway.revoked' ORDER BY occurred_at DESC, id DESC LIMIT 1`).Scan(&audited)
	}); err != nil {
		t.Fatal(err)
	}
	if active != 0 || retired != 1 || audited == nil || *audited != "1" {
		t.Fatalf("after the revocation: %d active and %d retired broker keys, audited %v", active, retired, audited)
	}
	if _, err := e.svc.GetSealingKey(e.sealer, e.conn.ID); !is(err, app.ErrGatewayRevoked) {
		t.Errorf("sealing key of a revoked gateway: %v", err)
	}
	if _, err := e.svc.PutCredential(e.sealer, before); !is(err, app.ErrGatewayRevoked) {
		t.Errorf("upload sealed before the revocation: %v", err)
	}
	if _, in := live.seal(t, "live"); in.BrokerKey != live.keyID {
		t.Fatalf("the live gateway's sealing key is %s, want %s", in.BrokerKey, live.keyID)
	} else if _, err := live.svc.PutCredential(live.sealer, in); err != nil {
		t.Fatalf("upload for the live gateway: %v", err)
	}

	// A gateway revoked while its broker key stayed active.
	other := e.withOrg(t)
	_, early := other.seal(t, "x")
	other.exec(t, "UPDATE pc.gateways SET state = 'REVOKED', revoked_at = now(), revoked_by = 'test', revoke_reason = 'lost' WHERE id = $1",
		other.gateway)
	if _, err := other.svc.GetSealingKey(other.sealer, other.conn.ID); !is(err, app.ErrGatewayRevoked) {
		t.Errorf("sealing key of a revoked gateway with an active key: %v", err)
	}
	if _, err := other.svc.PutCredential(other.sealer, early); !is(err, app.ErrGatewayRevoked) {
		t.Errorf("upload to a revoked gateway with an active key: %v", err)
	}
}

// TestHR182_OnlyHeldConnectionsTakeCredentialsAndOnlyPeopleSeal: sealing
// needs credential.seal (human only); a connection that is not
// pantherclaw_held, or whose gateway has no broker key, takes none; another
// org's connection is not found (T-037).
func TestHR182_OnlyHeldConnectionsTakeCredentialsAndOnlyPeopleSeal(t *testing.T) {
	e := newEnv(t)
	if _, err := e.svc.GetSealingKey(e.caller(td.KindServiceAccount, td.RoleGatewayAdmin), e.conn.ID); !denied(err) {
		t.Errorf("service account: %v", err)
	}
	if _, err := e.svc.GetSealingKey(e.caller(td.KindUser, td.RoleDeveloper), e.conn.ID); !denied(err) {
		t.Errorf("developer: %v", err)
	}
	none, err := e.conns.Create(e.sealer, capp.CreateInput{
		Name: "open", Kind: capp.KindHTTP, Package: mockpayments.Name, BaseURL: "https://open.example.test", Gateway: e.gateway,
		AccessMode: capp.AccessNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.GetSealingKey(e.sealer, none.ID); !is(err, app.ErrNotHeld) {
		t.Errorf("access none: %v", err)
	}
	e.exec(t, "UPDATE pc.broker_keys SET state = 'RETIRED', retired_at = now() WHERE gateway_id = $1", e.gateway)
	if _, err := e.svc.GetSealingKey(e.sealer, e.conn.ID); !is(err, app.ErrNoBrokerKey) {
		t.Errorf("no broker key: %v", err)
	}
	other := e.withOrg(t)
	if _, err := e.svc.GetSealingKey(e.sealer, other.conn.ID); !is(err, app.ErrConnectionNotFound) {
		t.Errorf("another org's sealing key: %v", err)
	}
	if _, err := e.svc.ListCredentials(e.sealer, other.conn.ID); !is(err, app.ErrConnectionNotFound) {
		t.Errorf("another org's credentials: %v", err)
	}
	if err := e.svc.RevokeCredential(e.sealer, other.conn.ID, 1); !is(err, app.ErrConnectionNotFound) {
		t.Errorf("another org's revoke: %v", err)
	}
}
