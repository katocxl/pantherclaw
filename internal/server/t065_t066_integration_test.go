// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/connections/adapters/connectionsrpc"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateways/adapters/gatewaysrpc"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// The T-065 (rogue or stale gateway) and T-066 (credential custody)
// scenarios, told through the real gateway listener (mTLS, the
// certificate-row check), the public enrollment RPC, and the gateway,
// connection and credential services behind them.

// m6Threat is one org on a running gateway listener (newM6Env).
type m6Threat struct {
	*m6Env
}

func newM6Threat(t *testing.T) *m6Threat { return &m6Threat{newM6Env(t)} }

// anotherOrg is a second org on the same server, database and listener,
// with its own Gateway Admin.
func (w *m6Threat) anotherOrg(t *testing.T) *m6Threat {
	t.Helper()
	o := &m6Env{m6: w.m6, pool: w.pool, org: ids.New[ids.Org](), url: w.url}
	o2 := &m6Threat{o}
	o2.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'm6-other')", o.org)
	o.admin = tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: o.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: o.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	return o2
}

func (w *m6Threat) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (w *m6Threat) count(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (w *m6Threat) epoch(t *testing.T) int64 {
	t.Helper()
	w.exec(t, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", w.org)
	return w.count(t, "SELECT epoch FROM pc.org_containment WHERE org_id = $1", w.org)
}

// publicGateways is GatewayService on a public API whose authenticator
// knows no one, as in TestHR181_ThePublicAPINeverActsAsAGateway: only
// Enroll reaches its handler, authenticated by its token.
func (w *m6Threat) publicGateways(t *testing.T) pantherclawv1connect.GatewayServiceClient {
	t.Helper()
	rs, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(denyAll{}, procedurePermissions, nil)})
	if err != nil {
		t.Fatal(err)
	}
	w.m6.registerPublic(rs)
	mux := http.NewServeMux()
	rpc.Mount(mux, rs)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return pantherclawv1connect.NewGatewayServiceClient(connect.NewClient(connecthttp.NewTransport(srv.Client(), srv.URL)))
}

// newCSR is a new gateway key and a certificate request it signed.
func newCSR(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, csr
}

// enrollWith enrolls a new key with token over the public API, as
// pantherclaw-gateway enroll does.
func enrollWith(t *testing.T, public pantherclawv1connect.GatewayServiceClient, token string) (tls.Certificate, ca.Identity, error) {
	t.Helper()
	priv, csr := newCSR(t)
	res, err := public.Enroll(context.Background(), &pantherclawv1.GatewayServiceEnrollRequest{Token: token, Csr: csr})
	if err != nil {
		return tls.Certificate{}, ca.Identity{}, err
	}
	id, err := ca.ParseIdentity(mustParse(res.GetCertificate()))
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{res.GetCertificate()}, PrivateKey: priv}, id, nil
}

func (w *m6Threat) authorityClient(certs ...tls.Certificate) pantherclawv1connect.AuthorityServiceClient {
	roots := x509.NewCertPool()
	roots.AddCert(mustParse(w.m6.ca.Certificate()))
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS13},
	}}
	return pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(hc, w.url)))
}

// gatewayCalls are the calls a gateway makes over the listener, each
// returning its error.
func (w *m6Threat) gatewayCalls(t *testing.T, cert tls.Certificate) map[string]func() error {
	t.Helper()
	gc, ac := w.client(cert), w.authorityClient(cert)
	ctx := context.Background()
	_, csr := newCSR(t)
	return map[string]func() error{
		"RegisterBrokerKey": func() error {
			_, err := gc.RegisterBrokerKey(ctx, &pantherclawv1.RegisterBrokerKeyRequest{PublicKey: brokerKey(t)})
			return err
		},
		"GetConfiguration": func() error {
			_, err := gc.GetConfiguration(ctx, &pantherclawv1.GetConfigurationRequest{})
			return err
		},
		"RenewCertificate": func() error {
			_, err := gc.RenewCertificate(ctx, &pantherclawv1.RenewCertificateRequest{Csr: csr})
			return err
		},
		"ReportCircuit": func() error {
			_, err := gc.ReportCircuit(ctx, &pantherclawv1.ReportCircuitRequest{ConnectionId: ids.NewV7().String(), UnknownCount: 5, TotalCount: 5})
			return err
		},
		"WatchContainment": func() error {
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			st, err := gc.WatchContainment(sctx, &pantherclawv1.WatchContainmentRequest{})
			if err != nil {
				return err
			}
			defer func() { _ = st.Close() }()
			_, err = st.Receive()
			return err
		},
		"Authority.GetNonce": func() error {
			_, err := ac.GetNonce(ctx, &pantherclawv1.GetNonceRequest{})
			return err
		},
	}
}

// pinMockPayments pins the mock-payments package in the org.
func (w *m6Threat) pinMockPayments(t *testing.T) {
	t.Helper()
	pkg, ver, raw := ids.NewV7(), ids.NewV7(), mockpayments.Package
	w.exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, $3)", w.org, pkg, mockpayments.Name)
	w.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`, w.org, ver, pkg, mockpayments.Version, manifest.FileDigest(raw), raw)
	w.exec(t, "INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, $4, $5)",
		w.org, pkg, ver, mockpayments.Version, manifest.FileDigest(raw))
}

// heldConnection is a pantherclaw_held connection of gateway gw to host.
func (w *m6Threat) heldConnection(t *testing.T, name string, gw ids.UUID, host string) ids.UUID {
	t.Helper()
	c, err := w.m6.connections.Create(w.admin, capp.CreateInput{
		Name: name, Kind: capp.KindHTTP, Package: mockpayments.Name, BaseURL: "https://" + host, Gateway: gw,
		AccessMode: capp.AccessHeld, CredentialHeader: "Authorization", CredentialScheme: "Bearer",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c.ID
}

// custodian is an enrolled gateway with its broker key file, registered
// over its own mTLS identity as pantherclaw-gateway does at start.
type custodian struct {
	cert  tls.Certificate
	id    ca.Identity
	key   *broker.Key
	keyID string
}

func (w *m6Threat) custodian(t *testing.T, name string) custodian {
	t.Helper()
	cert, gw := w.identity(t, name)
	id, err := ca.ParseIdentity(mustParse(cert.Certificate[0]))
	if err != nil || id.Gateway != gw {
		t.Fatalf("identity %+v %v", id, err)
	}
	dir := t.TempDir()
	kek, path := filepath.Join(dir, "kek"), filepath.Join(dir, "broker.json")
	if err := keys.GenerateKEKFile(kek); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Generate(context.Background(), path, []string{kek}); err != nil {
		t.Fatal(err)
	}
	key, err := broker.Load(context.Background(), path, []string{kek})
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.client(cert).RegisterBrokerKey(context.Background(), &pantherclawv1.RegisterBrokerKeyRequest{PublicKey: key.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	return custodian{cert: cert, id: id, key: key, keyID: res.GetBrokerKey().GetId()}
}

// seal does what pclaw seal does for connection: read the sealing key,
// seal secret to it locally, and return the upload.
func (w *m6Threat) seal(t *testing.T, conn ids.UUID, secret string) credapp.PutInput {
	t.Helper()
	k, err := w.m6.credentials.GetSealingKey(w.admin, conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := pccrypto.Seal(pub, k.Binding.Info(), creddomain.AAD, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	bk, err := ids.ParseUUID(k.Binding.BrokerKey)
	if err != nil {
		t.Fatal(err)
	}
	return credapp.PutInput{
		Connection: conn, BrokerKey: bk, Version: k.Binding.Version, Sealed: sealed,
		AllowedHosts: k.Binding.AllowedHosts, Header: k.Binding.Header, Scheme: k.Binding.Scheme,
	}
}

// rebind is blob uploaded as connection's next version: everything the
// server checks (broker key, version, hosts, placement) is the
// connection's own, only the sealed bytes come from elsewhere.
func (w *m6Threat) rebind(t *testing.T, conn ids.UUID, blob []byte) credapp.PutInput {
	t.Helper()
	in := w.seal(t, conn, "placeholder")
	in.Sealed = blob
	return in
}

// open fetches the gateway's configuration over mTLS and opens the active
// credential of conn as its dispatch does (dispatch.openCredential): the
// org from its certificate, the connection id and the credential's hosts
// and placement from the configuration, and its own broker key id.
func (w *m6Threat) open(t *testing.T, c custodian, conn ids.UUID) ([]byte, error) {
	t.Helper()
	cfg, err := w.client(c.cert).GetConfiguration(context.Background(), &pantherclawv1.GetConfigurationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, cr := range cfg.GetCredentials() {
		if cr.GetConnectionId() == conn.String() {
			return c.key.Open(c.id.Org.String(), conn.String(), cr.GetAllowedHosts(), c.keyID, broker.Sealed{
				Version: cr.GetVersion(), BrokerKey: cr.GetBrokerKeyId(), Blob: cr.GetSealed(), Header: cr.GetHeader(), Scheme: cr.GetScheme(),
			})
		}
	}
	t.Fatalf("the configuration carries no credential for connection %s", conn)
	return nil, nil
}

// TestT065_AThiefWhoEnrollsFirstIsCutOffByRevocation: an enrollment token
// read off the operator's screen is used first (T-065). The thief's
// gateway is indistinguishable on the wire, so it registers its own broker
// key. The operator's enrollment then fails exactly like a made-up token,
// the reuse is audited, and the admin sees the thief's certificate and the
// broker key fingerprint a person sealing would be shown (and pclaw seal
// --fingerprint compares). Revoking the gateway raises the epoch and
// refuses every call the thief's certificate makes on the gateway
// listener, the stream and the Authority included.
func TestT065_AThiefWhoEnrollsFirstIsCutOffByRevocation(t *testing.T) {
	w := newM6Threat(t)
	ctx := context.Background()
	w.pinMockPayments(t)
	public := w.publicGateways(t)
	g, err := w.m6.gateways.CreateGateway(w.admin, "edge")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := w.m6.gateways.CreateEnrollmentToken(w.admin, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn := w.heldConnection(t, "payments", g.ID, "payments.example.test")

	thief, thiefID, err := enrollWith(t, public, tok.Secret.Reveal())
	if err != nil || thiefID.Gateway != g.ID || thiefID.Org != w.org {
		t.Fatalf("the first use of the token: %+v %v", thiefID, err)
	}
	attackerKey := brokerKey(t)
	if _, err := w.client(thief).RegisterBrokerKey(ctx, &pantherclawv1.RegisterBrokerKeyRequest{PublicKey: attackerKey}); err != nil {
		t.Fatalf("the thief's gateway registers its broker key: %v", err)
	}
	if _, err := w.client(thief).GetConfiguration(ctx, &pantherclawv1.GetConfigurationRequest{}); err != nil {
		t.Fatalf("the thief's gateway gets its configuration: %v", err)
	}

	// The operator's own enrollment: refused, and indistinguishable from a
	// token that was never issued.
	_, _, reused := enrollWith(t, public, tok.Secret.Reveal())
	never, err := credential.New(credential.GatewayEnrollmentToken, "", w.org)
	if err != nil {
		t.Fatal(err)
	}
	_, _, unknown := enrollWith(t, public, never.Reveal())
	if reused == nil || unknown == nil || connect.CodeOf(reused) != connect.CodeUnauthenticated || reused.Error() != unknown.Error() {
		t.Fatalf("the operator's enrollment: %v; a never-issued token: %v", reused, unknown)
	}
	if n := w.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.security.gateway_enrollment_reused'
		AND position($1 in convert_from(body, 'UTF8')) > 0`, g.ID.String()); n != 1 {
		t.Fatalf("the reuse of the gateway's token is audited %d times", n)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.gateway_certs WHERE gateway_id = $1", g.ID); n != 1 {
		t.Fatalf("%d certificates after the reuse", n)
	}

	// What the admin and a person sealing a credential see: a certificate
	// they did not get and a broker key fingerprint that is not the
	// operator's.
	d, err := w.m6.gateways.GetGateway(w.admin, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Certificates) != 1 || d.Certificates[0].ID != thiefID.Cert || len(d.BrokerKeys) != 1 ||
		d.BrokerKeys[0].CertID != thiefID.Cert || d.BrokerKeys[0].Fingerprint != gwapp.Fingerprint(attackerKey) {
		t.Fatalf("the gateway as the admin sees it: %+v", d)
	}
	k, err := w.m6.credentials.GetSealingKey(w.admin, conn)
	if err != nil || k.Fingerprint != gwapp.Fingerprint(attackerKey) {
		t.Fatalf("the sealing key a person is shown: %q %v", k.Fingerprint, err)
	}

	epoch := w.epoch(t)
	if _, err := w.m6.gateways.RevokeGateway(w.admin, g.ID, "enrolled by someone else"); err != nil {
		t.Fatal(err)
	}
	if got := w.epoch(t); got != epoch+1 {
		t.Fatalf("revoking the gateway moved the epoch %d -> %d", epoch, got)
	}
	for name, call := range w.gatewayCalls(t, thief) {
		if err := call(); connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Errorf("%s with the thief's certificate after the revocation: %v", name, err)
		}
	}
	if _, err := w.m6.gateways.CreateEnrollmentToken(w.admin, g.ID); !errors.Is(err, gwapp.ErrGatewayRevoked) {
		t.Fatalf("a new token for the revoked gateway: %v", err)
	}
}

// TestT065_ACopiedGatewayKeyShowsAtRenewalAndDiesWithItsGateway: the
// certificate and key are copied off the gateway's host (T-065). The thief
// renews first with a key of its own; the operator's next renewal is then
// refused (only the current certificate renews), and the admin sees a
// renewal the operator did not make. The copy still works within its
// renewal grace, so revoking the gateway must refuse both the thief's
// renewed certificate and the copied one on every call.
func TestT065_ACopiedGatewayKeyShowsAtRenewalAndDiesWithItsGateway(t *testing.T) {
	w := newM6Threat(t)
	ctx := context.Background()
	operator, gw := w.identity(t, "edge")
	copied := operator
	opID, err := ca.ParseIdentity(mustParse(operator.Certificate[0]))
	if err != nil {
		t.Fatal(err)
	}

	priv, csr := newCSR(t)
	res, err := w.client(copied).RenewCertificate(ctx, &pantherclawv1.RenewCertificateRequest{Csr: csr})
	if err != nil {
		t.Fatalf("the thief renews with the copied certificate: %v", err)
	}
	renewed := tls.Certificate{Certificate: [][]byte{res.GetCertificate()}, PrivateKey: priv}
	renewedID, err := ca.ParseIdentity(mustParse(res.GetCertificate()))
	if err != nil || renewedID.Gateway != gw || renewedID.Cert == opID.Cert {
		t.Fatalf("renewed identity %+v %v", renewedID, err)
	}
	_, csr = newCSR(t)
	if _, err := w.client(operator).RenewCertificate(ctx, &pantherclawv1.RenewCertificateRequest{Csr: csr}); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatalf("the operator's renewal after the thief's: %v", err)
	}
	d, err := w.m6.gateways.GetGateway(w.admin, gw)
	if err != nil {
		t.Fatal(err)
	}
	states := map[ids.UUID]string{}
	for _, c := range d.Certificates {
		states[c.ID] = c.State
		if c.ID == renewedID.Cert && (c.IssuedVia != "RENEW" || c.PreviousID == nil || *c.PreviousID != opID.Cert) {
			t.Fatalf("the thief's certificate as the admin sees it: %+v", c)
		}
	}
	if len(states) != 2 || states[opID.Cert] != "SUPERSEDED" || states[renewedID.Cert] != "ACTIVE" {
		t.Fatalf("certificates %v", states)
	}
	if _, err := w.client(copied).GetConfiguration(ctx, &pantherclawv1.GetConfigurationRequest{}); err != nil {
		t.Fatalf("the copy within its renewal grace: %v", err)
	}

	if _, err := w.m6.gateways.RevokeGateway(w.admin, gw, "key copied"); err != nil {
		t.Fatal(err)
	}
	for who, cert := range map[string]tls.Certificate{"renewed": renewed, "copied": copied} {
		for name, call := range w.gatewayCalls(t, cert) {
			if err := call(); connect.CodeOf(err) != connect.CodeUnauthenticated {
				t.Errorf("%s with the %s certificate after the revocation: %v", name, who, err)
			}
		}
	}
}

// TestT066_ASealedCredentialMovedElsewhereNeverOpens: whoever can upload
// sealed bytes (a Gateway Admin, or anyone replaying an old upload) moves
// a credential sealed for one binding to another (T-066). The server
// cannot open what it stores, so it accepts each upload whose metadata
// fits; the gateway, which rebuilds the binding from its certificate and
// configuration, opens none of them: a blob moved to another connection
// on the same gateway and host, an old version replayed as the next one
// after a rotation, and a blob moved into another org's connection.
func TestT066_ASealedCredentialMovedElsewhereNeverOpens(t *testing.T) {
	w := newM6Threat(t)
	w.pinMockPayments(t)
	gw := w.custodian(t, "edge")
	a := w.heldConnection(t, "payments", gw.id.Gateway, "payments.example.test")
	b := w.heldConnection(t, "payouts", gw.id.Gateway, "payments.example.test")

	first := w.seal(t, a, "pc-test-credential-a1")
	if _, err := w.m6.credentials.PutCredential(w.admin, first); err != nil {
		t.Fatal(err)
	}
	if got, err := w.open(t, gw, a); err != nil || string(got) != "pc-test-credential-a1" {
		t.Fatalf("the gateway opens connection a's own credential: %q %v", got, err)
	}

	// Moved to another connection of the same gateway, with the same host.
	if _, err := w.m6.credentials.PutCredential(w.admin, w.rebind(t, b, first.Sealed)); err != nil {
		t.Fatalf("the upload for connection b: %v", err)
	}
	if got, err := w.open(t, gw, b); !errors.Is(err, broker.ErrOpen) || got != nil {
		t.Fatalf("a's credential opened for connection b: %q %v", got, err)
	}

	// Rotated, then the old version replayed as the next one.
	if _, err := w.m6.credentials.PutCredential(w.admin, w.seal(t, a, "pc-test-credential-a2")); err != nil {
		t.Fatal(err)
	}
	if got, err := w.open(t, gw, a); err != nil || string(got) != "pc-test-credential-a2" {
		t.Fatalf("the rotated credential: %q %v", got, err)
	}
	replay := w.rebind(t, a, first.Sealed)
	if replay.Version != 3 {
		t.Fatalf("the replay is version %d", replay.Version)
	}
	if _, err := w.m6.credentials.PutCredential(w.admin, replay); err != nil {
		t.Fatalf("the replayed upload: %v", err)
	}
	if got, err := w.open(t, gw, a); !errors.Is(err, broker.ErrOpen) || got != nil {
		t.Fatalf("version 1 opened as version 3: %q %v", got, err)
	}

	// Moved into another org's connection to the same host.
	o := w.anotherOrg(t)
	o.pinMockPayments(t)
	ogw := o.custodian(t, "edge")
	c := o.heldConnection(t, "payments", ogw.id.Gateway, "payments.example.test")
	if _, err := o.m6.credentials.PutCredential(o.admin, o.rebind(t, c, first.Sealed)); err != nil {
		t.Fatalf("the upload in another org: %v", err)
	}
	if got, err := o.open(t, ogw, c); !errors.Is(err, broker.ErrOpen) || got != nil {
		t.Fatalf("a's credential opened in another org: %q %v", got, err)
	}
}

// TestT066_NoUserFacingAPIReturnsSealedBytes: a person who may manage the
// gateway and its connections reads everything the public API offers
// about them (T-066, HR-061). No response, and no audit record, carries
// the sealed bytes or the credential; only the owning gateway's
// configuration over mTLS carries the sealed bytes.
func TestT066_NoUserFacingAPIReturnsSealedBytes(t *testing.T) {
	w := newM6Threat(t)
	ctx := w.admin
	w.pinMockPayments(t)
	gw := w.custodian(t, "edge")
	conn := w.heldConnection(t, "payments", gw.id.Gateway, "payments.example.test")
	const secret = "pc-test-credential-not-real"

	api := connectionsrpc.New(w.m6.connections, w.m6.credentials)
	admin := gatewaysrpc.NewAdmin(w.m6.gateways)
	var responses []proto.Message
	keep := func(m proto.Message, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		responses = append(responses, m)
	}
	k, err := api.GetSealingKey(ctx, &pantherclawv1.GetSealingKeyRequest{ConnectionId: conn.String()})
	keep(k, err)
	pub, err := pccrypto.ParseSealPublicKey(k.GetPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	bind := creddomain.Binding{
		Org: k.GetOrgId(), Connection: k.GetConnectionId(), Version: k.GetVersion(), AllowedHosts: k.GetAllowedHosts(),
		BrokerKey: k.GetBrokerKeyId(), Header: k.GetHeader(), Scheme: k.GetScheme(),
	}
	sealed, err := pccrypto.Seal(pub, bind.Info(), creddomain.AAD, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	put, err := api.PutCredential(ctx, &pantherclawv1.PutCredentialRequest{
		ConnectionId: conn.String(), Version: k.GetVersion(), BrokerKeyId: k.GetBrokerKeyId(), Sealed: sealed,
		AllowedHosts: k.GetAllowedHosts(), Header: k.GetHeader(), Scheme: k.GetScheme(),
	})
	keep(put, err)
	m1, err := api.ListCredentials(ctx, &pantherclawv1.ListCredentialsRequest{ConnectionId: conn.String()})
	keep(m1, err)
	m2, err := api.GetConnection(ctx, &pantherclawv1.GetConnectionRequest{Id: conn.String()})
	keep(m2, err)
	m3, err := api.ListConnections(ctx, &pantherclawv1.ListConnectionsRequest{})
	keep(m3, err)
	m4, err := admin.GetGateway(ctx, &pantherclawv1.GetGatewayRequest{Id: gw.id.Gateway.String()})
	keep(m4, err)
	if len(m1.GetCredentials()) != 1 {
		t.Fatalf("credentials listed: %v", m1.GetCredentials())
	}

	// A window of the sealed bytes, as they would appear raw or encoded.
	window := sealed[3:51]
	encodings := [][]byte{
		window, []byte(hex.EncodeToString(window)), []byte(base64.StdEncoding.EncodeToString(window)),
		[]byte(base64.RawURLEncoding.EncodeToString(window)), []byte(secret),
	}
	leaks := func(b []byte) bool {
		for _, e := range encodings {
			if bytes.Contains(b, e) {
				return true
			}
		}
		return false
	}
	for _, m := range responses {
		raw, err := proto.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if leaks(raw) {
			t.Errorf("%T carries the sealed credential", m)
		}
	}
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, "SELECT kind, body FROM pc.ledger_entries")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var kind string
			var body []byte
			if err := rows.Scan(&kind, &body); err != nil {
				return err
			}
			if leaks(body) {
				t.Errorf("the ledger entry %s carries the sealed credential", kind)
			}
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}

	cfg, err := w.client(gw.cert).GetConfiguration(context.Background(), &pantherclawv1.GetConfigurationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.GetCredentials()) != 1 || !bytes.Equal(cfg.GetCredentials()[0].GetSealed(), sealed) {
		t.Fatalf("the owning gateway's configuration: %v", cfg.GetCredentials())
	}
	if got, err := w.open(t, gw, conn); err != nil || string(got) != secret {
		t.Fatalf("the owning gateway opens it: %v", err)
	}
}
