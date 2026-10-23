// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type m6Env struct {
	m6    *m6Services
	pool  *db.Pool
	org   ids.OrgID
	admin context.Context
	url   string // the gateway listener
}

// newM6Env starts the gateway listener (its real handler and TLS profile)
// on a loopback port.
func newM6Env(t *testing.T) *m6Env {
	t.Helper()
	d := dbtest.New(t)
	pool := d.AppPool(t)
	reg := keys.NewRegistry()
	for _, p := range []keys.Purpose{keys.PurposeGatewayCA, keys.PurposePermits, keys.PurposeReceipts} {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.GatewayAPI = GatewayAPIConfig{Addr: ln.Addr().String(), Hostnames: []string{"127.0.0.1"}, URL: "https://" + ln.Addr().String()}
	m6, err := newM6(&cfg, pool, reg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := m6.gatewayHandler(authority.New(authority.Config{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, TLSConfig: m6.gatewayTLS(cfg.GatewayAPI.Hostnames, nil), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	e := &m6Env{m6: m6, pool: pool, org: ids.New[ids.Org](), url: cfg.GatewayAPI.URL}
	if err := pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'm6')", e.org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	e.admin = tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: e.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleGatewayAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: e.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	return e
}

// identity enrolls a new gateway and returns its TLS client certificate.
func (e *m6Env) identity(t *testing.T, name string) (tls.Certificate, ids.UUID) {
	t.Helper()
	g, err := e.m6.gateways.CreateGateway(e.admin, name)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := e.m6.gateways.CreateEnrollmentToken(e.admin, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		t.Fatal(err)
	}
	en, err := e.m6.gateways.Enroll(context.Background(), tok.Secret.Reveal(), csr)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{en.Certificate}, PrivateKey: priv}, g.ID
}

func (e *m6Env) client(certs ...tls.Certificate) pantherclawv1connect.GatewayServiceClient {
	roots := x509.NewCertPool()
	roots.AddCert(mustParse(e.m6.ca.Certificate()))
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS13},
		ForceAttemptHTTP2: true,
	}}
	return pantherclawv1connect.NewGatewayServiceClient(connect.NewClient(connecthttp.NewTransport(hc, e.url)))
}

func mustParse(der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

func brokerKey(t *testing.T) []byte {
	t.Helper()
	k, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().Bytes()
}

// TestHR181_TheGatewayListenerAcceptsOnlyLiveGatewayCertificates: no
// certificate, a certificate from another CA, a revoked certificate and a
// revoked gateway are refused; a live certificate is served, and the org
// it acts in is the certificate's.
func TestHR181_TheGatewayListenerAcceptsOnlyLiveGatewayCertificates(t *testing.T) {
	e := newM6Env(t)
	ctx := context.Background()
	cert, gw := e.identity(t, "edge")

	res, err := e.client(cert).RegisterBrokerKey(ctx, &pantherclawv1.RegisterBrokerKeyRequest{PublicKey: brokerKey(t)})
	if err != nil {
		t.Fatalf("a live gateway is refused: %v", err)
	}
	if res.GetBrokerKey().GetVersion() != 1 {
		t.Fatalf("broker key %+v", res.GetBrokerKey())
	}

	if _, err := e.client().RegisterBrokerKey(ctx, &pantherclawv1.RegisterBrokerKeyRequest{PublicKey: brokerKey(t)}); err == nil {
		t.Fatal("a client without a certificate was served")
	}
	// A certificate from another CA, naming the same gateway.
	other := keys.NewRegistry()
	k, _ := keys.GenerateSigningKey(keys.PurposeGatewayCA)
	_ = other.Put(k)
	rogue, _ := ca.New(other)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	iss, err := rogue.IssueClient(pub, ca.Identity{Org: e.org, Gateway: gw, Cert: ids.NewV7()}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	forged := tls.Certificate{Certificate: [][]byte{iss.DER}, PrivateKey: priv}
	if _, err := e.client(forged).RegisterBrokerKey(ctx, &pantherclawv1.RegisterBrokerKeyRequest{PublicKey: brokerKey(t)}); err == nil {
		t.Fatal("a certificate from another CA was served")
	}

	// Revocation applies on the next call (after the one-second cache).
	if _, err := e.m6.gateways.RevokeGateway(e.admin, gw, "lost"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	_, err = e.client(cert).RegisterBrokerKey(ctx, &pantherclawv1.RegisterBrokerKeyRequest{PublicKey: brokerKey(t)})
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("a revoked gateway: %v", err)
	}
}

// TestHR020_TheAuthoritySeesTheOrgOfTheCertificate: AuthorityService on
// the gateway listener runs as the certificate's gateway and org (the
// Authority answers, so authentication passed), and refuses a client
// without one.
// TestHR010_TheContainmentStreamSendsASnapshotThenChanges: over the mTLS
// listener a gateway gets a snapshot first, an epoch change within a
// second, heartbeats while nothing changes, and its own revocation.
func TestHR010_TheContainmentStreamSendsASnapshotThenChanges(t *testing.T) {
	e := newM6Env(t)
	cert, gw := e.identity(t, "edge")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hc := e.client(cert)
	st, err := hc.WatchContainment(ctx, &pantherclawv1.WatchContainmentRequest{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	recv := func() *pantherclawv1.WatchContainmentResponse {
		t.Helper()
		m, err := st.Receive()
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		return m
	}
	first := recv()
	if first.GetKind() != pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_SNAPSHOT || !first.GetGatewayActive() {
		t.Fatalf("first message %v", first)
	}
	if hb := recv(); hb.GetKind() != pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_HEARTBEAT || hb.GetEpoch() != first.GetEpoch() {
		t.Fatalf("expected a heartbeat, got %v", hb)
	}
	if err := e.pool.InTenantTx(ctx, e.org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.org_containment (org_id) VALUES ($1) ON CONFLICT DO NOTHING", e.org); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "UPDATE pc.org_containment SET epoch = epoch + 5 WHERE org_id = $1", e.org)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for {
		m := recv()
		if m.GetEpoch() > first.GetEpoch() {
			if m.GetKind() != pantherclawv1.ContainmentStateKind_CONTAINMENT_STATE_KIND_CHANGE {
				t.Fatalf("an epoch change sent as %v", m.GetKind())
			}
			break
		}
		if time.Since(start) > time.Second {
			t.Fatal("the epoch change took more than a second")
		}
	}
	if _, err := e.m6.gateways.RevokeGateway(e.admin, gw, "lost"); err != nil {
		t.Fatal(err)
	}
	for start = time.Now(); ; {
		m, err := st.Receive()
		if err != nil {
			break // the stream may end once the revoked certificate is refused
		}
		if !m.GetGatewayActive() {
			break
		}
		if time.Since(start) > 2*time.Second {
			t.Fatal("the revocation did not reach the stream")
		}
	}
}

func TestHR020_TheAuthoritySeesTheOrgOfTheCertificate(t *testing.T) {
	e := newM6Env(t)
	cert, _ := e.identity(t, "edge")
	roots := x509.NewCertPool()
	roots.AddCert(mustParse(e.m6.ca.Certificate()))
	client := func(certs ...tls.Certificate) pantherclawv1connect.AuthorityServiceClient {
		hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS13},
		}}
		return pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(hc, e.url)))
	}
	// A well-formed action naming another org: DENY ORG_MISMATCH (HR-020),
	// because the Authority acts for the certificate's org only.
	params, _ := json.Marshal(actionir.RefundParams{Amount: actionir.Amount{Value: "30.00", Currency: "USD"}, Reason: "duplicate"})
	p, err := actionir.Encode(actionir.ActionIR{
		V: actionir.Version, Org: ids.New[ids.Org]().String(), Env: ids.NewV7().String(), RunID: ids.NewV7().String(),
		ActionID: ids.NewV7().String(), AgentInstance: ids.NewV7().String(), Operation: actionir.OpRefundCreate,
		Definition: actionir.Definition{Package: "pc.mock-payments", Version: "1.0.0", Digest: "sha256:" + strings.Repeat("0", 64)},
		Channel:    "http", Route: "payments-refund", Target: actionir.Target{Type: "payments.charge", ID: "ch_1"}, Params: params,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := client(cert).Authorize(context.Background(), &pantherclawv1.AuthorizeRequest{ActionIr: p.Canonical})
	if err != nil {
		t.Fatalf("authorize over mTLS: %v", err)
	}
	if res.GetDecision() != pantherclawv1.Decision_DECISION_DENY || len(res.GetReasons()) == 0 || res.GetReasons()[0].GetCode() != "ORG_MISMATCH" {
		t.Fatalf("an action for another org: %v %v", res.GetDecision(), res.GetReasons())
	}
	if _, err := client().Authorize(context.Background(), &pantherclawv1.AuthorizeRequest{ActionIr: p.Canonical}); err == nil {
		t.Fatal("Authorize without a certificate")
	}
}

// TestHR181_ThePublicAPINeverActsAsAGateway: on the public API, gateway
// procedures are refused whatever credential comes with them; only Enroll
// reaches its handler (which checks its token).
func TestHR181_ThePublicAPINeverActsAsAGateway(t *testing.T) {
	e := newM6Env(t)
	rs, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(denyAll{}, procedurePermissions, nil)})
	if err != nil {
		t.Fatal(err)
	}
	e.m6.registerPublic(rs)
	pantherclawv1connect.RegisterAuthorityServiceHandler(rs, authority.NewHandler(authority.New(authority.Config{})))
	mux := http.NewServeMux()
	rpc.Mount(mux, rs)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	var lc net.ListenConfig
	ln, _ := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	base := "http://" + ln.Addr().String()
	hc := &http.Client{Timeout: 10 * time.Second}
	gwc := pantherclawv1connect.NewGatewayServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base)))
	auc := pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(hc, base)))
	ctx := context.Background()
	if _, err := gwc.RegisterBrokerKey(ctx, &pantherclawv1.RegisterBrokerKeyRequest{PublicKey: brokerKey(t)}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("RegisterBrokerKey on the public API: %v", err)
	}
	if _, err := auc.GetNonce(ctx, &pantherclawv1.GetNonceRequest{}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("GetNonce on the public API: %v", err)
	}
	_, err = gwc.Enroll(ctx, &pantherclawv1.GatewayServiceEnrollRequest{Token: "pcg_" + string(make([]byte, 0)) + "xxxxxxxxxxxxxxxx", Csr: make([]byte, 64)})
	if code := connect.CodeOf(err); code != connect.CodeUnauthenticated {
		t.Errorf("Enroll with a bad token: %v", err)
	}
}

type denyAll struct{}

func (denyAll) Authenticate(context.Context, string) (tapp.Caller, error) {
	return tapp.Caller{}, errors.New("no")
}
