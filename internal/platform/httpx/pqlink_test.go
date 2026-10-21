// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// pqPair is a self-signed P-256 certificate for 127.0.0.1 and its pool.
func pqPair(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "link"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// syncBuffer is a log sink safe for both ends of a handshake.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// handshake runs one TLS handshake over an in-memory pipe and returns the
// negotiated group and both ends' errors.
func handshake(t *testing.T, server, client *tls.Config) (tls.CurveID, error, error) {
	t.Helper()
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	_ = a.SetDeadline(time.Now().Add(10 * time.Second))
	_ = b.SetDeadline(time.Now().Add(10 * time.Second))
	srv := tls.Server(a, server)
	errc := make(chan error, 1)
	go func() {
		err := srv.Handshake()
		if err != nil {
			_ = a.Close() // unblock the client
		}
		errc <- err
	}()
	cli := tls.Client(b, client)
	cerr := cli.Handshake()
	if cerr != nil {
		_ = b.Close()
	}
	serr := <-errc
	return cli.ConnectionState().CurveID, serr, cerr
}

func transportTLS(t *testing.T, rt http.RoundTripper) *tls.Config {
	t.Helper()
	tr, ok := rt.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatalf("transport %T has no TLS config", rt)
	}
	return tr.TLSClientConfig
}

func classicalClient(pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	}
}

// TestHR395_AClassicalOnlyPeerCannotJoinAComponentLink: a component link
// end refuses a peer that offers or accepts only classical key exchanges,
// whichever end the classical peer is.
func TestHR395_AClassicalOnlyPeerCannotJoinAComponentLink(t *testing.T) {
	cert, pool := pqPair(t)
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))

	// A classical client against a component listener.
	server := ComponentLinkTLS(ServerTLSConfig(cert), "test-listener", log)
	if _, serr, cerr := handshake(t, server, classicalClient(pool)); serr == nil || cerr == nil {
		t.Fatalf("a classical-only client joined a component listener: server %v, client %v", serr, cerr)
	}

	// A component client against a classical-only server.
	classicalServer := &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	}
	client := ComponentLinkTLS(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}, "test-client", log)
	if _, serr, cerr := handshake(t, classicalServer, client); serr == nil || cerr == nil {
		t.Fatalf("a component client accepted a classical-only server: server %v, client %v", serr, cerr)
	}

	// The refusal is ErrClassicalKeyExchange even when the group list
	// itself would let a classical group through (defence in depth).
	loose := ComponentLinkTLS(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}, "test-loose", log)
	loose.CurvePreferences = []tls.CurveID{tls.CurveP256} // P-256: allowed in FIPS mode too
	if _, _, cerr := handshake(t, classicalServer, loose); !errors.Is(cerr, ErrClassicalKeyExchange) {
		t.Fatalf("a classical group on a component link: %v, want ErrClassicalKeyExchange", cerr)
	}
	if !strings.Contains(logs.String(), `"msg":"tls.link_refused"`) {
		t.Errorf("the refused link is not logged: %s", logs.String())
	}
}

// TestHR395_ComponentLinksNegotiateAHybridGroupAndLogIt: both ends of a
// component link agree on a hybrid post-quantum group, whichever of the
// three the client offers, and log the negotiated group.
func TestHR395_ComponentLinksNegotiateAHybridGroupAndLogIt(t *testing.T) {
	cert, pool := pqPair(t)
	if g := ComponentLinkGroups(); !slices.Equal(g, []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}) {
		t.Fatalf("component link groups = %v", g)
	}
	for _, group := range ComponentLinkGroups() {
		t.Run(group.String(), func(t *testing.T) {
			logs := &syncBuffer{}
			log := slog.New(slog.NewJSONHandler(logs, nil))
			server := ComponentLinkTLS(ServerTLSConfig(cert), "test-listener", log)
			client := ComponentLinkTLS(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}, "test-client", log)
			client.CurvePreferences = []tls.CurveID{group}
			got, serr, cerr := handshake(t, server, client)
			if serr != nil || cerr != nil {
				t.Fatalf("handshake: server %v, client %v", serr, cerr)
			}
			if got != group {
				t.Fatalf("negotiated %v, want %v", got, group)
			}
			out := logs.String()
			for _, link := range []string{"test-listener", "test-client"} {
				if !strings.Contains(out, `"msg":"tls.link","link":"`+link+`","group":"`+group.String()+`"`) {
					t.Errorf("%s did not log the negotiated group %s: %s", link, group, out)
				}
			}
		})
	}
	// Defaults: the client offers every hybrid group and the first wins.
	server := ComponentLinkTLS(ServerTLSConfig(cert), "l", nil)
	client := ComponentLinkTLS(&tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}, "c", nil)
	if got, serr, cerr := handshake(t, server, client); serr != nil || cerr != nil || !slices.Contains(ComponentLinkGroups(), got) {
		t.Fatalf("default component link: %v, %v, %v", got, serr, cerr)
	}
}

// TestHR395_ServerListenersNegotiateHybridWithDefaultClients: listeners
// third parties reach keep Go's defaults: a default client gets a hybrid
// group, and a classical-only client is still served (D35).
func TestHR395_ServerListenersNegotiateHybridWithDefaultClients(t *testing.T) {
	cert, pool := pqPair(t)
	got, serr, cerr := handshake(t, ServerTLSConfig(cert), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if serr != nil || cerr != nil || !slices.Contains(ComponentLinkGroups(), got) {
		t.Fatalf("default client: %v, %v, %v", got, serr, cerr)
	}
	got, serr, cerr = handshake(t, ServerTLSConfig(cert), classicalClient(pool))
	if serr != nil || cerr != nil || slices.Contains(ComponentLinkGroups(), got) {
		t.Fatalf("classical client at a public listener: %v, %v, %v", got, serr, cerr)
	}
}

// TestHR395_OnlyTheMTLSControlClientIsAComponentLink: the control client
// with the gateway's certificate is restricted to hybrid groups and TLS
// 1.3; without one (OpenID providers, JWKS) and the egress client keep TLS
// 1.2 minimum and Go's default groups.
func TestHR395_OnlyTheMTLSControlClientIsAComponentLink(t *testing.T) {
	mtls := NewControlClient(ControlConfig{ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &tls.Certificate{}, nil
	}})
	c := transportTLS(t, mtls.Transport)
	if c.MinVersion != tls.VersionTLS13 || !slices.Equal(c.CurvePreferences, ComponentLinkGroups()) || c.VerifyConnection == nil {
		t.Fatalf("mTLS control client TLS = min %x curves %v", c.MinVersion, c.CurvePreferences)
	}
	plain := transportTLS(t, NewControlClient(ControlConfig{}).Transport)
	if plain.MinVersion != tls.VersionTLS12 || plain.CurvePreferences != nil {
		t.Fatalf("third-party control client TLS = min %x curves %v", plain.MinVersion, plain.CurvePreferences)
	}
	egress := transportTLS(t, NewEgressClient(EgressConfig{}).Transport)
	if egress.MinVersion != tls.VersionTLS12 || egress.CurvePreferences != nil {
		t.Fatalf("egress TLS = min %x curves %v", egress.MinVersion, egress.CurvePreferences)
	}
}
