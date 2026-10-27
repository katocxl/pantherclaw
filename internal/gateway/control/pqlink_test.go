// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// serveMTLS serves f's handler over mutual TLS with the server certificate
// from f's CA and the key exchanges conf allows.
func serveMTLS(t *testing.T, f *fakeServer, handler http.Handler, conf *tls.Config) string {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srvCert, err := f.ca.IssueServer(pub, []string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	conf.Certificates = []tls.Certificate{{Certificate: [][]byte{srvCert.DER}, PrivateKey: priv}}
	conf.ClientAuth = tls.RequireAndVerifyClientCert
	conf.ClientCAs = f.ca.Pool()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, TLSConfig: conf}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

// TestT178_GatewayLinksCannotBeHarvestedForLaterDecryption (T-178,
// HR-395): an adversary who records the gateway's control traffic to
// decrypt it once a quantum computer exists gets nothing, because the link
// never falls back to a classical key exchange. A server (or a
// man-in-the-middle with a certificate from the internal CA) that offers
// only classical groups gets no request from the gateway; the server's
// own gateway listener profile negotiates a hybrid group, and both ends
// log which.
func TestT178_GatewayLinksCannotBeHarvestedForLaterDecryption(t *testing.T) {
	f, apiURL, _ := start(t)
	id, err := enroll(t, apiURL, ca.Fingerprint(f.ca.Certificate()))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	reached := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached++
		mu.Unlock()
		http.NotFound(w, r)
	})

	classical := serveMTLS(t, f, handler, &tls.Config{
		MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
	})
	c := NewClient(id, "", classical, 2*time.Second, pclog.Discard())
	if _, err := c.Gateway.RenewCertificate(context.Background(), &pb.RenewCertificateRequest{Csr: []byte("x")}); err == nil {
		t.Fatal("the gateway's control client completed a call over a classical key exchange")
	}
	mu.Lock()
	n := reached
	mu.Unlock()
	if n != 0 {
		t.Fatalf("%d requests reached a classical-only server", n)
	}

	serverLogs, clientLogs := &lockedBuffer{}, &lockedBuffer{}
	listener := httpx.ComponentLinkTLS(httpx.ServerTLSConfig(tls.Certificate{}), "gateway-api",
		slog.New(slog.NewJSONHandler(serverLogs, nil)))
	hybrid := serveMTLS(t, f, handler, listener)
	c = NewClient(id, "", hybrid, 2*time.Second, slog.New(slog.NewJSONHandler(clientLogs, nil)))
	// The handler answers 404: the call fails at the RPC layer, after a
	// completed handshake.
	_, _ = c.Gateway.RenewCertificate(context.Background(), &pb.RenewCertificateRequest{Csr: []byte("x")})
	mu.Lock()
	n = reached
	mu.Unlock()
	if n == 0 {
		t.Fatal("the gateway did not reach the server over a hybrid key exchange")
	}
	for name, out := range map[string]string{"server": serverLogs.String(), "client": clientLogs.String()} {
		if !strings.Contains(out, `"msg":"tls.link"`) || !strings.Contains(out, "MLKEM") {
			t.Errorf("the %s end did not log a hybrid group: %s", name, out)
		}
	}
}
