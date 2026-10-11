// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// seen is a request as the fake gateway received it.
type seen struct {
	method, path, query string
	header              http.Header
	body                []byte
}

type rig struct {
	edge    *Edge
	proxy   *url.URL
	gateway string
	run     string
	mu      sync.Mutex
	got     []seen
	log     *bytes.Buffer
}

func (r *rig) requests() []seen {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.got)
}

// newRig starts a fake gateway, which answers every request with a PC-*
// header and an internal one, and an edge in front of it.
func newRig(t *testing.T, token string) *rig {
	t.Helper()
	r := &rig{run: ids.NewV7().String(), log: &bytes.Buffer{}}
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, seen{req.Method, req.URL.EscapedPath(), req.URL.RawQuery, req.Header.Clone(), b})
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("PC-Decision", "ALLOW")
		w.Header().Set("X-Gateway-Internal", "1")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(gw.Close)
	r.gateway = gw.URL
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{
		GatewayURL: gw.URL + "/", Routes: []Route{{Host: "api.github.com", Connection: "github"}, {Host: "payments.example", Connection: "payments"}},
		Run: r.run, Key: key, Token: func() string { return token },
		Log: pclog.New(r.log, pclog.Options{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.edge = e
	ps := httptest.NewServer(e)
	t.Cleanup(ps.Close)
	r.proxy, _ = url.Parse(ps.URL)
	return r
}

// agent is the agent's HTTP client: the edge as its proxy, the session CA
// as its only root.
func (r *rig) agent() *http.Client {
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(r.edge.CACertificate())
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(r.proxy), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
}

func claims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof %q", proof)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestHR213_TheEdgeSignsMappedRequestsForTheGateway(t *testing.T) {
	r := newRig(t, "workload-token")
	action := ids.NewV7().String()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPut, "https://api.github.com/repos/acme/app/pulls/7/merge?x=1", strings.NewReader(`{"sha":"abc"}`))
	req.Header.Set("Authorization", "token ghp_planted")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Header", "1")
	req.Header.Set(headerActionID, action)
	res, err := r.agent().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusCreated || string(b) != `{"ok":true}` || res.Header.Get("PC-Decision") != "ALLOW" || res.Header.Get("X-Gateway-Internal") != "" ||
		res.Header.Get(HeaderRefusedBy) != "" {
		t.Fatalf("agent got %d %s %v", res.StatusCode, b, res.Header)
	}
	got := r.requests()
	if len(got) != 1 {
		t.Fatalf("gateway got %d requests", len(got))
	}
	g := got[0]
	if g.method != http.MethodPut || g.path != "/github/repos/acme/app/pulls/7/merge" || g.query != "x=1" || string(g.body) != `{"sha":"abc"}` {
		t.Fatalf("gateway got %s %s?%s %s", g.method, g.path, g.query, g.body)
	}
	if g.header.Get("Authorization") != "PAP workload-token" || g.header.Get(headerRunID) != r.run || g.header.Get(headerActionID) != action ||
		g.header.Get("X-Agent-Header") != "" || g.header.Get("Content-Type") != "application/json" {
		t.Fatalf("gateway headers %v", g.header)
	}
	c := claims(t, g.header.Get("PAP-Proof"))
	bh := sha256.Sum256(g.body)
	if c["htm"] != http.MethodPut || c["htu"] != r.gateway+"/github/repos/acme/app/pulls/7/merge" || c["bh"] != base64.RawURLEncoding.EncodeToString(bh[:]) {
		t.Fatalf("proof claims %v", c)
	}

	// Plain HTTP to a mapped host takes the same path; the edge mints the
	// action id when the agent sends none.
	res, err = r.agent().Post("http://payments.example/v1/refunds", "application/json", strings.NewReader(`{"amount":"30.00"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	got = r.requests()
	if len(got) != 2 || got[1].path != "/payments/v1/refunds" || string(got[1].body) != `{"amount":"30.00"}` {
		t.Fatalf("gateway got %+v", got)
	}
	if _, err := ids.ParseUUID(got[1].header.Get(headerActionID)); err != nil {
		t.Fatalf("minted action id %q", got[1].header.Get(headerActionID))
	}
}

func TestHR214_UnmappedDestinationsAreRefusedAndRecorded(t *testing.T) {
	r := newRig(t, "workload-token")
	for _, dest := range []string{"https://github.com/acme/app.git/info/refs", "https://api.github.com:8443/x", "https://140.82.112.6/x", "https://API.GITHUB.COM.evil.example/x"} {
		res, err := r.agent().Get(dest)
		if err == nil {
			_ = res.Body.Close()
			t.Errorf("%s: the tunnel opened (%d)", dest, res.StatusCode)
		}
	}
	for _, dest := range []string{"http://evil.example/exfil", "http://api.github.com:8080/x", "http://169.254.169.254/latest/meta-data"} {
		res, err := r.agent().Get(dest)
		if err != nil {
			t.Fatal(err)
		}
		var ref Refusal
		_ = json.UnmarshalRead(res.Body, &ref)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusForbidden || ref.Error != "unmapped_destination" || res.Header.Get(HeaderRefusedBy) != "edge" {
			t.Errorf("%s: %d %+v", dest, res.StatusCode, ref)
		}
	}
	// A request to the edge itself is not a proxy request.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, r.proxy.String()+"/", nil)
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("origin-form request: %d", res.StatusCode)
	}
	if n := len(r.requests()); n != 0 {
		t.Fatalf("the gateway got %d requests", n)
	}
	if got := r.edge.Refused(); got != 8 {
		t.Errorf("refused %d, want 8", got)
	}
	if n := strings.Count(r.log.String(), `"event":"edge.refused"`); n != 8 {
		t.Errorf("recorded %d refusals:\n%s", n, r.log)
	}
	if !strings.Contains(r.log.String(), `"destination":"github.com:443"`) {
		t.Errorf("the record lacks the destination:\n%s", r.log)
	}
}

// tunnel opens a CONNECT to authority through the edge and returns the raw
// connection after the edge's 200.
func tunnel(t *testing.T, r *rig, authority string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", r.proxy.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_, _ = io.WriteString(c, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect}) // a 2xx answer to CONNECT has no body
	if err != nil {
		t.Fatalf("CONNECT %s: %v", authority, err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s: %d", authority, res.StatusCode)
	}
	return c
}

func TestHR214_ATunnelServesOnlyItsOwnHost(t *testing.T) {
	r := newRig(t, "workload-token")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(r.edge.CACertificate())

	// Another server name in the handshake: no certificate.
	tc := tls.Client(tunnel(t, r, "api.github.com:443"), &tls.Config{ServerName: "payments.example", RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(t.Context()); err == nil {
		t.Fatal("the edge served payments.example inside a tunnel to api.github.com")
	}

	// Another Host inside the tunnel: refused before the gateway.
	tc = tls.Client(tunnel(t, r, "api.github.com:443"), &tls.Config{ServerName: "api.github.com", RootCAs: roots, MinVersion: tls.VersionTLS12})
	_, _ = io.WriteString(tc, "GET /v1/refunds HTTP/1.1\r\nHost: payments.example\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusMisdirectedRequest || len(r.requests()) != 0 {
		t.Fatalf("Host differing from the CONNECT: %d, gateway got %d", res.StatusCode, len(r.requests()))
	}
}

func TestHR213_TheSessionCAIsKeylessOnDiskAndNameConstrained(t *testing.T) {
	r := newRig(t, "workload-token")
	var blocks []string
	rest := r.edge.CACertificate()
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		blocks = append(blocks, b.Type)
	}
	if !slices.Equal(blocks, []string{"CERTIFICATE"}) {
		t.Fatalf("CA file blocks %v", blocks)
	}
	ca := r.edge.ca.cert
	if !ca.IsCA || !ca.MaxPathLenZero || !ca.PermittedDNSDomainsCritical || len(ca.ExcludedIPRanges) != 2 ||
		!slices.Equal(ca.PermittedDNSDomains, []string{"api.github.com", "payments.example"}) {
		t.Fatalf("CA constraints %+v", ca)
	}
	if ca.NotAfter.Sub(ca.NotBefore) > 24*time.Hour+time.Minute {
		t.Fatalf("CA valid %s", ca.NotAfter.Sub(ca.NotBefore))
	}
	if _, err := r.edge.ca.leaf("github.com"); err == nil {
		t.Fatal("a certificate for an unmapped host was issued")
	}
	// Even a certificate the CA key signed for another name does not verify.
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: "github.com"}, DNSNames: []string{"github.com"},
		NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &r.edge.ca.leafKey.PublicKey, r.edge.ca.key)
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := forged.Verify(x509.VerifyOptions{Roots: roots, DNSName: "github.com"}); err == nil {
		t.Fatal("a certificate outside the name constraints verified")
	}
	leaf, err := r.edge.ca.leaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(leaf.Certificate[0])
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "api.github.com"}); err != nil {
		t.Fatalf("the mapped host's certificate: %v", err)
	}
}

func TestTheEdgeRefusesWhatItCannotSend(t *testing.T) {
	r := newRig(t, "")
	res, err := r.agent().Post("http://payments.example/v1/refunds", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("no workload token: %d", res.StatusCode)
	}

	r = newRig(t, "workload-token")
	res, err = r.agent().Post("http://payments.example/v1/refunds", "application/json", bytes.NewReader(make([]byte, MaxBody+1)))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge || len(r.requests()) != 0 {
		t.Errorf("large body: %d", res.StatusCode)
	}

	_, key, _ := ed25519.GenerateKey(rand.Reader)
	down, err := New(Options{
		GatewayURL: "http://127.0.0.1:1", Routes: []Route{{Host: "payments.example", Connection: "payments"}},
		Run: ids.NewV7().String(), Key: key, Token: func() string { return "t" },
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	down.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://payments.example/v1/refunds/re_1", nil))
	if w.Code != http.StatusBadGateway {
		t.Errorf("gateway down: %d", w.Code)
	}
}

func TestNewRefusesBadRoutes(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for name, routes := range map[string][]Route{
		"none":       nil,
		"ip":         {{Host: "140.82.112.6", Connection: "github"}},
		"uppercase":  {{Host: "API.github.com", Connection: "github"}},
		"port":       {{Host: "api.github.com:443", Connection: "github"}},
		"wildcard":   {{Host: "*.github.com", Connection: "github"}},
		"twice":      {{Host: "api.github.com", Connection: "a"}, {Host: "api.github.com", Connection: "b"}},
		"connection": {{Host: "api.github.com"}},
	} {
		if _, err := New(Options{GatewayURL: "http://127.0.0.1:8090", Routes: routes, Run: ids.NewV7().String(), Key: key, Token: func() string { return "t" }}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
