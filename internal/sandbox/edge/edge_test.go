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
	"encoding/hex"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

var hosts = map[string]string{"api.github.com": "github", "payments.example": "payments"}

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
		Session: "0f3c", GatewayURL: gw.URL + "/", Hosts: hosts, Run: r.run, Key: key, Token: func() string { return token },
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
	agentAction := ids.NewV7().String()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPut, "https://api.github.com/repos/acme/app/pulls/7/merge?x=1", strings.NewReader(`{"sha":"abc"}`))
	req.Header.Set("Authorization", "token ghp_planted0123456789")
	req.Header.Set("Cookie", "session=1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set(headerAction, agentAction)
	res, err := r.agent().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusCreated || string(b) != `{"ok":true}` || res.Header.Get("PC-Decision") != "ALLOW" ||
		res.Header.Get("X-Gateway-Internal") != "" || res.Header.Get(HeaderRefusedBy) != "" {
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
	if g.header.Get("Authorization") != "PAP workload-token" || g.header.Get(headerRunID) != r.run || g.header.Get(headerSession) != "0f3c" ||
		g.header.Get("Cookie") != "" || g.header.Get("X-Forwarded-For") != "" ||
		g.header.Get("Content-Type") != "application/json" || g.header.Get("Accept") != "application/vnd.github+json" {
		t.Fatalf("gateway headers %v", g.header)
	}
	// A fresh action id per request, whatever the agent sent.
	if a := g.header.Get(headerAction); a == agentAction || a == "" {
		t.Fatalf("action id %q (the agent sent %q)", a, agentAction)
	}
	c := claims(t, g.header.Get("PAP-Proof"))
	bh := sha256.Sum256(g.body)
	if c["htm"] != http.MethodPut || c["htu"] != r.gateway+"/github/repos/acme/app/pulls/7/merge" || c["bh"] != base64.RawURLEncoding.EncodeToString(bh[:]) {
		t.Fatalf("proof claims %v", c)
	}
	// The found token and the cookie are reported, never logged, with the
	// client's address.
	logged := r.log.String()
	if r.edge.Stripped() != 2 || strings.Count(logged, `"event":"edge.credential_stripped"`) != 2 ||
		!strings.Contains(logged, `"kind":"github_pat"`) || strings.Count(logged, `"client":"127.0.0.1"`) != 2 ||
		strings.Contains(logged, "ghp_planted") || strings.Contains(logged, "session=1") {
		t.Fatalf("stripped %d:\n%s", r.edge.Stripped(), logged)
	}
}

func TestHR214_UnmappedDestinationsAndPlainHTTPAreRefusedAndRecorded(t *testing.T) {
	r := newRig(t, "workload-token")
	for _, dest := range []string{
		"https://github.com/acme/app.git/info/refs", "https://api.github.com:8443/x", "https://140.82.112.6/x",
		"https://api.github.com.evil.example/x",
	} {
		res, err := r.agent().Get(dest)
		if err == nil {
			_ = res.Body.Close()
			t.Errorf("%s: the tunnel opened (%d)", dest, res.StatusCode)
		}
	}
	// Plain HTTP is refused, a mapped host included.
	for _, dest := range []string{"http://api.github.com/repos/acme/app", "http://evil.example/exfil", "http://169.254.169.254/latest/meta-data"} {
		res, err := r.agent().Get(dest)
		if err != nil {
			t.Fatal(err)
		}
		var ref Refusal
		_ = json.UnmarshalRead(res.Body, &ref)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusForbidden || ref.Error != "plain_http_refused" || res.Header.Get(HeaderRefusedBy) != "edge" {
			t.Errorf("%s: %d %+v", dest, res.StatusCode, ref)
		}
	}
	if n := len(r.requests()); n != 0 {
		t.Fatalf("the gateway got %d requests", n)
	}
	if got := r.edge.Refused(); got != 7 {
		t.Errorf("refused %d, want 7", got)
	}
	if n := strings.Count(r.log.String(), `"event":"edge.refused"`); n != 7 || !strings.Contains(r.log.String(), `"destination":"github.com:443"`) ||
		strings.Count(r.log.String(), `"client":"127.0.0.1"`) < 7 {
		t.Errorf("recorded %d refusals:\n%s", n, r.log)
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

// inTunnel sends one raw request through a tunnel to api.github.com and
// returns the status of the answer.
func inTunnel(t *testing.T, r *rig, request string) int {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(r.edge.CACertificate())
	tc := tls.Client(tunnel(t, r, "api.github.com:443"), &tls.Config{ServerName: "api.github.com", RootCAs: roots, MinVersion: tls.VersionTLS12})
	_, _ = io.WriteString(tc, request)
	res, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode
}

func TestHR214_ATunnelServesOnlyItsOwnHostAndNoUpgrade(t *testing.T) {
	r := newRig(t, "workload-token")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(r.edge.CACertificate())
	tc := tls.Client(tunnel(t, r, "api.github.com:443"), &tls.Config{ServerName: "payments.example", RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(t.Context()); err == nil {
		t.Fatal("the edge served payments.example inside a tunnel to api.github.com")
	}
	if code := inTunnel(t, r, "GET /v1/refunds HTTP/1.1\r\nHost: payments.example\r\n\r\n"); code != http.StatusMisdirectedRequest {
		t.Fatalf("Host differing from the CONNECT: %d", code)
	}
	if code := inTunnel(t, r, "GET /x HTTP/1.1\r\nHost: api.github.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); code != http.StatusForbidden {
		t.Fatalf("WebSocket upgrade: %d", code)
	}
	if code := inTunnel(t, r, "GET /x HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n"); code != http.StatusCreated {
		t.Fatalf("Host with its port: %d", code)
	}
	if n := len(r.requests()); n != 1 {
		t.Fatalf("the gateway got %d requests", n)
	}
}

// TestHR213_WithTheGatewayDownNothingLeaves: the edge dials only the
// gateway; a mapped request then fails and reaches no target.
func TestHR213_WithTheGatewayDownNothingLeaves(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the target was reached")
	}))
	defer target.Close()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{
		GatewayURL: "http://127.0.0.1:1", GatewayAddr: "127.0.0.1:1", Hosts: map[string]string{"payments.example": "payments"},
		Run: ids.NewV7().String(), Key: key, Token: func() string { return "t" },
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	e.forward(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/refunds/re_1", nil), "payments.example", "payments")
	if w.Code != http.StatusBadGateway || w.Header().Get(HeaderRefusedBy) != "edge" {
		t.Fatalf("gateway down: %d", w.Code)
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
		t.Fatalf("CA blocks %v", blocks)
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

// TestTheGatewayCAPinIsEnforced: an HTTPS gateway is trusted through its
// pinned CA only.
func TestTheGatewayCAPinIsEnforced(t *testing.T) {
	gw := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }))
	defer gw.Close()
	// httptest's certificate is self-signed: the pin names the only
	// certificate in the chain.
	ca := gw.TLS.Certificates[0]
	issuer, err := x509.ParseCertificate(ca.Certificate[len(ca.Certificate)-1])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(issuer.Raw)
	good := "sha256:" + hex.EncodeToString(sum[:])
	for pin, want := range map[string]int{good: http.StatusTeapot, "sha256:" + strings.Repeat("0", 64): http.StatusBadGateway} {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		e, err := New(Options{
			GatewayURL: gw.URL, GatewayCAPin: pin, Hosts: map[string]string{"payments.example": "payments"},
			Run: ids.NewV7().String(), Key: key, Token: func() string { return "t" },
		})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		e.forward(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/x", nil), "payments.example", "payments")
		if w.Code != want {
			t.Errorf("pin %s…: %d, want %d", pin[:12], w.Code, want)
		}
	}
	if _, err := gatewayTLS("md5:abc"); err == nil {
		t.Fatal("a malformed pin was accepted")
	}
}

// TestHR395_TheEdgeReachesTheGatewayOnlyOverAHybridKeyExchange: a gateway
// that offers only classical key exchanges gets no request from the edge;
// one with Go's defaults (the gateway's listener profile) is reached over a
// hybrid post-quantum group, and the edge logs which (G0 M13 D35, T-178).
func TestHR395_TheEdgeReachesTheGatewayOnlyOverAHybridKeyExchange(t *testing.T) {
	var reached atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusTeapot)
	})
	for name, classical := range map[string]bool{"classical": true, "default": false} {
		reached.Store(0)
		gw := httptest.NewUnstartedServer(handler)
		gw.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
		if classical {
			gw.TLS.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
		}
		gw.StartTLS()
		ca := gw.TLS.Certificates[0]
		issuer, err := x509.ParseCertificate(ca.Certificate[len(ca.Certificate)-1])
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(issuer.Raw)
		var logs bytes.Buffer
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		e, err := New(Options{
			GatewayURL: gw.URL, GatewayCAPin: "sha256:" + hex.EncodeToString(sum[:]), Hosts: map[string]string{"payments.example": "payments"},
			Run: ids.NewV7().String(), Key: key, Token: func() string { return "t" },
			Log: slog.New(slog.NewJSONHandler(&logs, nil)),
		})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		e.forward(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/x", nil), "payments.example", "payments")
		gw.Close()
		switch {
		case classical && (w.Code != http.StatusBadGateway || reached.Load() != 0):
			t.Errorf("%s gateway: %d, %d requests reached it", name, w.Code, reached.Load())
		case !classical && (w.Code != http.StatusTeapot || !strings.Contains(logs.String(), `"link":"edge-gateway","group":"X25519MLKEM768"`) &&
			!strings.Contains(logs.String(), `"link":"edge-gateway","group":"SecP256r1MLKEM768"`)):
			t.Errorf("%s gateway: %d, logs %s", name, w.Code, logs.String())
		}
	}
}

func TestTheEdgeRefusesWhatItCannotSend(t *testing.T) {
	r := newRig(t, "")
	if code := inTunnel(t, r, "POST /x HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 2\r\n\r\n{}"); code != http.StatusServiceUnavailable {
		t.Errorf("no workload token: %d", code)
	}
	r = newRig(t, "workload-token")
	big := strings.Repeat("a", MaxBody+1)
	code := inTunnel(t, r, "POST /x HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: "+strconv.Itoa(len(big))+"\r\n\r\n"+big)
	if code != http.StatusRequestEntityTooLarge || len(r.requests()) != 0 {
		t.Errorf("large body: %d", code)
	}
}

func TestNewRefusesBadHosts(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for name, h := range map[string]map[string]string{
		"none":       nil,
		"ip":         {"140.82.112.6": "github"},
		"uppercase":  {"API.github.com": "github"},
		"port":       {"api.github.com:443": "github"},
		"wildcard":   {"*.github.com": "github"},
		"connection": {"api.github.com": ""},
		"path":       {"api.github.com": "github/../x"},
	} {
		if _, err := New(Options{GatewayURL: "http://127.0.0.1:8090", Hosts: h, Run: ids.NewV7().String(), Key: key, Token: func() string { return "t" }}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCredentialKinds(t *testing.T) {
	for v, want := range map[[2]string]string{
		{"Authorization", "token ghp_x"}:          "github_pat",
		{"Authorization", "Bearer github_pat_11"}: "github_pat",
		{"Authorization", "Basic eDp5"}:           "authorization:basic",
		{"X-Api-Key", "sk_live_1"}:                "stripe_live",
		{"Cookie", "a=b"}:                         "cookie",
	} {
		if got := credentialKind(v[0], v[1]); got != want {
			t.Errorf("%v: %q, want %q", v, got, want)
		}
	}
}

// FuzzEdgeConnect: whatever authority a CONNECT names, the edge routes only
// an agent host on port 443, to that host's connection.
func FuzzEdgeConnect(f *testing.F) {
	for _, s := range []string{
		"api.github.com:443", "API.GITHUB.COM:443", "api.github.com:8443", "api.github.com", "[::1]:443",
		"140.82.112.6:443", "api.github.com.:443", "payments.example:0443", "api.github.com:443:443", "%61pi.github.com:443", "",
	} {
		f.Add(s)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	e, err := New(Options{GatewayURL: "http://127.0.0.1:1", Hosts: hosts, Run: ids.NewV7().String(), Key: key, Token: func() string { return "t" }})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, authority string) {
		host, conn, ok := e.route(authority)
		if !ok {
			return
		}
		h, p, err := net.SplitHostPort(authority)
		if err != nil || p != "443" || !strings.EqualFold(h, host) || hosts[host] != conn || conn == "" {
			t.Fatalf("%q routed to %q → %q", authority, host, conn)
		}
	})
}

// TestHR213_CredentialsInTheQueryAreStrippedAndReported: a token-shaped
// query parameter, by name or by prefix, never reaches the gateway, and is
// reported like a header; the other parameters keep their order.
func TestHR213_CredentialsInTheQueryAreStrippedAndReported(t *testing.T) {
	r := newRig(t, "workload-token")
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
		"https://api.github.com/repos/acme/app?per_page=5&access_token=s3cret&q=a+b&sig=ghp_planted0123456789&page=2", nil)
	res, err := r.agent().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	got := r.requests()
	if len(got) != 1 || got[0].query != "per_page=5&q=a+b&page=2" {
		t.Fatalf("gateway got %+v", got)
	}
	logged := r.log.String()
	if r.edge.Stripped() != 2 || !strings.Contains(logged, `"kind":"query:access_token"`) || !strings.Contains(logged, `"kind":"github_pat"`) ||
		strings.Contains(logged, "s3cret") || strings.Contains(logged, "ghp_planted") {
		t.Fatalf("stripped %d:\n%s", r.edge.Stripped(), logged)
	}
}

// TestTheSessionCAsCertificatesLiveAnHour: a host certificate lives at most
// an hour and is issued again before it expires; the CA serves only
// server authentication.
func TestTheSessionCAsCertificatesLiveAnHour(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	a, err := newAuthority([]string{"api.github.com"}, 24*time.Hour, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(a.cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatalf("CA key usage %v", a.cert.ExtKeyUsage)
	}
	first, err := a.leaf("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	if life := first.Leaf.NotAfter.Sub(now); life > time.Hour {
		t.Fatalf("a leaf lives %s", life)
	}
	now = now.Add(30 * time.Minute)
	if again, _ := a.leaf("api.github.com"); again != first {
		t.Fatal("a fresh leaf was issued again")
	}
	now = now.Add(26 * time.Minute)
	renewed, _ := a.leaf("api.github.com")
	if renewed == first || !renewed.Leaf.NotAfter.After(first.Leaf.NotAfter) {
		t.Fatal("a leaf about to expire was not issued again")
	}
	if _, err := renewed.Leaf.Verify(x509.VerifyOptions{
		DNSName: "api.github.com", Roots: certPool(a.cert), CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatal(err)
	}
}

func certPool(c *x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c)
	return p
}

// TestHR213_TheEdgeListensOnlyOnTheSandboxNetwork: the edge listens on its
// address in the sandbox network, and a connection that arrives on another
// local address (its uplink's) is dropped unanswered.
func TestHR213_TheEdgeListensOnlyOnTheSandboxNetwork(t *testing.T) {
	ln, err := listen(t.Context(), ":0", "127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if a := ln.Addr().(*net.TCPAddr); !a.IP.IsLoopback() {
		t.Fatalf("listening on %s", a)
	}
	_ = ln.Close()
	if _, err := listen(t.Context(), ":0", "192.0.2.0/24"); err == nil {
		t.Fatal("listened with no address in the sandbox network")
	}
	raw, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	other := &subnetListener{Listener: raw, prefix: netip.MustParsePrefix("10.0.0.0/8")}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := other.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()
	c, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("the edge answered on another address: %d, %v", n, err)
	}
	_ = c.Close()
	_ = other.Close()
	if c, ok := <-accepted; ok {
		_ = c.Close()
		t.Fatal("a connection to another address was accepted")
	}
}
