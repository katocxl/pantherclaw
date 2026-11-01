// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package relay_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/katocxl/pantherclaw/internal/redteam/relay"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

const (
	testKey   = "sk-test-KEEP-THIS-OUT-0123456789"
	modelHost = "model.provider.test"
)

// provider is a local TLS fake provider. handler sees each request.
func provider(t *testing.T, h http.HandlerFunc) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv, roots
}

type rig struct {
	r   *relay.Relay
	log *bytes.Buffer
}

func start(t *testing.T, srv *httptest.Server, roots *x509.CertPool, edit func(*relay.Options)) rig {
	t.Helper()
	log := &bytes.Buffer{}
	o := relay.Options{
		Listen: "127.0.0.1:0", ModelHost: "example.com", Key: []byte(testKey), KeyHeader: "x-api-key", Roots: roots,
		DialAddr: srv.Listener.Addr().String(), Log: slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if edit != nil {
		edit(&o)
	}
	r, err := relay.New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		_ = r.Close(ctx)
	})
	return rig{r: r, log: log}
}

func post(t *testing.T, r rig, path string, hdr map[string]string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, r.r.BaseURL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = res.Body.Close() })
	return res
}

// TestHR607_TheKeyGoesOnlyToTheModelHost: the upstream request carries the
// key and none of the credentials the request came with; the body reaches it
// unchanged; the log, the answer and the answer's headers hold no key.
// Covers: F905
func TestHR607_TheKeyGoesOnlyToTheModelHost(t *testing.T) {
	var got http.Header
	var body []byte
	var host string
	srv, roots := provider(t, func(w http.ResponseWriter, r *http.Request) {
		got, host = r.Header.Clone(), r.Host
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo", r.Header.Get("X-Api-Key"))
		w.Header().Set("Set-Cookie", "a=b")
		_, _ = io.WriteString(w, `{"ok":true}`)
	})
	// The certificate of httptest is for example.com.
	rg := start(t, srv, roots, nil)
	res := post(t, rg, "/v1/messages?x=1", map[string]string{
		"Authorization": "Bearer stolen", "X-Api-Key": "stolen", "Cookie": "s=1", "Api-Key": "stolen", "X-Forwarded-For": "1.2.3.4", "Anthropic-Version": "2023-06-01",
	}, `{"messages":[{"role":"user","content":"hi"}]}`)
	out, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(out) != `{"ok":true}` {
		t.Fatalf("%d %s", res.StatusCode, out)
	}
	if got.Get("X-Api-Key") != testKey || len(got.Values("X-Api-Key")) != 1 {
		t.Fatalf("key header %q", got.Values("X-Api-Key"))
	}
	for _, h := range []string{"Authorization", "Cookie", "Api-Key", "X-Forwarded-For"} {
		if got.Get(h) != "" {
			t.Errorf("%s reached the model host: %q", h, got.Get(h))
		}
	}
	if got.Get("Anthropic-Version") == "" || string(body) != `{"messages":[{"role":"user","content":"hi"}]}` {
		t.Errorf("the request changed: %v %s", got, body)
	}
	if host != "example.com" {
		t.Errorf("host %q", host)
	}
	if res.Header.Get("X-Echo") != "" || res.Header.Get("Set-Cookie") != "" {
		t.Errorf("answer headers leak: %v", res.Header)
	}
	if strings.Contains(rg.log.String(), testKey) {
		t.Errorf("the key is in the log: %s", rg.log)
	}
	if s := rg.r.Stats(); s.Requests != 1 || s.BytesToModel == 0 || s.BytesFromModel == 0 {
		t.Errorf("stats %+v", s)
	}
}

// TestHR607_AnEchoedKeyNeverComesBack: a host that echoes the key in its body
// or a header gets it removed, also across a chunk boundary.
// Covers: F905
func TestHR607_AnEchoedKeyNeverComesBack(t *testing.T) {
	srv, roots := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "before "+testKey[:9])
		f.Flush()
		_, _ = io.WriteString(w, testKey[9:]+" after")
	})
	res := post(t, start(t, srv, roots, nil), "/x", nil, "{}")
	out, _ := io.ReadAll(res.Body)
	if strings.Contains(string(out), testKey) || strings.Contains(string(out), testKey[9:]) {
		t.Fatalf("the key came back: %s", out)
	}
	if string(out) != "before [REDACTED] after" {
		t.Fatalf("%q", out)
	}
}

// TestHR607_ACloseStartOfTheKeyStillArrives: a tail that only looks like the
// key's start is held for the next chunk, never lost.
// Covers: F905
func TestHR607_ACloseStartOfTheKeyStillArrives(t *testing.T) {
	srv, roots := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tail sk-te")
	})
	res := post(t, start(t, srv, roots, nil), "/x", nil, "{}")
	if out, _ := io.ReadAll(iotest.OneByteReader(res.Body)); string(out) != "tail sk-te" {
		t.Fatalf("%q", out)
	}
}

// TestHR607_StreamsAsTheModelWrites: the first event arrives before the
// model has finished.
// Covers: F906
func TestHR607_StreamsAsTheModelWrites(t *testing.T) {
	release := make(chan struct{})
	srv, roots := provider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		f, _ := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: one\n\n")
		f.Flush()
		<-release
		_, _ = io.WriteString(w, "data: two\n\n")
	})
	res := post(t, start(t, srv, roots, nil), "/v1/messages", nil, "{}")
	if res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%v", res.Header)
	}
	br := bufio.NewReader(res.Body)
	line, err := br.ReadString('\n') // blocks forever if the relay buffers
	close(release)
	if err != nil || line != "data: one\n" {
		t.Fatalf("%q %v", line, err)
	}
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: two") {
		t.Fatalf("%q", rest)
	}
}

// TestHR607_AnyOtherHostIsRefused: a request for another host never leaves,
// and a redirect is refused rather than followed or handed back.
// Covers: F907
func TestHR607_AnyOtherHostIsRefused(t *testing.T) {
	hits := 0
	srv, roots := provider(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "https://evil.example/steal")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}
	})
	rg := start(t, srv, roots, nil)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, rg.r.BaseURL()+"/x", strings.NewReader("{}"))
	req.Host = "evil.example"
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusForbidden || res.Header.Get(relay.HeaderRefused) != "relay" || hits != 0 {
		t.Fatalf("another host: %d, %d hits", res.StatusCode, hits)
	}
	r2 := post(t, rg, "/redirect", nil, "{}")
	out, _ := io.ReadAll(r2.Body)
	if r2.StatusCode != http.StatusBadGateway || r2.Header.Get("Location") != "" || !strings.Contains(string(out), "redirect_refused") {
		t.Fatalf("redirect: %d %v %s", r2.StatusCode, r2.Header, out)
	}
}

// TestHR607_OnlyAVerifiedHost: a certificate the relay does not trust, or for
// another name, stops the request, so the key is never sent to it.
// Covers: F907
func TestHR607_OnlyAVerifiedHost(t *testing.T) {
	hits := 0
	srv, roots := provider(t, func(http.ResponseWriter, *http.Request) { hits++ })
	for name, edit := range map[string]func(*relay.Options){
		"untrusted": func(o *relay.Options) { o.Roots = x509.NewCertPool() },
		"other":     func(o *relay.Options) { o.ModelHost = modelHost },
	} {
		res := post(t, start(t, srv, roots, edit), "/x", nil, "{}")
		if res.StatusCode != http.StatusBadGateway || hits != 0 {
			t.Fatalf("%s: %d, %d hits", name, res.StatusCode, hits)
		}
	}
}

// TestHR607_ListensPrivatelyForTheLocalGateway: a public or unspecified
// listen address and a remote gateway are refused.
// Covers: F908
func TestHR607_ListensPrivatelyForTheLocalGateway(t *testing.T) {
	base := func() relay.Options {
		return relay.Options{Listen: "127.0.0.1:0", ModelHost: modelHost, Key: []byte(testKey), KeyHeader: "x-api-key"}
	}
	for name, edit := range map[string]func(*relay.Options){
		"unspecified":     func(o *relay.Options) { o.Listen = "0.0.0.0:0" },
		"unspecified6":    func(o *relay.Options) { o.Listen = "[::]:0" },
		"public":          func(o *relay.Options) { o.Listen = "8.8.8.8:0" },
		"a name":          func(o *relay.Options) { o.Listen = "localhost:0" },
		"remote gateway":  func(o *relay.Options) { o.Gateway = netip.MustParseAddr("8.8.8.8") },
		"private, no gw":  func(o *relay.Options) { o.Listen = "10.0.0.1:0" },
		"an IP host":      func(o *relay.Options) { o.ModelHost = "10.0.0.1" },
		"no key":          func(o *relay.Options) { o.Key = nil },
		"a header header": func(o *relay.Options) { o.KeyHeader = "x-api-key: y\r\nz" },
	} {
		o := base()
		edit(&o)
		if r, err := relay.New(o); err == nil {
			_ = r.Close(t.Context())
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestHR607_RefusesAnyOtherPeer: a relay for a gateway at another address
// refuses this peer before anything leaves.
// Covers: F908
func TestHR607_RefusesAnyOtherPeer(t *testing.T) {
	hits := 0
	srv, roots := provider(t, func(http.ResponseWriter, *http.Request) { hits++ })
	rg := start(t, srv, roots, func(o *relay.Options) { o.Gateway = netip.MustParseAddr("10.1.2.3") })
	res := post(t, rg, "/x", nil, "{}")
	if res.StatusCode != http.StatusForbidden || hits != 0 {
		t.Fatalf("%d, %d hits", res.StatusCode, hits)
	}
}

// TestHR607_AnswersTheSimulatorHandshake: the gateway verifies it like any
// simulator, without a credential, and the handshake never reaches the host.
// Covers: F905
func TestHR607_AnswersTheSimulatorHandshake(t *testing.T) {
	hits := 0
	srv, roots := provider(t, func(http.ResponseWriter, *http.Request) { hits++ })
	rg := start(t, srv, roots, nil)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, rg.r.BaseURL()+handshake.Path+"?nonce="+strings.Repeat("a", 32), http.NoBody)
	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || res.Header.Get("Simulated") != "true" || !strings.Contains(string(b), relay.Kind) || hits != 0 {
		t.Fatalf("%d %s %d", res.StatusCode, b, hits)
	}
}

// TestHR607_ABodyOverTheLimitIsRefused: 8 MiB each way (D313).
// Covers: F906
func TestHR607_ABodyOverTheLimitIsRefused(t *testing.T) {
	srv, roots := provider(t, func(_ http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) })
	res := post(t, start(t, srv, roots, nil), "/x", nil, strings.Repeat("a", relay.MaxBody+1))
	if res.StatusCode < 400 {
		t.Fatalf("%d", res.StatusCode)
	}
}
