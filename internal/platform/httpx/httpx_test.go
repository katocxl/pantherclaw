// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}

func TestHR071_DeniedAddresses(t *testing.T) {
	denied := []string{
		"127.0.0.1", "127.255.255.254", "0.0.0.0", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "100.100.100.200", "224.0.0.1", "255.255.255.255", "240.0.0.1",
		"192.0.2.1", "198.18.0.1",
		"::", "::1", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1", "2001:db8::1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", // IPv4-mapped
		"64:ff9b::a9fe:a9fe", // NAT64 of 169.254.169.254
		"2002:7f00:0001::1",  // 6to4 of 127.0.0.1
		"2002:a00:1::1",      // 6to4 of 10.0.0.1
	}
	for _, s := range denied {
		if !DeniedAddr(netip.MustParseAddr(s), nil) {
			t.Errorf("%s is allowed, want denied", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "93.184.216.34", "::ffff:8.8.8.8"} {
		if DeniedAddr(netip.MustParseAddr(s), nil) {
			t.Errorf("%s is denied, want allowed", s)
		}
	}
	if DeniedAddr(netip.MustParseAddr("127.0.0.1"), loopback) {
		t.Error("explicit allow prefix ignored")
	}
	if !DeniedAddr(netip.MustParseAddr("127.0.0.2"), loopback) {
		t.Error("allow prefix too broad")
	}
}

func TestHR071_EgressRefusesInternalTargetsAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "secret internal data") }))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":"):]
	c := NewEgressClient(EgressConfig{})
	// Decimal, hex, octal and short IPv4 encodings are not IP literals for
	// Go: they can only ever be resolved as hostnames, and whatever they
	// resolve to is checked at dial time like any other name. (They are not
	// dialed here because that would query external DNS.)
	for _, s := range []string{"2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1", "0x7f000001"} {
		if _, err := netip.ParseAddr(s); err == nil {
			t.Errorf("%q parses as an IP literal", s)
		}
	}
	// Local spellings of loopback resolve without the network and must all
	// be refused at dial time.
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]", "[::ffff:127.0.0.1]"} {
		resp, err := c.Get("http://" + host + port + "/")
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s reached the internal server", host)
		}
	}
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, ErrDestinationDenied) {
		t.Fatalf("loopback request err = %v, want ErrDestinationDenied", err)
	}
}

func TestHR070_RedirectsAreNotFollowed(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			hits++
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer srv.Close()
	c := NewEgressClient(EgressConfig{AllowedPrefixes: loopback})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/start", nil)
	req.Header.Set("Authorization", "Bearer credential-not-real")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || hits != 0 {
		t.Fatalf("status %d, target hits %d: redirect was followed", resp.StatusCode, hits)
	}
}

func TestHR072_ProxyEnvironmentIsIgnored(t *testing.T) {
	var direct bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { direct = true }))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "")
	c := NewEgressClient(EgressConfig{AllowedPrefixes: loopback})
	if tr := c.Transport.(*http.Transport); tr.Proxy != nil {
		t.Fatal("egress transport has a proxy function")
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("request went to the environment proxy: %v", err)
	}
	_ = resp.Body.Close()
	if !direct {
		t.Fatal("request did not reach the target directly")
	}
}

func TestHR074_NoClientCertificateOnEgress(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c := NewEgressClient(EgressConfig{AllowedPrefixes: loopback, RootCAs: pool})
	tr := c.Transport.(*http.Transport)
	if len(tr.TLSClientConfig.Certificates) != 0 {
		t.Fatal("egress TLS config carries certificates")
	}
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("server requiring a client certificate accepted the egress client")
	}
	// The same server without client auth works, proving TLS itself is fine.
	ok := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer ok.Close()
	pool.AddCert(ok.Certificate())
	resp, err = NewEgressClient(EgressConfig{AllowedPrefixes: loopback, RootCAs: pool}).Get(ok.URL)
	if err != nil {
		t.Fatalf("plain TLS request failed: %v", err)
	}
	_ = resp.Body.Close()
}

func TestServerRequiresTLSOffLoopback(t *testing.T) {
	h := http.NotFoundHandler()
	if _, err := NewServer(ServerConfig{Addr: "0.0.0.0:8080", Handler: h}); err == nil {
		t.Fatal("plaintext server on all interfaces accepted")
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		if _, err := NewServer(ServerConfig{Addr: addr, Handler: h}); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if _, err := NewServer(ServerConfig{Addr: "0.0.0.0:8080", Handler: h, PlaintextBehindProxy: true}); err != nil {
		t.Fatal(err)
	}
	s, _ := NewServer(ServerConfig{Addr: "127.0.0.1:0", Handler: h})
	if s.ReadHeaderTimeout != ReadHeaderTimeout || s.ReadTimeout != ReadTimeout || s.WriteTimeout != WriteTimeout ||
		s.IdleTimeout != IdleTimeout || s.MaxHeaderBytes != MaxHeaderBytes {
		t.Fatalf("server limits not applied: %+v", s)
	}
}

func TestServerHeadersBodyLimitAndRecovery(t *testing.T) {
	var logs bytes.Buffer
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
	})
	mux.HandleFunc("/panic", func(http.ResponseWriter, *http.Request) { panic("db password=hunter2 at handler.go:42") })
	s, err := NewServer(ServerConfig{Addr: "127.0.0.1:0", Handler: mux, BodyLimit: 16, Logger: pclog.New(&logs, pclog.Options{})})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler)
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/ok", "text/plain", strings.NewReader("small")) //nolint:forbidigo // test client for a local test server
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'", "Cache-Control": "no-store",
	} {
		if got := resp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent over plain loopback HTTP")
	}

	resp, err = http.Post(ts.URL+"/ok", "text/plain", strings.NewReader(strings.Repeat("x", 1000))) //nolint:forbidigo // test client for a local test server
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d", resp.StatusCode)
	}

	resp, err = http.Get(ts.URL + "/panic") //nolint:forbidigo // test client for a local test server
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError || strings.Contains(string(body), "hunter2") || strings.Contains(string(body), "handler.go") {
		t.Fatalf("panic leaked to client: %d %q", resp.StatusCode, body)
	}
	if !strings.Contains(logs.String(), "http.panic") {
		t.Fatal("panic not logged")
	}
}

func TestServerTLSConfigIsTLS13WithPQ(t *testing.T) {
	c := ServerTLSConfig(tls.Certificate{})
	// Go's defaults (nil) put the hybrid post-quantum group first (D35);
	// TestHR395_ServerListenersNegotiateHybridWithDefaultClients checks
	// the handshake.
	if c.MinVersion != tls.VersionTLS13 || c.CurvePreferences != nil {
		t.Fatalf("TLS profile = %+v", c)
	}
}
