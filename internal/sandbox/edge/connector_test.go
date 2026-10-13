// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package edge

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR216_AConnectorsEdgeSendsOnlyToTheEgressListener: in connector mode
// the edge sends each request a connector makes to a mapped host to the
// gateway's egress listener, with the binding token and the request as
// data, its credentials stripped and reported; it holds no key and signs
// nothing, and without a binding it sends nothing (G0 M9 track C).
func TestHR216_AConnectorsEdgeSendsOnlyToTheEgressListener(t *testing.T) {
	var mu sync.Mutex
	var got []Egress
	var bindings []string
	egress := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in Egress
		if r.URL.Path != EgressPath || r.Method != http.MethodPost || json.UnmarshalRead(r.Body, &in) != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mu.Lock()
		got, bindings = append(got, in), append(bindings, r.Header.Get(HeaderBinding))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Target-Internal", "1")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(egress.Close)
	binding := "binding-token"
	var log bytes.Buffer
	e, err := New(Options{
		GatewayURL: egress.URL, Hosts: map[string]string{"api.github.com": "github"}, Binding: func() string { return binding },
		Placeholder: "pantherclaw-placeholder", Log: pclog.New(&log, pclog.Options{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ps := httptest.NewServer(e)
	t.Cleanup(ps.Close)
	proxy, _ := url.Parse(ps.URL)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(e.CACertificate())
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://api.github.com/repos/acme/app/issues?access_token=s3cret&per_page=5",
		strings.NewReader(`{"title":"x"}`))
	req.Header.Set("Authorization", "token ghp_planted0123456789")
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || string(b) != `{"ok":true}` || res.Header.Get("X-Target-Internal") != "" {
		t.Fatalf("connector got %d %s %v", res.StatusCode, b, res.Header)
	}
	mu.Lock()
	if len(got) != 1 || bindings[0] != binding {
		t.Fatalf("egress got %d requests, bindings %q", len(got), bindings)
	}
	g := got[0]
	mu.Unlock()
	if g.Connection != "github" || g.Method != http.MethodPost || g.Host != "api.github.com" || g.Path != "/repos/acme/app/issues" ||
		g.Query != "per_page=5" || string(g.Body) != `{"title":"x"}` || g.Headers["Content-Type"] != "application/json" || len(g.Headers) != 1 {
		t.Fatalf("egress request %+v", g)
	}
	if e.Stripped() != 2 || strings.Contains(log.String(), "ghp_planted") || strings.Contains(log.String(), "s3cret") {
		t.Fatalf("stripped %d:\n%s", e.Stripped(), log.String())
	}

	// The placeholder is dropped like a credential, but it is no secret and
	// is not reported.
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.github.com/user?token=pantherclaw-placeholder", nil)
	req.Header.Set("Authorization", "Bearer pantherclaw-placeholder")
	if res, err = client.Do(req); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	mu.Lock()
	if len(got) != 2 || got[1].Query != "" || len(got[1].Headers) != 0 {
		t.Fatalf("egress got %+v", got)
	}
	mu.Unlock()
	if e.Stripped() != 2 {
		t.Fatalf("the placeholder was reported: %d", e.Stripped())
	}
	// A real token next to the placeholder is reported as any credential.
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "ghp_"+strings.Repeat("a", 20)+" pantherclaw-placeholder")
	if res, err = client.Do(req); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if e.Stripped() != 3 {
		t.Fatalf("a token beside the placeholder was not reported: %d", e.Stripped())
	}

	binding = ""
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.github.com/user", nil)
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable || res.Header.Get(HeaderRefusedBy) != "edge" {
		t.Fatalf("without a binding: %d", res.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatal("a request without a binding reached the egress listener")
	}
}

// TestHR216_TheBindingTokenGoesInClearOnlyToANonRoutableAddress: a
// connector's edge refuses a plain-HTTP egress listener on a routable
// address, which would carry the binding token in clear.
func TestHR216_TheBindingTokenGoesInClearOnlyToANonRoutableAddress(t *testing.T) {
	hosts := map[string]string{"api.github.com": "github"}
	binding := func() string { return "b" }
	for _, c := range []struct {
		url, addr string
		ok        bool
	}{
		{"http://203.0.113.7:8095", "", false},
		{"http://gateway.example.com:8095", "", false},
		{"http://gateway.example.com:8095", "198.51.100.1:8095", false},
		{"http://127.0.0.1:8095", "", true},
		{"http://10.20.0.1:8095", "", true},
		{"http://host.docker.internal:8095", "", true},
		{"http://gateway.example.com:8095", "172.17.0.1:8095", true},
		{"https://gateway.example.com", "", true},
	} {
		_, err := New(Options{GatewayURL: c.url, GatewayAddr: c.addr, Hosts: hosts, Binding: binding})
		if (err == nil) != c.ok {
			t.Errorf("%s via %q: %v", c.url, c.addr, err)
		}
	}
}
