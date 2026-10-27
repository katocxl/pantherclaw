// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestControlClientUsesOnlyAnExplicitProxy (G0 M2 follow-up): the control
// client goes through a proxy only when ControlConfig.Proxy names one,
// never because of HTTPS_PROXY or HTTP_PROXY, and never for loopback hosts.
func TestControlClientUsesOnlyAnExplicitProxy(t *testing.T) {
	var proxied []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = append(proxied, r.URL.String())
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	var direct int
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { direct++ }))
	defer target.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	get := func(c *http.Client, u string) int {
		t.Helper()
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}

	// Off by default: the environment's proxy is ignored (HR-072).
	off := NewControlClient(ControlConfig{})
	if tr := off.Transport.(*http.Transport); tr.Proxy != nil {
		t.Fatal("the control transport has a proxy function without the opt-in")
	}
	get(off, target.URL)
	if direct != 1 || len(proxied) != 0 {
		t.Fatalf("without the opt-in: direct %d, proxied %v", direct, proxied)
	}

	p, err := ParseControlProxy(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	on := NewControlClient(ControlConfig{Proxy: p})
	if code := get(on, "http://control.example.invalid/v1/x"); code != http.StatusNoContent ||
		len(proxied) != 1 || proxied[0] != "http://control.example.invalid/v1/x" {
		t.Fatalf("with the opt-in: status %d, proxied %v", code, proxied)
	}
	// Loopback servers are reached directly.
	get(on, target.URL)
	if direct != 2 || len(proxied) != 1 {
		t.Fatalf("loopback with the opt-in: direct %d, proxied %v", direct, proxied)
	}
}

// TestHR072_EgressIgnoresProxiesWithTheControlOptIn: pclaw's control
// proxy opt-in leaves every egress client as it was: no proxy function,
// and requests go to the target directly whatever the environment says.
func TestHR072_EgressIgnoresProxiesWithTheControlOptIn(t *testing.T) {
	var proxied int
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxied++ }))
	defer proxy.Close()
	var direct bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { direct = true }))
	defer target.Close()
	t.Setenv("PANTHERCLAW_HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	// A control client with the opt-in exists in the same process.
	p, err := ParseControlProxy(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = NewControlClient(ControlConfig{Proxy: p})

	c := NewEgressClient(EgressConfig{AllowedPrefixes: loopback})
	if tr := c.Transport.(*http.Transport); tr.Proxy != nil {
		t.Fatal("egress transport has a proxy function")
	}
	resp, err := c.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !direct || proxied != 0 {
		t.Fatalf("egress: direct %v, proxied %d", direct, proxied)
	}
}

func TestParseControlProxy(t *testing.T) {
	for _, ok := range []string{"http://proxy.corp:3128", "https://proxy.corp:443/", "http://user:pass@10.0.0.1:8080"} {
		u, err := ParseControlProxy(ok)
		if err != nil || u.Path != "" {
			t.Errorf("%s: %v %v", ok, u, err)
		}
	}
	for _, bad := range []string{"", "proxy.corp:3128", "socks5://proxy:1080", "http://", "http://proxy/path", "http://proxy?x=1", "file:///etc/passwd", "http://[::1"} {
		if _, err := ParseControlProxy(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseControlProxy("http://user:secret@[::1"); err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("error leaks the password: %v", err)
	}
}
