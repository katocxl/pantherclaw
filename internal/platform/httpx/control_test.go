// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type headerAdder struct{ base http.RoundTripper }

func (h headerAdder) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Control", "1")
	return h.base.RoundTrip(r)
}

func TestControlClientNeverFollowsRedirectsOrProxies(t *testing.T) {
	var hits, wrapped int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Control") == "1" {
			wrapped++
		}
		if r.URL.Path == "/target" {
			hits++
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("NO_PROXY", "")
	c := NewControlClient(ControlConfig{Wrap: func(rt http.RoundTripper) http.RoundTripper { return headerAdder{rt} }})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/start", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request went to the environment proxy: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || hits != 0 {
		t.Fatalf("status %d, target hits %d: redirect was followed", resp.StatusCode, hits)
	}
	if wrapped != 1 {
		t.Fatalf("wrapped transport used %d times, want 1", wrapped)
	}
}

func TestStreamingClientKeepsTheRedirectPolicyWithoutATimeout(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			hits++
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer srv.Close()
	base := NewControlClient(ControlConfig{Timeout: time.Second})
	c := StreamingClient(base)
	if c.Timeout != 0 || c.Transport != base.Transport {
		t.Fatalf("timeout %v, same transport %v: want no timeout and the base transport", c.Timeout, c.Transport == base.Transport)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/start", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || hits != 0 {
		t.Fatalf("status %d, target hits %d: the streaming client followed a redirect", resp.StatusCode, hits)
	}
}
