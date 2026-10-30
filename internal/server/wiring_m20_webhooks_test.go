// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

type orgJWKS map[ids.OrgID]string

func (j orgJWKS) WebhookJWKS(_ context.Context, org ids.OrgID) ([]byte, error) {
	if b, ok := j[org]; ok {
		return []byte(b), nil
	}
	return emptyJWKS, nil
}

// TestHR511_WebhookJWKSRouteServesThePathsOrgOnly: the per-org JWKS route
// asks for the org named in its path and nothing else; an unknown org gets
// the same empty set, and the platform org and malformed ids get 404
// (G0 M20 D251).
// Covers: PN-018
func TestHR511_WebhookJWKSRouteServesThePathsOrgOnly(t *testing.T) {
	a, b := ids.New[ids.Org](), ids.New[ids.Org]()
	src := orgJWKS{a: `{"keys":[{"kid":"webhooks-a"}]}`, b: `{"keys":[{"kid":"webhooks-b"}]}`}
	mux := http.NewServeMux()
	mountWebhookJWKS(mux, src, nil, pclog.Discard())
	get := func(org string) (int, string, string) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/pantherclaw/orgs/"+org+"/webhook-jwks.json", nil))
		body, _ := io.ReadAll(rec.Body)
		return rec.Code, string(body), rec.Header().Get("Content-Type")
	}
	if code, body, ct := get(a.String()); code != http.StatusOK || body != src[a] || ct != "application/jwk-set+json" {
		t.Fatalf("org a: %d %s %s", code, body, ct)
	}
	if code, body, _ := get(b.String()); code != http.StatusOK || body != src[b] {
		t.Fatalf("org b: %d %s", code, body)
	}
	if code, body, _ := get(ids.New[ids.Org]().String()); code != http.StatusOK || body != string(emptyJWKS) {
		t.Fatalf("unknown org: %d %s", code, body)
	}
	for _, bad := range []string{ids.PlatformOrg.String(), "not-a-uuid"} {
		if code, _, _ := get(bad); code != http.StatusNotFound {
			t.Fatalf("%s: %d, want 404", bad, code)
		}
	}
	// Without a source the route serves the empty set.
	mux = http.NewServeMux()
	mountWebhookJWKS(mux, nil, nil, pclog.Discard())
	if code, body, _ := get(a.String()); code != http.StatusOK || body != string(emptyJWKS) {
		t.Fatalf("no source: %d %s", code, body)
	}
}

// TestHR511_WebhookJWKSRouteIsRateLimitedPerClient: one client address
// gets webhookJWKSRateLimit requests a minute, then 429 with Retry-After;
// another address is unaffected (D271).
// Covers: PN-018
func TestHR511_WebhookJWKSRouteIsRateLimitedPerClient(t *testing.T) {
	mux := http.NewServeMux()
	mountWebhookJWKS(mux, nil, nil, pclog.Discard())
	get := func(addr string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/pantherclaw/orgs/"+ids.New[ids.Org]().String()+"/webhook-jwks.json", nil)
		req.RemoteAddr = addr
		mux.ServeHTTP(rec, req)
		return rec
	}
	for i := range webhookJWKSRateLimit {
		if rec := get("203.0.113.7:4000"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i+1, rec.Code)
		}
	}
	if rec := get("203.0.113.7:4001"); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("over the limit: %d %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := get("198.51.100.9:4000"); rec.Code != http.StatusOK {
		t.Fatalf("another client: %d", rec.Code)
	}
}
