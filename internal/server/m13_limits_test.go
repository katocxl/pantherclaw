// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// unavailableCounter is a shared counter that cannot be reached.
type unavailableCounter struct{}

func (unavailableCounter) Take(context.Context, string, string, time.Duration, int, int) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("counter unavailable")
}

// TestHR376_AuthZENPointRateIsSharedAndFailsClosed: the decision endpoint
// counts each point's evaluations in the shared limiter, keyed by the
// point, and refuses (429) when the counter cannot be reached, before any
// connection is read or anything decided.
func TestHR376_AuthZENPointRateIsSharedAndFailsClosed(t *testing.T) {
	org := ids.New[ids.Org]()
	c := tapp.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleEnforcementPoint, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}, Credential: tapp.CredAccessToken}
	shared := ratelimit.NewMemory(nil) // stands in for the store both replicas share
	pt := point{Org: org, ID: ids.NewV7(), Rate: 3}
	replica := func(l ratelimit.Limiter) *http.ServeMux {
		e := newAuthZENEndpoint(nil, fakeAuthn{bearer: "good", caller: c}, failDecider{t}, "https://pc.example.test", celenv.Limits{}, nil, nil)
		e.rates = sharedPointRates{l}
		e.pointOf = func(context.Context, tapp.Caller) (point, error) { return pt, nil }
		mux := http.NewServeMux()
		e.mount(mux)
		return mux
	}
	do := func(mux *http.ServeMux, path, body string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer good")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	a, b := replica(shared), replica(shared)
	if st, _ := do(a, authzenEvaluationsPath, `{"evaluations":[{},{}]}`); st != http.StatusOK {
		t.Fatalf("replica a within the rate: %d", st)
	}
	if st, _ := do(b, authzenEvaluationsPath, `{"evaluations":[{},{}]}`); st != http.StatusTooManyRequests {
		t.Fatalf("replica b past the shared rate: %d", st)
	}
	if st, _ := do(b, authzenEvaluationPath, `{}`); st != http.StatusOK {
		t.Fatalf("replica b within the shared rate: %d", st)
	}
	if d, _ := shared.Take(context.Background(), scopeAuthZENPoint, org.String()+"/"+pt.ID.String(), time.Second, 1, 3); d.Allowed {
		t.Fatal("the point's count is not under its org and id")
	}
	st, body := do(replica(unavailableCounter{}), authzenEvaluationPath, `{}`)
	if st != http.StatusTooManyRequests || !strings.Contains(body, authzenRateLimited) {
		t.Fatalf("counter unavailable: %d %s", st, body)
	}
}

// TestHR375_LimitsConfig: limits.api.* default to D8's values and must be
// 1 to 10^6; limits.usage.enforce refuses true (HR-377).
func TestHR375_LimitsConfig(t *testing.T) {
	base := func() Config {
		c := DefaultConfig()
		c.DB.AppPasswordFile, c.KEKFiles = "pw", []string{"kek"}
		return c
	}
	c := base()
	if c.Limits.API.PerOrgPerMinute != 6000 || c.Limits.API.PerCredentialPerMinute != 1200 || c.Limits.Usage.Enforce {
		t.Fatalf("defaults: %+v", c.Limits)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for name, set := range map[string]func(*Config){
		"per_org 0":         func(c *Config) { c.Limits.API.PerOrgPerMinute = 0 },
		"per_org too large": func(c *Config) { c.Limits.API.PerOrgPerMinute = 1_000_001 },
		"per_credential -1": func(c *Config) { c.Limits.API.PerCredentialPerMinute = -1 },
		"usage.enforce":     func(c *Config) { c.Limits.Usage.Enforce = true },
	} {
		c := base()
		set(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "limits.") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
