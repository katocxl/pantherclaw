// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR397_HealthListenerOnlyForWorkers: health.addr is accepted for role
// worker only (roles api and all serve the probes on the API listener),
// must be host:port, and is optional.
func TestHR397_HealthListenerOnlyForWorkers(t *testing.T) {
	for _, tc := range []struct {
		role, addr string
		ok         bool
	}{
		{RoleWorker, "0.0.0.0:8081", true},
		{RoleWorker, "127.0.0.1:0", true},
		{RoleWorker, "", true},
		{RoleAPI, "", true},
		{RoleAll, "", true},
		{RoleAPI, "0.0.0.0:8081", false},
		{RoleAll, "127.0.0.1:8081", false},
		{RoleWorker, "8081", false},
	} {
		c := DefaultConfig()
		c.Role, c.Health.Addr = tc.role, tc.addr
		errs := c.validateHealth()
		if (len(errs) == 0) != tc.ok {
			t.Errorf("role %s, health.addr %q: errors %v, want ok=%v", tc.role, tc.addr, errs, tc.ok)
		}
	}
	c := DefaultConfig()
	c.Role, c.Health.Addr = RoleAll, "127.0.0.1:8081"
	if errs := c.validateHealth(); len(errs) == 0 || !strings.Contains(errs[0].Error(), "only for role worker") {
		t.Errorf("role all with health.addr: %v", errs)
	}
}

// TestHR397_HealthHandlerServesOnlyProbes: the health listener's handler
// answers /livez and routes /readyz, and nothing else: no API procedure,
// no JWKS, no console, no other method.
func TestHR397_HealthHandlerServesOnlyProbes(t *testing.T) {
	h := healthHandler(nil, nil, false, pclog.Discard())
	do := func(method, path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, path, nil))
		return rec.Code
	}
	if code := do(http.MethodGet, "/livez"); code != http.StatusOK {
		t.Errorf("/livez = %d", code)
	}
	for _, path := range []string{
		"/", "/.well-known/pantherclaw/jwks.json", "/pantherclaw.v1.SystemService/GetBuildInfo",
		"/oauth2/token", "/account", "/metrics", "/livez/x", "/readyz/x",
	} {
		if code := do(http.MethodGet, path); code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, code)
		}
	}
	if code := do(http.MethodPost, "/livez"); code != http.StatusMethodNotAllowed {
		t.Errorf("POST /livez = %d, want 405", code)
	}
}
