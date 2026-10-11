// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestT066_ACredentialDoesNotFollowItsConnectionToAnotherHost: the
// payments connection holds a sealed credential (custody, HR-061). A
// person who may manage connections, or someone using their session,
// re-points it at another host they control (T-066). The connection
// follows, and the gateway serves the new configuration, but the sealed
// credential stays bound to the host it was sealed for: the refund is
// refused as credential_unavailable before any byte is sent, and the new
// host never gets the refund or the credential.
func TestT066_ACredentialDoesNotFollowItsConnectionToAnotherHost(t *testing.T) {
	const custody = "e2e-held-credential"
	s := start(t, options{budget: "1000.00", access: capp.AccessHeld, token: custody})
	if code, r := s.refund(t, ids.NewV7(), "30.00"); code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("before: %d %+v", code, r)
	}

	// The other host records every request: the refund, and any
	// verification read of the earlier refund (G0 M7) made after the move.
	var mu sync.Mutex
	var seen []*http.Request
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Clone(r.Context()))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"re_other","status":"succeeded"}`)
	}))
	t.Cleanup(other.Close)

	admin := s.person(t, "connection-admin", td.RoleGatewayAdmin)
	conns := capp.New(s.pool, nil, s.apiURL, "")
	c, err := conns.Get(admin.ctx, s.conn)
	if err != nil {
		t.Fatal(err)
	}
	base := other.URL
	moved, err := conns.Update(admin.ctx, capp.UpdateInput{ID: s.conn, Revision: c.Revision, BaseURL: &base})
	if err != nil {
		t.Fatal(err)
	}
	if moved.BaseUrl == nil || *moved.BaseUrl != base {
		t.Fatalf("the connection was not re-pointed: %+v", moved.PcConnection)
	}
	s.waitConfig(t, s.configVersion(t, s.gatewayID(t)))

	code, r := s.refund(t, ids.NewV7(), "31.00")
	if code != http.StatusBadGateway || r.Error != "credential_unavailable" {
		t.Fatalf("a refund through the re-pointed connection: %d %+v", code, r)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, req := range seen {
		if v := req.Header.Get("Authorization"); v != "" || req.Method != http.MethodGet {
			t.Errorf("the other host got %s %s with Authorization %q", req.Method, req.URL.Path, v)
		}
	}
	if st := s.sim.Stats(); st.Refunds != 1 {
		t.Fatalf("target %+v, want only the refund before", st)
	}
}
