// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/tenancy/adapters/tenancyrpc"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

type noBearer struct{}

func (noBearer) Authenticate(context.Context, string) (tapp.Caller, error) {
	return tapp.Caller{}, authnapp.ErrUnauthenticated
}

// TestHR351_CreateOrgThroughTheAPIIsRateLimitedPerClientAddress (D85): the
// API's account sessions carry the trusted-proxy-aware client address, so
// accounts behind one address share its CreateOrg limit.
func TestHR351_CreateOrgThroughTheAPIIsRateLimitedPerClientAddress(t *testing.T) {
	d := dbtest.New(t)
	pool := d.AppPool(t)
	ctx := context.Background()
	cfg := uiWebConfig()
	cfg.Billing.Mode, cfg.Signup.SelfServe = "off", true
	cfg.Signup.PerIPPerHour, cfg.Signup.PerAccountPerHour, cfg.Signup.MaxOrgsPerAccount = 2, 100, 100
	ents, err := entitlements.New(pool, entitlements.LicenceFunc(func(context.Context) (billing.Entitlements, error) {
		return billing.CommunityEntitlements(), nil
	}), entitlements.ModeOff, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ui := newUITenancy(&cfg, pool, ents)

	var handler http.Handler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	browser := authnapp.NewBrowser(pool, ts.URL, nil, clock.System{}, nil).WithAccounts(ui.store, ui.invites, true)
	sessions, err := webguard.NewSessions(browser, ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(noBearer{}, procedurePermissions, nil,
		rpcauth.WithBrowserSessions(sessions, nil), rpcauth.WithAccountSessions(browser, "pc_account", ts.URL))})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterTenancyServiceHandler(rs, tenancyHandler(tenancyrpc.NewTenancy(tapp.NewHierarchy(pool, nil)), ui))
	mux := http.NewServeMux()
	rpc.Mount(mux, rs)
	handler = httpx.ClientIPMiddleware(mux, httpx.NewLimiter(1000, 60_000_000_000, nil).ClientIP)

	// Three accounts behind one address, each with an account session.
	cookies := make([]string, 3)
	var acct []ids.UUID
	for i := range cookies {
		a, err := ui.store.Resolve(ctx, accounts.Identity{
			Issuer: "https://idp.test", Subject: []string{"a", "b", "c"}[i], Email: []string{"a", "b", "c"}[i] + "@example.test", EmailVerified: true,
		}, "")
		if err != nil {
			t.Fatal(err)
		}
		acct = append(acct, a.ID)
		tok, err := credential.New(credential.AccountSession, "", ids.PlatformOrg)
		if err != nil {
			t.Fatal(err)
		}
		if err := pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
			_, err := dbq.New(tx).InsertAccountSession(ctx, dbq.InsertAccountSessionParams{
				ID: ids.NewV7(), AccountID: a.ID, SecretHash: tok.Hash(), Provider: "test", TtlSeconds: 3600,
			})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		cookies[i] = tok.Reveal()
	}
	create := func(cookie string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+pantherclawv1connect.TenancyServiceCreateOrgProcedure,
			strings.NewReader(`{"name":"Acme","slug":"acme","termsVersion":"1","dpaVersion":"1"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Origin", ts.URL)
		req.Header.Set(webguard.CSRFHeader, "1")
		req.Header.Set("Cookie", "pc_account="+cookie)
		res, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var b strings.Builder
		buf := make([]byte, 4096)
		n, _ := res.Body.Read(buf)
		b.Write(buf[:n])
		return res.StatusCode, b.String()
	}
	for i := range 2 {
		if code, body := create(cookies[i]); code != http.StatusOK {
			t.Fatalf("account %d: %d %s", i, code, body)
		}
	}
	if code, body := create(cookies[2]); code == http.StatusOK || !strings.Contains(body, "RATE_LIMITED") {
		t.Errorf("third account from the same address: %d %s", code, body)
	}
	var recorded int
	if err := pool.InGlobalTx(ctx, db.GlobalAccounts, func(ctx context.Context, tx db.GlobalTx) error {
		return tx.QueryRow(ctx, `SELECT count(*)::int FROM pc.account_events WHERE client_ip = '127.0.0.1'
			AND kind IN ('ORG_CREATED', 'ORG_CREATE_REFUSED') AND account_id = ANY($1)`, acct).Scan(&recorded)
	}); err != nil {
		t.Fatal(err)
	}
	if recorded != 3 {
		t.Errorf("events with the client address = %d, want 3", recorded)
	}
}
