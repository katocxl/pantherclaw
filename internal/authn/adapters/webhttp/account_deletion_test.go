// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

type deletionAccounts struct {
	fakeAccounts
	account, session ids.UUID
}

func (f *deletionAccounts) AuthenticateAccount(_ context.Context, cookie string) (authnapp.AccountSession, error) {
	now := time.Now()
	s := authnapp.AccountSession{Caller: accounts.Caller{Account: f.account, Session: f.session, Provider: "test"}, CreatedAt: now.Add(-time.Minute), Now: now}
	if cookie == "confirmed" {
		s.DeletionReauthenticatedAt = &now
	} else if cookie != "ordinary" {
		return s, authnapp.ErrUnauthenticated
	}
	return s, nil
}

type deletionPage struct{ called bool }

func (d *deletionPage) Confirm(context.Context, ids.UUID, ids.UUID) error {
	d.called = true
	return nil
}

func TestAccountDeletionRequiresFreshCeremonyAndCSRF(t *testing.T) {
	fa := &deletionAccounts{account: ids.NewV7(), session: ids.NewV7()}
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.WithAccounts(fa, false)
	d := &deletionPage{}
	mux := http.NewServeMux()
	h.Mount(mux)
	h.MountAccountDeletion(mux, d)
	withAccount := func(r *http.Request, cookie string) *http.Request {
		r.Header.Del("Cookie")
		r.AddCookie(&http.Cookie{Name: h.AccountCookieName(), Value: cookie})
		return r
	}
	res := do(t, mux, withAccount(get(authnapp.AccountDeletePath), "ordinary"))
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Body, "Sign in to continue") {
		t.Fatalf("ordinary GET: %d %s", res.StatusCode, res.Body)
	}
	res = do(t, mux, withAccount(post(authnapp.AccountDeletePath), "ordinary"))
	if res.StatusCode != http.StatusForbidden || d.called {
		t.Fatal("ordinary sign-in authorized deletion")
	}
	r := withAccount(post(authnapp.AccountDeletePath), "confirmed")
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Del("Sec-Fetch-Site")
	if res = do(t, mux, r); res.StatusCode != http.StatusForbidden || d.called {
		t.Fatal("cross-origin deletion authorized")
	}
	if res = do(t, mux, withAccount(post(authnapp.AccountDeletePath), "confirmed")); res.StatusCode != http.StatusOK || !d.called {
		t.Fatalf("fresh POST: %d %s", res.StatusCode, res.Body)
	}
	d.called = false
	r = withAccount(post(authnapp.AccountDeletePath), "confirmed")
	r.AddCookie(&http.Cookie{Name: h.SessionCookieName(), Value: "good"})
	if res = do(t, mux, r); res.StatusCode != http.StatusUnauthorized || d.called {
		t.Fatal("ambiguous cookies authorized deletion")
	}
}
