// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/accounts"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
)

func TestAccountDeletionForcesAccountBoundSingleUseAuthentication(t *testing.T) {
	b := newBrowserEnv(t)
	store := b.withAccounts(t, true)
	ctx := context.Background()
	a, err := store.Resolve(ctx, accounts.Identity{Issuer: b.idp.Issuer(), Subject: "alice", Email: "alice@example.test"}, "")
	if err != nil {
		t.Fatal(err)
	}
	begin := func() authnapp.Redirect {
		t.Helper()
		red, err := b.browser.Start(ctx, authnapp.BrowserStart{Provider: "test", Next: authnapp.AccountDeletePath, DeletionAccount: a.ID})
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(red.URL)
		if err != nil {
			t.Fatal(err)
		}
		if u.Query().Get("prompt") != "login" || u.Query().Get("max_age") != "0" {
			t.Fatalf("forced auth URL: %s", red.URL)
		}
		return red
	}
	for _, user := range []oidctest.User{
		{Subject: "alice", OmitAuthTime: true},
		{Subject: "alice", AuthTime: time.Now().Add(-time.Hour)},
		{Subject: "different-user"},
	} {
		b.idp.SignIn(user)
		red := begin()
		out, err := b.browser.Callback(ctx, "test", b.authorize(t, red.URL), red.Binding, authnapp.ClientMeta{})
		if err != nil {
			t.Fatal(err)
		}
		if out.Secret != "" || out.Reason != "LOGIN_FAILED" {
			t.Fatalf("invalid forced authentication: %+v", out)
		}
	}
	b.idp.SignIn(oidctest.User{Subject: "alice", Email: "alice@example.test"})
	red := begin()
	out, err := b.browser.Callback(ctx, "test", b.authorize(t, red.URL), red.Binding, authnapp.ClientMeta{})
	if err != nil || out.Kind != authnapp.SessionAccount || out.Account != a.ID || out.Next != authnapp.AccountDeletePath {
		t.Fatalf("forced callback: %+v %v", out, err)
	}
	s, err := b.browser.AuthenticateAccount(ctx, out.Secret)
	if err != nil || s.DeletionReauthenticatedAt == nil {
		t.Fatalf("ceremony session: %+v %v", s, err)
	}
	d := accounts.NewDeletion(store, nil, nil)
	// Alice is the last administrator, so confirmation is refused before intent.
	if err := d.Confirm(ctx, a.ID, s.Session); !errors.Is(err, accounts.ErrLastAdmin) {
		t.Fatalf("last administrator: %v", err)
	}
	if err := d.Confirm(ctx, a.ID, s.Session); !errors.Is(err, accounts.ErrReauth) {
		t.Fatalf("reused ceremony: %v", err)
	}
}
