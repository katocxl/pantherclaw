// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package oidcrp_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/oidctest"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// signIn runs one authorization code flow against idp and exchanges the
// code.
func signIn(t *testing.T, idp *oidctest.Provider, tokenAuth string) error {
	t.Helper()
	p, err := oidcrp.New(oidcrp.Config{
		Name: "corp", Issuer: idp.Issuer(), ClientID: idp.ClientID, ClientSecret: pclog.NewSecret([]byte(idp.ClientSecret)),
		AllowInsecureLoopback: true, HTTPClient: idp.Client(), TokenAuth: tokenAuth,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const redirect = "http://127.0.0.1:1/oauth2/callback/corp"
	verifier := strings.Repeat("v", 43)
	u, err := p.AuthCodeURL(ctx, authnapp.AuthRequest{State: "s", Nonce: "n", Verifier: verifier, RedirectURI: redirect})
	if err != nil {
		t.Fatal(err)
	}
	c := idp.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	_, err = p.Exchange(ctx, loc.Query().Get("code"), verifier, redirect)
	return err
}

// TestTokenEndpointAuth: token_auth basic (the default) sends the client
// secret with HTTP Basic and post sends it as form fields (G0 UI D32);
// each fails against a provider that takes only the other; any other value
// is refused.
func TestTokenEndpointAuth(t *testing.T) {
	user := oidctest.User{Subject: "alice", Email: "alice@example.com", EmailVerified: true}
	basic := oidctest.New(t)
	basic.SignIn(user)
	post := oidctest.New(t)
	post.SignIn(user)
	post.Set(oidctest.Knobs{TokenAuthPost: true})
	for _, tc := range []struct {
		name      string
		idp       *oidctest.Provider
		tokenAuth string
		ok        bool
	}{
		{"default is basic", basic, "", true},
		{"basic", basic, oidcrp.TokenAuthBasic, true},
		{"post", post, oidcrp.TokenAuthPost, true},
		{"basic against a post provider", post, oidcrp.TokenAuthBasic, false},
		{"post against a basic provider", basic, oidcrp.TokenAuthPost, false},
	} {
		if err := signIn(t, tc.idp, tc.tokenAuth); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	for _, bad := range []string{"private_key_jwt", "none", "Basic", "client_secret_post"} {
		if _, err := oidcrp.New(oidcrp.Config{
			Name: "corp", Issuer: basic.Issuer(), ClientID: "c", ClientSecret: pclog.NewSecret([]byte("s")),
			AllowInsecureLoopback: true, TokenAuth: bad,
		}); err == nil {
			t.Errorf("token_auth %q accepted", bad)
		}
	}
}
