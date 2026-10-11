// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package webhttp_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/webauthntest"
)

// p1tThief is another browser holding a copy of s's session cookie.
func p1tThief(t *testing.T, s *site, cookie string) *site {
	t.Helper()
	u, err := url.Parse(s.url)
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(u, []*http.Cookie{{Name: "pc_session", Value: cookie, Path: "/"}})
	return &site{url: s.url, org: s.org, pool: s.pool, client: &http.Client{
		Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// p1tStepUp runs a step-up ceremony on the account page with a and
// returns the final response.
func p1tStepUp(t *testing.T, s *site, a *webauthntest.Authenticator) (int, map[string]jsontext.Value) {
	t.Helper()
	status, body := s.postJSONBody(t, authnapp.AccountPath+"/step-up-options", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("step-up options: %d %v", status, body)
	}
	resp, err := a.Assert(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	return s.postJSONBody(t, authnapp.AccountPath+"/step-up", map[string]any{"ceremony": body["ceremony"], "response": jsontext.Value(resp)})
}

// p1tRefused checks a refusal's status and error code.
func p1tRefused(t *testing.T, what string, status int, body map[string]jsontext.Value, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus || string(body["error"]) != `"`+wantCode+`"` {
		t.Errorf("%s: %d %v, want %d %s", what, status, body, wantStatus, wantCode)
	}
}

// TestT052_AStolenCookieCannotChangeKeysOnTheAccountPage: T-052 through
// the account page — Mallory replays a stolen cookie of alice's ordinary
// sign-in from her own client, with whatever headers she likes. Adding a
// key and removing alice's key need a recent sign-in, a step-up she relays
// to alice through a phishing origin fails verification, and alice's own
// step-up in her browser does not unlock Mallory's copy of the old
// session. TestHR155_AKeyLifecycleThroughTheAccountPage is the honest path.
func TestT052_AStolenCookieCannotChangeKeysOnTheAccountPage(t *testing.T) {
	s := newSite(t)
	key, err := webauthntest.New(s.url, "localhost", webauthntest.ES256)
	if err != nil {
		t.Fatal(err)
	}
	s.signIn(t)
	mallory := p1tThief(t, s, s.cookie(t))

	// Alice signs in again recently, as the page asks, and adds her key.
	status, body := s.postJSONBody(t, authnapp.AccountPath+"/keys/registration-options", map[string]any{})
	var signIn string
	if err := json.Unmarshal(body["sign_in"], &signIn); status != http.StatusForbidden || err != nil {
		t.Fatalf("registration options before a recent sign-in: %d %v", status, body)
	}
	s.follow(t, s.url+signIn)
	status, body = s.postJSONBody(t, authnapp.AccountPath+"/keys/registration-options", map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("registration options: %d %v", status, body)
	}
	resp, err := key.Register(body["options"])
	if err != nil {
		t.Fatal(err)
	}
	status, body = s.postJSONBody(t, authnapp.AccountPath+"/keys", map[string]any{
		"ceremony": body["ceremony"], "name": "Desk key", "response": jsontext.Value(resp),
	})
	var keyID string
	if err := json.Unmarshal(body["id"], &keyID); status != http.StatusOK || err != nil {
		t.Fatalf("add key: %d %v", status, body)
	}

	status, body = mallory.postJSONBody(t, authnapp.AccountPath+"/keys/registration-options", map[string]any{})
	p1tRefused(t, "Mallory adds a key", status, body, http.StatusForbidden, "recent_auth_required")
	status, body = mallory.postJSONBody(t, authnapp.AccountPath+"/keys/"+keyID+"/remove", map[string]any{})
	p1tRefused(t, "Mallory removes alice's key", status, body, http.StatusForbidden, "recent_auth_required")

	key.Origin = "http://pc-localhost.example"
	status, body = p1tStepUp(t, mallory, key)
	key.Origin = s.url
	p1tRefused(t, "a step-up relayed from a phishing origin", status, body, http.StatusBadRequest, "verification_failed")

	if status, body = p1tStepUp(t, s, key); status != http.StatusOK {
		t.Fatalf("alice's own step-up: %d %v", status, body)
	}
	status, body = mallory.postJSONBody(t, authnapp.AccountPath+"/keys/"+keyID+"/remove", map[string]any{})
	p1tRefused(t, "Mallory removes alice's key after alice's step-up", status, body, http.StatusForbidden, "recent_auth_required")
	if page := s.get(t, s.url+authnapp.AccountPath); page.StatusCode != http.StatusOK || !strings.Contains(page.Body, "Desk key") {
		t.Fatalf("alice's account page: %d", page.StatusCode)
	}
}
