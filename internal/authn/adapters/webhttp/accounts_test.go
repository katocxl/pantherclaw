// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/accounts"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// fakeAccounts accepts the account cookies "fresh" (signed in a minute
// ago) and "stale" (16 minutes ago); PickOrg applies the picker window as
// the real use case does.
type fakeAccounts struct{ picked bool }

func (f *fakeAccounts) AuthenticateAccount(_ context.Context, cookie string) (authnapp.AccountSession, error) {
	now := time.Now()
	switch cookie {
	case "fresh":
		return authnapp.AccountSession{CreatedAt: now.Add(-time.Minute), Now: now}, nil
	case "stale":
		return authnapp.AccountSession{CreatedAt: now.Add(-16 * time.Minute), Now: now}, nil
	}
	return authnapp.AccountSession{}, authnapp.ErrUnauthenticated
}

func (f *fakeAccounts) Memberships(context.Context, authnapp.AccountSession) ([]accounts.Membership, error) {
	return []accounts.Membership{{Org: testOrg, Name: "Acme", Slug: "acme"}}, nil
}

func (f *fakeAccounts) PickOrg(_ context.Context, s authnapp.AccountSession, org ids.OrgID, _ authnapp.ClientMeta) (authnapp.BrowserSignIn, error) {
	if !authnapp.PickerFresh(s) {
		return authnapp.BrowserSignIn{}, authnapp.ErrPickerStale
	}
	f.picked = true
	return authnapp.BrowserSignIn{Org: org, Secret: "org-session", Next: authnapp.AccountPath}, nil
}

func (f *fakeAccounts) EndAccountSession(context.Context, authnapp.AccountSession, string) error {
	return nil
}

// TestHR353_AStalePickerStartsAFreshSignInToTheSameOrg (D88): within 15
// minutes of its sign-in an account session picks an org; after that the
// picker page and a pick send the browser to a fresh sign-in (the pick
// keeps its org hint and destination) and clear the account cookie.
func TestHR353_AStalePickerStartsAFreshSignInToTheSameOrg(t *testing.T) {
	if authnapp.PickerFreshness != 15*time.Minute {
		t.Fatalf("picker window %s, want 15m (D88)", authnapp.PickerFreshness)
	}
	fa := &fakeAccounts{}
	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.WithAccounts(fa, false)
	mux := http.NewServeMux()
	h.Mount(mux)

	withAccount := func(r *http.Request, v string) *http.Request {
		r.Header.Del("Cookie")
		r.AddCookie(&http.Cookie{Name: h.AccountCookieName(), Value: v})
		return r
	}
	cleared := func(res result) bool {
		for _, c := range res.Cookies() {
			if c.Name == h.AccountCookieName() && c.MaxAge < 0 {
				return true
			}
		}
		return false
	}

	// Fresh: the picker renders and a pick opens the org.
	if res := do(t, mux, withAccount(get(authnapp.OrgPickerPath), "fresh")); res.StatusCode != http.StatusOK {
		t.Fatalf("fresh picker: %d", res.StatusCode)
	}
	if res := do(t, mux, withAccount(post(authnapp.OrgPickerPath+"/"+testOrg.String()), "fresh")); res.StatusCode != http.StatusOK || !fa.picked {
		t.Fatalf("fresh pick: %d %s", res.StatusCode, res.Body)
	}

	// Stale picker page: a redirect to the sign-in start.
	res := do(t, mux, withAccount(get(authnapp.OrgPickerPath), "stale"))
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != authnapp.LoginPath || !cleared(res) {
		t.Errorf("stale picker: %d %q cleared=%v", res.StatusCode, res.Header.Get("Location"), cleared(res))
	}

	// Stale pick: no session, a sign-in link to the same org instead.
	fa.picked = false
	res = do(t, mux, withAccount(post(authnapp.OrgPickerPath+"/"+testOrg.String()), "stale"))
	var body map[string]string
	if err := json.Unmarshal([]byte(res.Body), &body); err != nil {
		t.Fatalf("stale pick body %q: %v", res.Body, err)
	}
	if res.StatusCode != http.StatusUnauthorized || body["error"] != "sign_in_again" || fa.picked || !cleared(res) {
		t.Fatalf("stale pick: %d %s cleared=%v", res.StatusCode, res.Body, cleared(res))
	}
	u, err := url.Parse(body["sign_in"])
	if err != nil || u.IsAbs() || u.Path != authnapp.LoginPath || u.Query().Get("org") != testOrg.String() ||
		u.Query().Get("next") != authnapp.AccountPath {
		t.Errorf("stale pick sign-in link %q", body["sign_in"])
	}
	for _, c := range res.Cookies() {
		if c.Name == h.SessionCookieName() && c.Value != "" {
			t.Errorf("a stale pick set an org session cookie")
		}
	}
}
