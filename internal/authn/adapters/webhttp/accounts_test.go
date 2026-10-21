// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"strings"
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
	case "no-org":
		return authnapp.AccountSession{CreatedAt: now.Add(-time.Minute), Now: now, Email: "none@example.test"}, nil
	}
	return authnapp.AccountSession{}, authnapp.ErrUnauthenticated
}

func (f *fakeAccounts) Memberships(_ context.Context, s authnapp.AccountSession) ([]accounts.Membership, error) {
	if s.Email == "none@example.test" {
		return nil, nil
	}
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
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != authnapp.LoginPath+"?next=%2Faccount" || !cleared(res) {
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

	// The page the sign-in asked for survives the picker (reviewer LOW on
	// D88): a valid return path is kept, anything else becomes /account.
	const console = "/app/agents?tab=runs"
	for _, tc := range []struct{ next, want string }{
		{console, console},
		{"/approvals", "/approvals"},
		{"https://evil.example/x", authnapp.AccountPath},
		{"//evil.example", authnapp.AccountPath},
		{"/app/../account", authnapp.AccountPath},
		{"", authnapp.AccountPath},
	} {
		q := "?" + url.Values{"next": {tc.next}}.Encode()
		pick := post(authnapp.OrgPickerPath + "/" + testOrg.String() + q)

		res = do(t, mux, withAccount(get(authnapp.OrgPickerPath+q), "stale"))
		if u, err := url.Parse(res.Header.Get("Location")); err != nil || u.Query().Get("next") != tc.want {
			t.Errorf("stale picker, next %q: %q", tc.next, res.Header.Get("Location"))
		}
		res = do(t, mux, withAccount(pick, "stale"))
		body = nil
		_ = json.Unmarshal([]byte(res.Body), &body)
		if u, err := url.Parse(body["sign_in"]); err != nil || u.Query().Get("next") != tc.want || u.Query().Get("org") != testOrg.String() {
			t.Errorf("stale pick, next %q: %s", tc.next, res.Body)
		}
		res = do(t, mux, withAccount(post(authnapp.OrgPickerPath+"/"+testOrg.String()+q), "fresh"))
		body = nil
		_ = json.Unmarshal([]byte(res.Body), &body)
		if res.StatusCode != http.StatusOK || body["next"] != tc.want {
			t.Errorf("fresh pick, next %q: %s", tc.next, res.Body)
		}
		res = do(t, mux, withAccount(get(authnapp.OrgPickerPath+q), "fresh"))
		if res.StatusCode != http.StatusOK || !strings.Contains(res.Body, `data-next="`+html.EscapeString(tc.want)+`"`) {
			t.Errorf("fresh picker, next %q: the page does not carry %q", tc.next, tc.want)
		}
	}
}

// accountBrowser completes every sign-in as an account session with the
// Next and Return the sign-in use case would give.
type accountBrowser struct {
	fakeBrowser
	next, ret string
}

func (f *accountBrowser) Callback(context.Context, string, url.Values, string, authnapp.ClientMeta) (authnapp.BrowserSignIn, error) {
	return authnapp.BrowserSignIn{Kind: authnapp.SessionAccount, Secret: "account-session", Next: f.next, Return: f.ret}, nil
}

// TestHR353_AnAccountWithoutAnOrgGoesToTheConsoleNotThePicker (D94): after an
// account sign-in that found no org, the browser continues to the
// console's create-org page (or the console page the sign-in asked for),
// never to an empty picker; the picker itself sends such an account there
// too, and shows only when there is something to pick.
func TestHR353_AnAccountWithoutAnOrgGoesToTheConsoleNotThePicker(t *testing.T) {
	ab := &accountBrowser{}
	h, err := webhttp.New(ab, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.WithAccounts(&fakeAccounts{}, true)
	mux := http.NewServeMux()
	h.Mount(mux)
	mux.HandleFunc("GET /oauth2/callback/{provider}", h.Callback)

	continueTo := func(res result) string {
		const marker = `<a href="`
		i := strings.Index(res.Body, marker)
		if i < 0 {
			return ""
		}
		rest := res.Body[i+len(marker):]
		return html.UnescapeString(rest[:strings.IndexByte(rest, '"')])
	}
	for _, tc := range []struct{ next, ret, want string }{
		{authnapp.WelcomePath, authnapp.AccountPath, authnapp.WelcomePath},
		{"/app/settings/billing", "/app/settings/billing", "/app/settings/billing"},
		{"https://evil.example/app/x", "https://evil.example/app/x", authnapp.WelcomePath},
		{authnapp.OrgPickerPath, authnapp.AccountPath, authnapp.OrgPickerPath},
		{authnapp.OrgPickerPath, "/app/agents", authnapp.OrgPickerPath + "?next=%2Fapp%2Fagents"},
	} {
		ab.next, ab.ret = tc.next, tc.ret
		res := do(t, mux, get("/oauth2/callback/test?code=x&state=y"))
		if res.StatusCode != http.StatusOK || continueTo(res) != tc.want {
			t.Errorf("sign-in with next %q: %d, continues to %q, want %q", tc.next, res.StatusCode, continueTo(res), tc.want)
		}
	}

	noOrg := func(path string) *http.Request {
		r := get(path)
		r.AddCookie(&http.Cookie{Name: h.AccountCookieName(), Value: "no-org"})
		return r
	}
	for path, want := range map[string]string{
		authnapp.OrgPickerPath:                              authnapp.WelcomePath,
		authnapp.OrgPickerPath + "?next=%2Fapp%2Fagents":    "/app/agents",
		authnapp.OrgPickerPath + "?next=%2Fapprovals":       authnapp.WelcomePath,
		authnapp.OrgPickerPath + "?next=https%3A%2F%2Fevil": authnapp.WelcomePath,
	} {
		res := do(t, mux, noOrg(path))
		if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != want {
			t.Errorf("picker without an org, %s: %d %q, want %q", path, res.StatusCode, res.Header.Get("Location"), want)
		}
	}
}
