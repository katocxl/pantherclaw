// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const origin = "https://pc.example.test"

var testOrg = ids.New[ids.Org]()

// fakeBrowser accepts the cookie "good" (and "rotate", which it rotates to
// "rotated"); it records whether a state-changing use case ran.
type fakeBrowser struct {
	revoked, loggedOut bool
}

func (f *fakeBrowser) Start(context.Context, authnapp.BrowserStart) (authnapp.Redirect, error) {
	return authnapp.Redirect{URL: "https://idp.example.test/authorize?x=1", Binding: "bind"}, nil
}

func (f *fakeBrowser) Callback(_ context.Context, _ string, params url.Values, binding string, _ authnapp.ClientMeta) (authnapp.BrowserSignIn, error) {
	if binding != "bind" {
		return authnapp.BrowserSignIn{Reason: "LOGIN_FAILED"}, nil
	}
	return authnapp.BrowserSignIn{Org: testOrg, Secret: "new-session", Next: params.Get("next")}, nil
}

func (f *fakeBrowser) Authenticate(_ context.Context, cookie string) (authnapp.BrowserSession, error) {
	s := authnapp.BrowserSession{
		Caller: tapp.Caller{
			Subject:    td.Subject{Org: testOrg, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}},
			Credential: authnapp.CredBrowserSession,
		},
		ID: ids.NewV7(),
	}
	s.Session = s.ID
	switch cookie {
	case "good":
		return s, nil
	case "rotate":
		s.Rotated = "rotated"
		return s, nil
	case "responder": // containment_test.go
		s.Principal.ID = responderID
		s.Bindings = []td.Binding{{Role: td.RoleEmergency, Scope: td.Scope{Type: td.ScopeOrg, ID: testOrg.UUID()}}}
		s.StepUpCredential, s.StepUpAt = responderKey, steppedUpAt
		return s, nil
	case "reader":
		s.Bindings = []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: testOrg.UUID()}}}
		return s, nil
	}
	return authnapp.BrowserSession{}, authnapp.ErrUnauthenticated
}

func (f *fakeBrowser) Logout(context.Context, string) error { f.loggedOut = true; return nil }

func (f *fakeBrowser) Profile(_ context.Context, s authnapp.BrowserSession) (authnapp.Profile, error) {
	return authnapp.Profile{Org: s.Org, User: s.User(), Email: "a@example.test", Name: `<script>alert(1)</script>`}, nil
}

func (f *fakeBrowser) ListSessions(context.Context, authnapp.BrowserSession) ([]authnapp.SessionInfo, error) {
	return []authnapp.SessionInfo{{ID: ids.NewV7(), UserAgent: `"><img src=x onerror=alert(1)>`, Live: true}}, nil
}

func (f *fakeBrowser) RevokeSession(context.Context, authnapp.BrowserSession, ids.UUID) error {
	f.revoked = true
	return nil
}

func newHandler(t *testing.T, publicURL string) (*webhttp.Handler, *fakeBrowser, http.Handler) {
	t.Helper()
	fb := &fakeBrowser{}
	h, err := webhttp.New(fb, publicURL, nil, nil)
	if err == nil {
		h.WithKeys(&fakeKeys{}).WithContainment(&fakeContainment{}).WithApprovals(&fakeApprovals{}, &fakeBindings{})
	}
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h.Mount(mux)
	mux.HandleFunc("GET /oauth2/callback/{provider}", h.Callback)
	return h, fb, mux
}

// result is a response with its body read.
type result struct {
	StatusCode int
	Header     http.Header
	Body       string
	cookies    []*http.Cookie
}

func (r result) Cookies() []*http.Cookie { return r.cookies }

func do(t *testing.T, mux http.Handler, r *http.Request) result {
	t.Helper()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	resp := w.Result()
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return result{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(b), cookies: resp.Cookies()}
}

// post builds a request that passes the CSRF check; tests then break one part.
func post(path string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, origin+path, strings.NewReader("{}"))
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Origin", origin)
	r.Header.Set(webhttp.CSRFHeader, "1")
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	return r
}

func TestHR151_StateChangingRequestsNeedTheCSRFProof(t *testing.T) {
	h, fb, mux := newHandler(t, origin)
	path := "/account/sessions/" + ids.NewV7().String() + "/revoke"
	for _, tc := range []struct {
		name   string
		break_ func(*http.Request)
	}{
		{"no PC-CSRF header", func(r *http.Request) { r.Header.Del(webhttp.CSRFHeader) }},
		{"wrong PC-CSRF value", func(r *http.Request) { r.Header.Set(webhttp.CSRFHeader, "true") }},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"same-site (another subdomain)", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
		{"typed URL", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "none") }},
		{"same-origin with a foreign Origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }},
		{"no Fetch Metadata and a foreign Origin", func(r *http.Request) {
			r.Header.Del("Sec-Fetch-Site")
			r.Header.Set("Origin", "https://evil.example")
		}},
		{"no Fetch Metadata and no Origin", func(r *http.Request) { r.Header.Del("Sec-Fetch-Site"); r.Header.Del("Origin") }},
		{"form content type", func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }},
		{"text content type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
	} {
		r := post(path)
		tc.break_(r)
		resp := do(t, mux, r)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(resp.Body, "csrf") {
			t.Errorf("%s: %d %s, want 403 csrf", tc.name, resp.StatusCode, resp.Body)
		}
	}
	if fb.revoked {
		t.Fatal("a refused request reached the use case")
	}
	// The valid request, and one from a browser without Fetch Metadata but
	// with the right Origin, go through.
	if resp := do(t, mux, post(path)); resp.StatusCode != http.StatusOK || !fb.revoked {
		t.Fatalf("valid request: %d", resp.StatusCode)
	}
	r := post(path)
	r.Header.Del("Sec-Fetch-Site")
	if resp := do(t, mux, r); resp.StatusCode != http.StatusOK {
		t.Fatalf("Origin without Fetch Metadata: %d", resp.StatusCode)
	}
	// Without a session the request is refused after the CSRF check.
	r = post(path)
	r.Header.Del("Cookie")
	if resp := do(t, mux, r); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session: %d", resp.StatusCode)
	}
	_ = h
}

func TestHR151_RouteTable(t *testing.T) {
	h, _, mux := newHandler(t, origin)
	for _, rt := range h.Routes() {
		private := strings.HasPrefix(rt.Path, authnapp.AccountPath) || strings.HasPrefix(rt.Path, authnapp.ContainmentPath) ||
			strings.HasPrefix(rt.Path, authnapp.ApprovalsPath) ||
			rt.Path == authnapp.LogoutPath
		if private != rt.Session {
			t.Errorf("%s %s: session=%v, want %v", rt.Method, rt.Path, rt.Session, private)
		}
		if (rt.Method != http.MethodGet) != rt.CSRF {
			t.Errorf("%s %s: csrf=%v", rt.Method, rt.Path, rt.CSRF)
		}
		if rt.Method != http.MethodGet && !rt.Session {
			t.Errorf("%s %s changes state without a session", rt.Method, rt.Path)
		}
	}
	// The emergency-stop page and its four actions (G0 M6).
	for _, want := range []webhttp.Route{
		{Method: http.MethodGet, Path: "/containment", Session: true},
		{Method: http.MethodPost, Path: "/containment/kill-switch/engage", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/containment/kill-switch/restore", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/containment/kill-switch/restore/{id}/confirm", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/containment/kill-switch/restore/{id}/cancel", Session: true, CSRF: true},
		// The approval page (G0 M5 part 2).
		{Method: http.MethodGet, Path: "/approvals", Session: true},
		{Method: http.MethodGet, Path: "/approvals/{id}", Session: true},
		{Method: http.MethodPost, Path: "/approvals/batch-options", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/approvals/batch", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/approvals/{id}/approve-options", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/approvals/{id}/approve", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/approvals/{id}/decline", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/approvals/{id}/evidence-request", Session: true, CSRF: true},
		{Method: http.MethodPost, Path: "/approvals/{id}/narrower", Session: true, CSRF: true},
	} {
		if !slices.Contains(h.Routes(), want) {
			t.Errorf("route %+v is not mounted", want)
		}
	}
	// A state-changing method on a GET route is not served.
	r := post(authnapp.AccountPath)
	if resp := do(t, mux, r); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST %s: %d, want 405", authnapp.AccountPath, resp.StatusCode)
	}
}

func TestHR151_EveryResponseCarriesThePagePolicy(t *testing.T) {
	_, _, mux := newHandler(t, origin)
	account := httptest.NewRequest(http.MethodGet, origin+authnapp.AccountPath, nil)
	account.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	for _, r := range []*http.Request{
		account,
		httptest.NewRequest(http.MethodGet, origin+authnapp.AccountPath+"?org="+testOrg.String(), nil), // redirect to sign-in
		httptest.NewRequest(http.MethodGet, origin+"/login?org="+testOrg.String(), nil),
		httptest.NewRequest(http.MethodGet, origin+"/signed-out", nil),
		httptest.NewRequest(http.MethodGet, origin+"/static/account.js", nil),
		httptest.NewRequest(http.MethodGet, origin+"/static/nothing.js", nil),
		post(authnapp.LogoutPath),
	} {
		resp := do(t, mux, r)
		hd := resp.Header
		if hd.Get("Content-Security-Policy") != webhttp.PageCSP || hd.Get("X-Frame-Options") != "DENY" ||
			hd.Get("Cache-Control") != "no-store" || hd.Get("X-Content-Type-Options") != "nosniff" ||
			hd.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("%s %s: headers %v", r.Method, r.URL.Path, hd)
		}
	}
	if !strings.Contains(webhttp.PageCSP, "require-trusted-types-for 'script'") || strings.Contains(webhttp.PageCSP, "unsafe") {
		t.Fatalf("CSP %q", webhttp.PageCSP)
	}
}

func TestHR151_PagesEscapeUntrustedText(t *testing.T) {
	_, _, mux := newHandler(t, origin)
	r := httptest.NewRequest(http.MethodGet, origin+authnapp.AccountPath, nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "good"})
	resp := do(t, mux, r)
	body := resp.Body
	if resp.StatusCode != http.StatusOK || strings.Contains(body, "<script>alert") || strings.Contains(body, "<img src=x") {
		t.Fatalf("account page: %d, unescaped text in %s", resp.StatusCode, body)
	}
	if strings.Count(body, "<script") != 1 || !strings.Contains(body, `<script src="/static/account.js"></script>`) {
		t.Fatal("the account page must load exactly one script, the static file")
	}
}

func TestHR150_CookiesAreHostOnlyStrictAndRotated(t *testing.T) {
	_, _, mux := newHandler(t, origin)
	// The binding cookie is Lax (it must survive the provider's redirect).
	resp := do(t, mux, httptest.NewRequest(http.MethodGet, origin+"/login?org="+testOrg.String(), nil))
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "https://idp.example.test/") {
		t.Fatalf("login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	c := resp.Cookies()
	if len(c) != 1 || c[0].Name != "__Host-pc_login" || !c[0].HttpOnly || !c[0].Secure || c[0].SameSite != http.SameSiteLaxMode || c[0].Path != "/" || c[0].Domain != "" {
		t.Fatalf("binding cookie %+v", c)
	}
	// The callback sets the session cookie: host-only, Secure, HttpOnly, Strict.
	r := httptest.NewRequest(http.MethodGet, origin+"/oauth2/callback/test?next=/account", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_login", Value: "bind"})
	resp = do(t, mux, r)
	body := resp.Body
	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-pc_session" {
			session = c
		}
	}
	if resp.StatusCode != http.StatusOK || session == nil || session.Value != "new-session" || !session.HttpOnly || !session.Secure ||
		session.SameSite != http.SameSiteStrictMode || session.Path != "/" || session.Domain != "" {
		t.Fatalf("callback: %d cookie %+v", resp.StatusCode, session)
	}
	if !strings.Contains(body, `content="0;url=/account"`) {
		t.Fatalf("continue page does not open /account from the same origin: %s", body)
	}
	// A callback without the binding cookie is refused and sets no session.
	resp = do(t, mux, httptest.NewRequest(http.MethodGet, origin+"/oauth2/callback/test", nil))
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-pc_session" && c.Value != "" {
			t.Fatal("a refused callback set a session")
		}
	}
	// A rotated session replaces the cookie on the same response.
	r = httptest.NewRequest(http.MethodGet, origin+authnapp.AccountPath, nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "rotate"})
	resp = do(t, mux, r)
	if cs := resp.Cookies(); resp.StatusCode != http.StatusOK || len(cs) != 1 || cs[0].Value != "rotated" || cs[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("rotation: %d %+v", resp.StatusCode, cs)
	}
	// A dead session cookie is cleared.
	r = httptest.NewRequest(http.MethodGet, origin+authnapp.AccountPath, nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "stolen"})
	resp = do(t, mux, r)
	if cs := resp.Cookies(); len(cs) != 1 || cs[0].MaxAge >= 0 {
		t.Fatalf("dead cookie not cleared: %+v", cs)
	}
}

func TestPlainCookieNamesOnlyForHTTPDevelopment(t *testing.T) {
	_, _, mux := newHandler(t, "http://localhost:8080")
	resp := do(t, mux, httptest.NewRequest(http.MethodGet, "http://localhost:8080/login?org="+testOrg.String(), nil))
	if c := resp.Cookies(); len(c) != 1 || c[0].Name != "pc_login" || c[0].Secure {
		t.Fatalf("development cookie %+v", c)
	}
	if _, err := webhttp.New(&fakeBrowser{}, "ftp://pc.example.test", nil, nil); err == nil {
		t.Fatal("a non-http public URL was accepted")
	}
}

func TestPagesWithoutSessionGoToSignIn(t *testing.T) {
	_, fb, mux := newHandler(t, origin)
	resp := do(t, mux, httptest.NewRequest(http.MethodGet, origin+authnapp.AccountPath+"?org="+testOrg.String(), nil))
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || loc.Path != authnapp.LoginPath || loc.Query().Get("org") != testOrg.String() ||
		loc.Query().Get("next") != authnapp.AccountPath {
		t.Fatalf("no session: %d %s", resp.StatusCode, loc)
	}
	resp = do(t, mux, httptest.NewRequest(http.MethodGet, origin+authnapp.AccountPath, nil))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no session and no org: %d", resp.StatusCode)
	}
	if resp := do(t, mux, post(authnapp.LogoutPath)); resp.StatusCode != http.StatusOK || !fb.loggedOut {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
}
