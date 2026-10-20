// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// fakeBrowser authenticates the cookie "good" as one org user.
type fakeBrowser struct {
	webhttp.Browser
	org  ids.OrgID
	user ids.UUID
}

func (f fakeBrowser) Authenticate(_ context.Context, cookie string) (authnapp.BrowserSession, error) {
	if cookie != "good" {
		return authnapp.BrowserSession{}, authnapp.ErrUnauthenticated
	}
	return authnapp.BrowserSession{Caller: tapp.Caller{
		Subject:    td.Subject{Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.user}},
		Credential: tapp.CredBrowserSession,
	}}, nil
}

func (f fakeBrowser) Profile(_ context.Context, s authnapp.BrowserSession) (authnapp.Profile, error) {
	return authnapp.Profile{Org: s.Org, Email: "ada@example.com"}, nil
}

const uiWebOrigin = "http://127.0.0.1:8080"

func uiWebHandler(t *testing.T) (*webhttp.Handler, fakeBrowser) {
	t.Helper()
	fb := fakeBrowser{org: ids.New[ids.Org](), user: ids.NewV7()}
	h, err := webhttp.New(fb, uiWebOrigin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h, fb
}

func routes(rs ...extension.Route) extension.Set {
	return extension.Set{Mount: func(extension.Deps) ([]extension.Route, error) { return rs, nil }}
}

// coreMux stands in for the core routes, with the console's subtree.
func coreMux() *http.ServeMux {
	mux := http.NewServeMux()
	nop := func(http.ResponseWriter, *http.Request) {}
	mux.HandleFunc("GET /login", nop)
	mux.HandleFunc("/pantherclaw.v1.AccessService/", nop)
	mux.HandleFunc("POST /v1/ext/core-owned", nop)
	mux.HandleFunc(consolePattern, nop)
	return mux
}

func mountTest(mux *http.ServeMux, set extension.Set, web *webhttp.Handler) error {
	return mountExtension(mux, set, extension.Deps{}, web, nil)
}

// TestHR341_ExtensionRoutesRefused: routes outside the prefixes, routes
// that reach a core route, conflicting routes, session routes that skip
// the CSRF check and session routes without browser sessions are start-up
// errors, never panics.
func TestHR341_ExtensionRoutesRefused(t *testing.T) {
	web, _ := uiWebHandler(t)
	ok := http.NotFoundHandler()
	for name, set := range map[string]extension.Set{
		"core path":     routes(extension.Route{Pattern: "GET /login", Handler: ok}),
		"rpc path":      routes(extension.Route{Pattern: "/pantherclaw.v1.AccessService/WhoAmI", Handler: ok}),
		"root":          routes(extension.Route{Pattern: "/", Handler: ok}),
		"console root":  routes(extension.Route{Pattern: "GET /app/", Handler: ok}),
		"console page":  routes(extension.Route{Pattern: "GET /app/agents", Handler: ok}),
		"core shadowed": routes(extension.Route{Pattern: "POST /v1/ext/core-owned", Handler: ok}),
		"trailing dot":  routes(extension.Route{Pattern: "GET /v1/ext/a/.", Handler: ok}),
		"duplicate": routes(extension.Route{Pattern: "POST /v1/ext/a", Handler: ok},
			extension.Route{Pattern: "POST /v1/ext/a", Handler: ok}),
		"no handler":           routes(extension.Route{Pattern: "POST /v1/ext/a"}),
		"session POST no CSRF": routes(extension.Route{Pattern: "POST /app/ext/a", Auth: extension.AuthSession, Handler: ok}),
		"session any method":   routes(extension.Route{Pattern: "/app/ext/a", Auth: extension.AuthSession, Handler: ok}),
		"mount error": {Mount: func(extension.Deps) ([]extension.Route, error) {
			return nil, errors.New("boom")
		}},
	} {
		if err := mountTest(coreMux(), set, web); !errors.Is(err, errExtensionRoute) {
			t.Errorf("%s: err = %v, want errExtensionRoute", name, err)
		}
	}
	err := mountTest(coreMux(), routes(extension.Route{Pattern: "GET /app/ext/a", Auth: extension.AuthSession, Handler: ok}), nil)
	if !errors.Is(err, errExtensionRoute) {
		t.Errorf("session route without web pages: err = %v", err)
	}
	if err := mountTest(coreMux(), extension.Set{}, nil); err != nil {
		t.Errorf("empty set: %v", err)
	}
	// Nothing is mounted when one route is refused.
	mux := coreMux()
	_ = mountTest(mux, routes(extension.Route{Pattern: "POST /v1/ext/fine", Handler: ok},
		extension.Route{Pattern: "GET /login", Handler: ok}), web)
	if p := coreRouteFor(mux, "POST /v1/ext/fine"); p != "" {
		t.Errorf("route mounted although another was refused: %q", p)
	}
}

// TestHR341_ConsoleLeavesAppExtToExtensions: the console's /app/ subtree
// is not a conflict for /app/ext/ routes, and they win over it.
func TestHR341_ConsoleLeavesAppExtToExtensions(t *testing.T) {
	web, _ := uiWebHandler(t)
	mux := coreMux()
	hit := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	if err := mountTest(mux, routes(
		extension.Route{Pattern: "GET /app/ext/billing/plans", Auth: extension.AuthNone, Handler: hit},
		extension.Route{Pattern: "GET /app/ext/x/{id}", Auth: extension.AuthNone, Handler: hit},
	), web); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/app/ext/billing/plans", "/app/ext/x/1"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, uiWebOrigin+p, nil))
		if rec.Code != http.StatusTeapot {
			t.Errorf("%s = %d, want the extension route", p, rec.Code)
		}
	}
}

// TestExtensionRoutesServe: an AuthNone route serves anyone within its
// body cap; session routes need the session cookie (and AuthSessionCSRF
// the CSRF check) and see the caller, with the email, through
// extension.PrincipalFrom.
func TestExtensionRoutesServe(t *testing.T) {
	web, fb := uiWebHandler(t)
	var got extension.Principal
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := extension.PrincipalFrom(r.Context())
		got = p
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux := coreMux()
	err := mountTest(mux, routes(
		extension.Route{Pattern: "POST /v1/ext/hook", Auth: extension.AuthNone, Handler: echo},
		extension.Route{Pattern: "GET /app/ext/plans", Auth: extension.AuthSession, Handler: echo},
		extension.Route{Pattern: "POST /app/ext/checkout", Auth: extension.AuthSessionCSRF, Handler: echo},
	), web)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, cookie string, csrf bool, body string) int {
		got = extension.Principal{}
		req := httptest.NewRequest(method, uiWebOrigin+path, strings.NewReader(body))
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "pc_session", Value: cookie})
		}
		if csrf {
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set(webhttp.CSRFHeader, "1")
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := do(http.MethodPost, "/v1/ext/hook", "", false, "{}"); c != http.StatusNoContent {
		t.Errorf("AuthNone = %d", c)
	}
	if c := do(http.MethodPost, "/v1/ext/hook", "", false, strings.Repeat("x", extBodyLimit+1)); c != http.StatusRequestEntityTooLarge {
		t.Errorf("AuthNone over the body cap = %d", c)
	}
	if c := do(http.MethodGet, "/app/ext/plans", "", false, ""); c != http.StatusUnauthorized {
		t.Errorf("session route without a cookie = %d", c)
	}
	if c := do(http.MethodGet, "/app/ext/plans", "forged", false, ""); c != http.StatusUnauthorized {
		t.Errorf("session route with a bad cookie = %d", c)
	}
	if c := do(http.MethodGet, "/app/ext/plans", "good", false, ""); c != http.StatusNoContent {
		t.Fatalf("session route = %d", c)
	}
	want := extension.Principal{OrgID: fb.org.String(), UserID: fb.user.String(), Email: "ada@example.com"}
	if got != want {
		t.Errorf("principal = %+v, want %+v", got, want)
	}
	if c := do(http.MethodPost, "/app/ext/checkout", "good", false, "{}"); c != http.StatusForbidden {
		t.Errorf("CSRF route without the check = %d", c)
	}
	if c := do(http.MethodPost, "/app/ext/checkout", "good", true, "{}"); c != http.StatusNoContent || got != want {
		t.Errorf("CSRF route = %d, %+v", c, got)
	}
}

// TestExtensionAuthNoneRateLimit: AuthNone routes are rate limited per
// client address.
func TestExtensionAuthNoneRateLimit(t *testing.T) {
	mux := coreMux()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	if err := mountTest(mux, routes(extension.Route{Pattern: "POST /v1/ext/hook", Handler: ok}), nil); err != nil {
		t.Fatal(err)
	}
	send := func(remote string) int {
		req := httptest.NewRequest(http.MethodPost, uiWebOrigin+"/v1/ext/hook", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := range extRateLimit {
		if c := send("192.0.2.1:1000"); c != http.StatusNoContent {
			t.Fatalf("request %d = %d", i, c)
		}
	}
	if c := send("192.0.2.1:1000"); c != http.StatusTooManyRequests {
		t.Fatalf("over the limit = %d", c)
	}
	if c := send("192.0.2.2:1000"); c != http.StatusNoContent {
		t.Fatalf("another client = %d", c)
	}
}
