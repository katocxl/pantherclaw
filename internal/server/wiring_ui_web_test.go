// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
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

func uiWebConfig() Config {
	c := DefaultConfig()
	c.DB.AppPasswordFile = "pw"
	c.KEKFiles = []string{"kek"}
	return c
}

// TestHR346_DeploymentConfig: deployment defaults to development and
// accepts only development, staging or production; anything else stops
// start-up with DEPLOYMENT_CONFIG.
func TestHR346_DeploymentConfig(t *testing.T) {
	c := uiWebConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("default configuration refused: %v", err)
	}
	if c.deployment() != extension.DeploymentDevelopment {
		t.Fatalf("default deployment = %q", c.deployment())
	}
	for _, d := range []string{"development", "staging", "production"} {
		c := uiWebConfig()
		c.Deployment = d
		if err := c.Validate(); err != nil {
			t.Errorf("deployment %q refused: %v", d, err)
		}
	}
	for _, d := range []string{"", "prod", "Production", "dev", "test"} {
		c := uiWebConfig()
		c.Deployment = d
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "DEPLOYMENT_CONFIG") {
			t.Errorf("deployment %q: err = %v, want DEPLOYMENT_CONFIG", d, err)
		}
	}
}

// TestHR346_ExtensionValidateStopsStartup: an extension's Validate error
// is a DEPLOYMENT_CONFIG start-up error, and it sees the deployment.
func TestHR346_ExtensionValidateStopsStartup(t *testing.T) {
	c := uiWebConfig()
	c.Deployment = "production"
	d := extensionDeps(&c, nil)
	if d.Deployment != extension.DeploymentProduction || d.PublicURL != c.Auth.PublicURL || d.Clock == nil {
		t.Fatalf("deps = %+v", d)
	}
	if d.Plans != nil || d.Accounts != nil {
		t.Fatal("plans and accounts are not provided yet")
	}
	if err := validateExtension(extension.Set{}, d); err != nil {
		t.Fatal(err)
	}
	refuse := extension.Set{Validate: func(d extension.Deps) error {
		if d.Deployment == extension.DeploymentProduction {
			return errors.New("fake billing in production")
		}
		return nil
	}}
	err := validateExtension(refuse, d)
	if err == nil || !strings.HasPrefix(err.Error(), "DEPLOYMENT_CONFIG: ") {
		t.Fatalf("err = %v", err)
	}
	// RunWith checks the extension before it touches the database.
	c.DB.AppPasswordFile = t.TempDir() + "/missing"
	if err := RunWith(context.Background(), &c, refuse); err == nil || !strings.Contains(err.Error(), "DEPLOYMENT_CONFIG") {
		t.Fatalf("RunWith = %v", err)
	}
}

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

// coreMux stands in for the core routes.
func coreMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("/pantherclaw.v1.AccessService/", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("POST /v1/ext/core-owned", func(http.ResponseWriter, *http.Request) {})
	return mux
}

// TestHR341_ExtensionRoutesRefused: routes outside the prefixes, routes
// that reach a core route, conflicting routes and session routes without
// browser sessions are start-up errors, never panics.
func TestHR341_ExtensionRoutesRefused(t *testing.T) {
	web, _ := uiWebHandler(t)
	ok := http.NotFoundHandler()
	for name, set := range map[string]extension.Set{
		"core path":     routes(extension.Route{Pattern: "GET /login", Handler: ok}),
		"rpc path":      routes(extension.Route{Pattern: "/pantherclaw.v1.AccessService/WhoAmI", Handler: ok}),
		"root":          routes(extension.Route{Pattern: "/", Handler: ok}),
		"console root":  routes(extension.Route{Pattern: "GET /app/", Handler: ok}),
		"core shadowed": routes(extension.Route{Pattern: "POST /v1/ext/core-owned", Handler: ok}),
		"duplicate": routes(extension.Route{Pattern: "POST /v1/ext/a", Handler: ok},
			extension.Route{Pattern: "POST /v1/ext/a", Handler: ok}),
		"no handler": routes(extension.Route{Pattern: "POST /v1/ext/a"}),
		"mount error": {Mount: func(extension.Deps) ([]extension.Route, error) {
			return nil, errors.New("boom")
		}},
	} {
		err := mountExtension(coreMux(), set, extension.Deps{}, web)
		if !errors.Is(err, errExtensionRoute) {
			t.Errorf("%s: err = %v, want errExtensionRoute", name, err)
		}
	}
	err := mountExtension(coreMux(), routes(extension.Route{Pattern: "GET /app/ext/a", Auth: extension.AuthSession, Handler: ok}),
		extension.Deps{}, nil)
	if !errors.Is(err, errExtensionRoute) {
		t.Errorf("session route without web pages: err = %v", err)
	}
	if err := mountExtension(coreMux(), extension.Set{}, extension.Deps{}, nil); err != nil {
		t.Errorf("empty set: %v", err)
	}
	// Nothing is mounted when one route is refused.
	mux := coreMux()
	_ = mountExtension(mux, routes(extension.Route{Pattern: "POST /v1/ext/fine", Handler: ok},
		extension.Route{Pattern: "GET /login", Handler: ok}), extension.Deps{}, web)
	if p := coreRouteFor(mux, "POST /v1/ext/fine"); p != "" {
		t.Errorf("route mounted although another was refused: %q", p)
	}
}

// TestExtensionRoutesServe: an AuthNone route serves anyone; session
// routes need the session cookie (and AuthSessionCSRF the CSRF check) and
// see the caller through extension.PrincipalFrom.
func TestExtensionRoutesServe(t *testing.T) {
	web, fb := uiWebHandler(t)
	var got extension.Principal
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := extension.PrincipalFrom(r.Context())
		got = p
		w.WriteHeader(http.StatusNoContent)
	})
	mux := coreMux()
	err := mountExtension(mux, routes(
		extension.Route{Pattern: "POST /v1/ext/hook", Auth: extension.AuthNone, Handler: echo},
		extension.Route{Pattern: "GET /app/ext/plans", Auth: extension.AuthSession, Handler: echo},
		extension.Route{Pattern: "POST /app/ext/checkout", Auth: extension.AuthSessionCSRF, Handler: echo},
	), extension.Deps{}, web)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, cookie string, csrf bool) int {
		got = extension.Principal{}
		req := httptest.NewRequest(method, uiWebOrigin+path, strings.NewReader("{}"))
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
	if c := do(http.MethodPost, "/v1/ext/hook", "", false); c != http.StatusNoContent {
		t.Errorf("AuthNone = %d", c)
	}
	if c := do(http.MethodGet, "/app/ext/plans", "", false); c != http.StatusUnauthorized {
		t.Errorf("session route without a cookie = %d", c)
	}
	if c := do(http.MethodGet, "/app/ext/plans", "forged", false); c != http.StatusUnauthorized {
		t.Errorf("session route with a bad cookie = %d", c)
	}
	if c := do(http.MethodGet, "/app/ext/plans", "good", false); c != http.StatusNoContent {
		t.Fatalf("session route = %d", c)
	}
	want := extension.Principal{OrgID: fb.org.String(), UserID: fb.user.String()}
	if got != want {
		t.Errorf("principal = %+v, want %+v", got, want)
	}
	if c := do(http.MethodPost, "/app/ext/checkout", "good", false); c != http.StatusForbidden {
		t.Errorf("CSRF route without the check = %d", c)
	}
	if c := do(http.MethodPost, "/app/ext/checkout", "good", true); c != http.StatusNoContent || got != want {
		t.Errorf("CSRF route = %d, %+v", c, got)
	}
}
