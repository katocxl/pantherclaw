// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webguard"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// extensionDeps are what the core hands to an extension. Plans, Accounts
// and BillingLinks are nil until the core provides them (G0 UI D20, D37).
func extensionDeps(cfg *Config, log *slog.Logger) extension.Deps {
	return extension.Deps{
		Log: log, Clock: clock.System{}, PublicURL: cfg.Auth.PublicURL, Deployment: cfg.deployment(),
	}
}

// validateExtension runs the extension's start-up check; its error stops
// the server (DEPLOYMENT_CONFIG).
func validateExtension(ext extension.Set, d extension.Deps) error {
	if ext.Validate == nil {
		return nil
	}
	if err := ext.Validate(d); err != nil {
		return fmt.Errorf("%sextension: %w", errDeploymentConfig, err)
	}
	return nil
}

// browserSessions are the session cookie rules the Connect API and the
// live stream share with the pages (G0 UI D11).
func browserSessions(cfg *Config, pool *db.Pool, idps []authnapp.IdP, log *slog.Logger) (*webguard.Sessions, error) {
	return webguard.NewSessions(authnapp.NewBrowser(pool, cfg.Auth.PublicURL, idps, clock.System{}, log), cfg.Auth.PublicURL)
}

// mountConsole serves the extension's console at /app/ with the console
// CSP, and redirects / to it (HR-340). Without a console nothing is
// mounted and / stays unanswered.
func mountConsole(mux *http.ServeMux, ext extension.Set) error {
	if ext.Console == nil {
		return nil
	}
	c, err := webhttp.NewConsole(ext.Console)
	if err != nil {
		return err
	}
	c.Mount(mux)
	return nil
}

// errExtensionRoute reports an extension route the server refuses at
// start-up (HR-341).
var errExtensionRoute = errors.New("server: extension route refused")

// wildcard matches one ServeMux wildcard segment.
var wildcard = regexp.MustCompile(`\{[^}]*\}`)

// consolePattern is the console's own subtree (D10). It leaves /app/ext/
// to extensions, so an extension route under /app/ext/ never conflicts
// with it.
const consolePattern = "GET " + webhttp.ConsoleRoot

// Limits of AuthNone extension routes, which have no session to bound
// them: a request body cap and a per-client rate (D48). A handler may cap
// its body lower.
const (
	extBodyLimit = 1 << 20
	extRateLimit = 600 // per client address per minute
)

// mountExtension mounts the extension's routes after every core route:
// each must be under /v1/ext/ or /app/ext/ and must not reach a core
// route (HR-341); session routes go through the page foundation's session
// and CSRF checks, and their handler reads the caller with
// extension.PrincipalFrom; AuthNone routes get a body cap and a per-client
// rate limit.
func mountExtension(mux *http.ServeMux, ext extension.Set, d extension.Deps, web *webhttp.Handler,
	clientIP httpx.ClientIPFunc,
) error {
	if ext.Mount == nil {
		return nil
	}
	routes, err := ext.Mount(d)
	if err != nil {
		return fmt.Errorf("%w: %w", errExtensionRoute, err)
	}
	// Check every route against the core routes before mounting any.
	for _, r := range routes {
		if err := extension.ValidateRoute(r); err != nil {
			return fmt.Errorf("%w: %w", errExtensionRoute, err)
		}
		if r.Auth != extension.AuthNone && web == nil {
			return fmt.Errorf("%w: %q needs browser sessions, which this server does not serve", errExtensionRoute, r.Pattern)
		}
		if p := coreRouteFor(mux, r.Pattern); p != "" {
			return fmt.Errorf("%w: %q reaches the core route %q", errExtensionRoute, r.Pattern, p)
		}
	}
	limiter := httpx.NewLimiter(extRateLimit, time.Minute, nil).WithClientIP(clientIP)
	for _, r := range routes {
		if err := mountRoute(mux, r, web, limiter, d.Authz != nil); err != nil {
			return err
		}
	}
	return nil
}

// coreRouteFor returns the pattern of the core route mux already has for
// a request to pattern (wildcards filled in), or "". The console's subtree
// does not count: it reserves /app/ext/ for extensions.
func coreRouteFor(mux *http.ServeMux, pattern string) string {
	method, path, err := extension.SplitPattern(pattern)
	if err != nil {
		return ""
	}
	if method == "" {
		method = http.MethodGet
	}
	path = wildcard.ReplaceAllStringFunc(path, func(w string) string {
		if w == "{$}" {
			return ""
		}
		return "x"
	})
	u, err := url.Parse("http://ext.invalid" + path)
	if err != nil {
		return ""
	}
	// A probe the mux only matches, never sent or served.
	req := &http.Request{Method: method, URL: u, Host: u.Host, Header: http.Header{}}
	if _, p := mux.Handler(req); p != consolePattern {
		return p
	}
	return ""
}

// mountRoute mounts one checked route; a conflict with another extension
// route is a start-up error, not a panic.
func mountRoute(mux *http.ServeMux, r extension.Route, web *webhttp.Handler, limiter *httpx.Limiter, authz bool) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%w: %q: %v", errExtensionRoute, r.Pattern, p)
		}
	}()
	h := r.Handler
	switch r.Auth {
	case extension.AuthNone:
		mux.Handle(r.Pattern, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !limiter.AllowRequest(req) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			req.Body = http.MaxBytesReader(w, req.Body, extBodyLimit)
			h.ServeHTTP(w, req)
		}))
	case extension.AuthSession, extension.AuthSessionCSRF:
		web.SessionRoute(mux, r.Pattern, r.Auth == extension.AuthSessionCSRF,
			func(w http.ResponseWriter, req *http.Request, s authnapp.BrowserSession) {
				if !authz {
					// Without the core's permission check no session route
					// may run (G0 UI D70).
					web.JSONError(w, http.StatusServiceUnavailable, "unavailable")
					return
				}
				p, err := principalOf(req, web, s)
				if err != nil {
					web.InternalError(w, req, err)
					return
				}
				// The caller is in the context for Deps.Authz, as for a Connect
				// procedure; the principal for the extension.
				ctx := tapp.WithCaller(extension.WithPrincipal(req.Context(), p), s.Caller)
				h.ServeHTTP(w, req.WithContext(ctx))
			})
	default:
		return fmt.Errorf("%w: %q: unknown auth mode", errExtensionRoute, r.Pattern)
	}
	return nil
}

// principalOf is the extension view of an org browser session, with the
// person's email. AccountID is set for account sessions (hosted accounts,
// G0 UI D8).
func principalOf(r *http.Request, web *webhttp.Handler, s authnapp.BrowserSession) (extension.Principal, error) {
	prof, err := web.SessionProfile(r.Context(), s)
	if err != nil {
		return extension.Principal{}, err
	}
	return extension.Principal{OrgID: s.Org.String(), UserID: s.Principal.ID.String(), Email: prof.Email}, nil
}
