// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// extensionDeps are what the core hands to an extension. Plans and
// Accounts are nil until the core provides them (G0 UI D20).
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

// errExtensionRoute reports an extension route the server refuses at
// start-up (HR-341).
var errExtensionRoute = errors.New("server: extension route refused")

// wildcard matches one ServeMux wildcard segment.
var wildcard = regexp.MustCompile(`\{[^}]*\}`)

// mountExtension mounts the extension's routes after every core route:
// each must be under /v1/ext/ or /app/ext/ and must not reach a core
// route (HR-341); session routes go through the page foundation's session
// and CSRF checks, and their handler reads the caller with
// extension.PrincipalFrom.
func mountExtension(mux *http.ServeMux, ext extension.Set, d extension.Deps, web *webhttp.Handler) error {
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
	for _, r := range routes {
		if err := mountRoute(mux, r, web); err != nil {
			return err
		}
	}
	return nil
}

// coreRouteFor returns the pattern of the route mux already has for a
// request to pattern (wildcards filled in), or "".
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
	req, err := http.NewRequest(method, "http://ext.invalid"+path, nil) //nolint:noctx // a probe, never sent
	if err != nil {
		return ""
	}
	_, p := mux.Handler(req)
	return p
}

// mountRoute mounts one checked route; a conflict with another extension
// route is a start-up error, not a panic.
func mountRoute(mux *http.ServeMux, r extension.Route, web *webhttp.Handler) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%w: %q: %v", errExtensionRoute, r.Pattern, p)
		}
	}()
	switch r.Auth {
	case extension.AuthNone:
		mux.Handle(r.Pattern, r.Handler)
	case extension.AuthSession, extension.AuthSessionCSRF:
		h := r.Handler
		web.SessionRoute(mux, r.Pattern, r.Auth == extension.AuthSessionCSRF,
			func(w http.ResponseWriter, req *http.Request, s authnapp.BrowserSession) {
				h.ServeHTTP(w, req.WithContext(extension.WithPrincipal(req.Context(), principalOf(s))))
			})
	default:
		return fmt.Errorf("%w: %q: unknown auth mode", errExtensionRoute, r.Pattern)
	}
	return nil
}

// principalOf is the extension view of an org browser session. Account
// sessions and the email arrive with hosted accounts (G0 UI D8).
func principalOf(s authnapp.BrowserSession) extension.Principal {
	return extension.Principal{OrgID: s.Org.String(), UserID: s.Principal.ID.String()}
}
