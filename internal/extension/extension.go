// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package extension is the point where a build of pantherclaw-server adds a
// web console and extra routes to the core server (ADR-0030). The public
// binary passes an empty Set, so self-hosted servers run as before; a
// private build passes its console and routes through the same entry point
// (servercli.Main).
//
// The package lives at internal/extension rather than under
// internal/platform because it names core domain concepts (plans,
// accounts). Ids are strings so the contract stays stable as the core's id
// types change.
package extension

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/clock"
)

// Deployment names the kind of deployment the server runs as (config
// `deployment`). Production refuses development-only seams at start-up.
type Deployment string

// Deployments.
const (
	DeploymentDevelopment Deployment = "development"
	DeploymentStaging     Deployment = "staging"
	DeploymentProduction  Deployment = "production"
)

// Valid reports whether d is one of the three deployments.
func (d Deployment) Valid() bool {
	switch d {
	case DeploymentDevelopment, DeploymentStaging, DeploymentProduction:
		return true
	}
	return false
}

// Set is what a build adds to the core server. The zero Set adds nothing.
type Set struct {
	// Console is the built console (index.html at its root); nil means no
	// console is served.
	Console fs.FS
	// Mount returns extra routes; it is called after the core wiring. Nil
	// means none.
	Mount func(Deps) ([]Route, error)
	// Validate is a start-up check; an error stops the server
	// (DEPLOYMENT_CONFIG). Nil means no check.
	Validate func(Deps) error
}

// RouteAuth is how an extension route authenticates its caller.
type RouteAuth int

// Route authentication modes.
const (
	// AuthNone: no authentication (for example a signed webhook).
	AuthNone RouteAuth = iota
	// AuthSession: a browser session is required; PrincipalFrom reports it.
	AuthSession
	// AuthSessionCSRF: a browser session and the CSRF check (same-origin
	// Fetch Metadata or Origin, PC-CSRF: 1, a JSON body).
	AuthSessionCSRF
)

// Route is one extension route. Pattern is an http.ServeMux pattern,
// optionally with a method ("POST /v1/ext/billing/webhook"); its path must
// start with "/v1/ext/" or "/app/ext/" (HR-341).
type Route struct {
	Pattern string
	Auth    RouteAuth
	Handler http.Handler
}

// Deps are what the core hands to Validate and Mount.
type Deps struct {
	Log        *slog.Logger
	Clock      clock.Clock
	PublicURL  string
	Deployment Deployment
	// Plans writes an org's plan; nil until the core provides it.
	Plans PlanWriter
	// Accounts reads hosted accounts; nil until the core provides it.
	Accounts AccountReader
}

// Principal is the browser-session caller of an AuthSession or
// AuthSessionCSRF route. OrgID is empty for account sessions.
type Principal struct {
	AccountID, OrgID, UserID, Email string
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p. Only the core's route wrapper (and
// tests) call it.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the authenticated caller of a session route.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// PlanWriter applies a plan snapshot to an org. It is idempotent by
// EventID, ignores snapshots older than the last applied EventAt, and
// audits every change.
type PlanWriter interface {
	ApplyPlan(ctx context.Context, orgID string, s PlanSnapshot) error
}

// PlanSnapshot is an org's plan as a billing provider reports it.
type PlanSnapshot struct {
	PlanID, Edition string
	Status          PlanStatus
	Limits          PlanLimits
	Features        []string
	PeriodEnd       time.Time
	EventID         string
	EventAt         time.Time
}

// PlanStatus is a plan's billing state. COMP and DEV are core-only and
// refused through PlanWriter.
type PlanStatus string

// Plan states a PlanWriter accepts.
const (
	PlanNone     PlanStatus = "NONE"
	PlanTrialing PlanStatus = "TRIALING"
	PlanActive   PlanStatus = "ACTIVE"
	PlanPastDue  PlanStatus = "PAST_DUE"
	PlanPaused   PlanStatus = "PAUSED"
	PlanCanceled PlanStatus = "CANCELED"
	PlanLapsed   PlanStatus = "LAPSED"
)

// Valid reports whether s is a state a PlanWriter accepts.
func (s PlanStatus) Valid() bool {
	switch s {
	case PlanNone, PlanTrialing, PlanActive, PlanPastDue, PlanPaused, PlanCanceled, PlanLapsed:
		return true
	}
	return false
}

// PlanLimits are a plan's limits; 0 means unlimited.
type PlanLimits struct {
	MaxAgents, MaxEnvironments, RetentionDays, InstanceAllowance, MaxMembers int
}

// AccountReader reads hosted accounts.
type AccountReader interface {
	Account(ctx context.Context, accountID string) (Account, error)
}

// Account is a hosted account.
type Account struct {
	ID, Email     string
	EmailVerified bool
	DisplayName   string
}

// Route path prefixes (HR-341).
const (
	APIPrefix     = "/v1/ext/"
	ConsolePrefix = "/app/ext/"
)

// ErrRoute is returned for an extension route the core refuses.
var ErrRoute = errors.New("extension: route refused")

var routeMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true,
}

// SplitPattern returns the method (empty for any) and path of a route
// pattern, refusing patterns outside the extension prefixes or with
// anything but a plain path (HR-341): no host, no "..", "//", backslash,
// percent or query, and nothing but letters, digits, "-", "_", ".", "/"
// and ServeMux wildcards.
func SplitPattern(pattern string) (method, path string, err error) {
	path = pattern
	if m, p, ok := strings.Cut(pattern, " "); ok {
		if !routeMethods[m] {
			return "", "", fmt.Errorf("%w: %q: unknown method", ErrRoute, pattern)
		}
		method, path = m, p
	}
	if !strings.HasPrefix(path, APIPrefix) && !strings.HasPrefix(path, ConsolePrefix) {
		return "", "", fmt.Errorf("%w: %q: path must start with %s or %s", ErrRoute, pattern, APIPrefix, ConsolePrefix)
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(path, APIPrefix), ConsolePrefix)
	if rest == "" || strings.HasPrefix(rest, "{") {
		return "", "", fmt.Errorf("%w: %q: path needs a fixed segment after the prefix", ErrRoute, pattern)
	}
	if strings.Contains(path, "//") || strings.Contains(path, "/./") || strings.Contains(path, "..") {
		return "", "", fmt.Errorf("%w: %q: path is not clean", ErrRoute, pattern)
	}
	for _, r := range path {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_./{}$", r):
		default:
			return "", "", fmt.Errorf("%w: %q: character %q not allowed", ErrRoute, pattern, r)
		}
	}
	return method, path, nil
}

// ValidateRoute checks one route: its pattern, its auth mode and a handler.
func ValidateRoute(r Route) error {
	if _, _, err := SplitPattern(r.Pattern); err != nil {
		return err
	}
	switch r.Auth {
	case AuthNone, AuthSession, AuthSessionCSRF:
	default:
		return fmt.Errorf("%w: %q: unknown auth mode %d", ErrRoute, r.Pattern, r.Auth)
	}
	if r.Handler == nil {
		return fmt.Errorf("%w: %q: no handler", ErrRoute, r.Pattern)
	}
	return nil
}
