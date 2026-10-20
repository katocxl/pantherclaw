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
	// BillingLinks binds provider subscriptions to orgs; nil until the
	// core provides it.
	BillingLinks BillingLinks
	// Authz checks the session principal's permissions; nil until the core
	// provides it, and while it is nil every session route refuses.
	Authz Authorizer
	// Audit records billing events in the org's audit ledger; nil until the
	// core provides it.
	Audit AuditRecorder
}

// Authorizer checks a permission for the principal of a session route's
// request, with the core's normal permission check, scoped as for a
// Connect procedure: the error refuses the request.
type Authorizer interface {
	Require(ctx context.Context, permission string) error
}

// AuditRecorder records one event in an org's audit ledger. kind must
// start with "billing."; fields are small and never hold secrets (the core
// bounds and checks them).
type AuditRecorder interface {
	Record(ctx context.Context, orgID, kind string, fields map[string]string) error
}

// AuditKindPrefix is the prefix every extension audit kind carries.
const AuditKindPrefix = "billing."

// Present reports whether s adds anything to the core server.
func (s Set) Present() bool { return s.Console != nil || s.Mount != nil || s.Validate != nil }

// BillingLinks binds billing-provider subscriptions to orgs, only through
// checkouts the server created (a webhook's own org hint is never
// trusted). A ref never moves to another org. A subscription is "current"
// from its binding until it ends (a subscription canceled at period end
// stays current until the cancellation takes effect and EndSubscription is
// called); an org has at most one current subscription per provider.
type BillingLinks interface {
	// RecordCheckout records a pending checkout the server created for
	// orgID. An existing pending checkout of the same org and provider is
	// marked expired and its ref returned as superseded (the caller cancels
	// it at the provider); re-recording the same pending ref for the same
	// org is a no-op. It returns ErrConflict when the org has a current
	// subscription, and when checkoutRef is already recorded for another
	// org.
	RecordCheckout(ctx context.Context, orgID, provider, checkoutRef string, expiresAt time.Time) (superseded string, err error)
	// BindSubscription binds a subscription to the org of a recorded
	// checkout and marks the checkout consumed. A checkout still binds
	// after it expired or was superseded while the org has no current
	// subscription. The same checkout and subscription return the org again
	// (idempotent); a checkout consumed by a different subscription, and a
	// subscription already bound through another checkout, return
	// ErrConflict; an unknown checkout returns ErrNotFound. When the org
	// already has a different current subscription, the new one is
	// recorded as an ended duplicate and BindSubscription returns
	// (orgID, ErrDuplicate), every time for that pair; the caller cancels
	// and refunds it.
	BindSubscription(ctx context.Context, provider, checkoutRef, subscriptionRef, customerRef string) (orgID string, err error)
	// SubscriptionOrg returns the org of a bound subscription and whether
	// it is the org's current one; ErrNotFound if unknown.
	SubscriptionOrg(ctx context.Context, provider, subscriptionRef string) (orgID string, current bool, err error)
	// EndSubscription marks a subscription ended; it is no longer current.
	// Ending an ended subscription is a no-op; an unknown one returns
	// ErrNotFound.
	EndSubscription(ctx context.Context, provider, subscriptionRef string) error
	// CurrentSubscription returns the org's current subscription with the
	// provider, if any (ok false, no error, when there is none).
	CurrentSubscription(ctx context.Context, orgID, provider string) (subscriptionRef string, ok bool, err error)
}

// BillingLinks errors. errors.Is(ErrDuplicate, ErrConflict) is true.
var (
	ErrNotFound  = errors.New("extension: not found")
	ErrConflict  = errors.New("extension: conflict")
	ErrDuplicate = fmt.Errorf("%w: duplicate subscription", ErrConflict)
)

// Principal is the browser-session caller of an AuthSession or
// AuthSessionCSRF route. OrgID and UserID are empty for account sessions;
// AccountID is empty for org sessions of a person without a hosted account.
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
	if strings.Contains(path, "//") || strings.Contains(path, "/./") || strings.Contains(path, "..") ||
		strings.HasSuffix(path, "/.") {
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
// AuthSession is only for GET or HEAD routes; a route with any other
// method, or with none (which matches every method), that takes the
// session cookie must use AuthSessionCSRF (HR-151, T-160).
func ValidateRoute(r Route) error {
	method, _, err := SplitPattern(r.Pattern)
	if err != nil {
		return err
	}
	switch r.Auth {
	case AuthNone, AuthSessionCSRF:
	case AuthSession:
		if method != http.MethodGet && method != http.MethodHead {
			return fmt.Errorf("%w: %q: a session route that is not GET or HEAD must use AuthSessionCSRF", ErrRoute, r.Pattern)
		}
	default:
		return fmt.Errorf("%w: %q: unknown auth mode %d", ErrRoute, r.Pattern, r.Auth)
	}
	if r.Handler == nil {
		return fmt.Errorf("%w: %q: no handler", ErrRoute, r.Pattern)
	}
	return nil
}
