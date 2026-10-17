// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// RouteStatus is what the evidence says about one route.
type RouteStatus string

// Route statuses.
const (
	StatusMediated    RouteStatus = "mediated"
	StatusMonitored   RouteStatus = "monitored"
	StatusCooperative RouteStatus = "cooperative"
	StatusOpaque      RouteStatus = "opaque"
	StatusClosed      RouteStatus = "closed"
	StatusPossible    RouteStatus = "possible"
	StatusNotObserved RouteStatus = "not_observed"
	StatusProposed    RouteStatus = "proposed"
	StatusExcluded    RouteStatus = "excluded"
)

// Reason codes, in the order Compute reports them.
const (
	ReasonNoRoutes       = "no_known_routes"
	ReasonNoChannel      = "no_gateway_channel"
	ReasonNotActive      = "connection_not_active"
	ReasonMonitorMode    = "monitor_mode"
	ReasonCooperative    = "cooperative_channel"
	ReasonOpaqueMCP      = "opaque_mcp_server"
	ReasonAgentHeld      = "agent_held_access"
	ReasonUnverified     = "target_not_verified"
	ReasonWriteCapped    = "write_not_liftable_m9"
	ReasonNoClosure      = "no_closure_evidence"
	ReasonClosureFailed  = "closure_failed"
	ReasonClosureExpired = "closure_expired"
	ReasonClosureRebound = "closure_binding_changed"
	ReasonInvalidated    = "invalidated"
	ReasonRouteOpen      = "route_not_closed"
	ReasonInstance       = "instance_outside_sandbox"
	ReasonExcluded       = "excluded"
)

// Access modes of a connection (M6), as stored.
const (
	AccessPantherClawHeld = "pantherclaw_held"
	AccessAgentHeld       = "agent_held"
	AccessTargetEnforced  = "target_enforced"
	AccessNone            = "none"
)

// Connection is what coverage reads of a connection now. Its fields are
// settings: they can lower a state, never raise one on their own (HR-210,
// F460).
type Connection struct {
	// Kind is "http", "mcp", "mcp_container", "local", "postgres" or "a2a"
	// (the last two held by the gateway, G0 M14 D4). An "mcp"
	// connection fronts an opaque MCP server (HR-086); an "mcp_container"
	// one runs it in a connector whose egress the edge can mediate.
	Kind string
	// State is "ACTIVE", "QUARANTINED" or "RETIRED".
	State             string
	Revision          int32
	Gateway           ids.UUID
	PackageVersion    ids.UUID
	CredentialVersion *int32
	AccessMode        string
	// RouteMode is the mode, "monitor" or "enforce", of the operation's
	// package routes on a channel without an entry in RouteModes.
	RouteMode string
	// RouteModes are the current modes of the operation's routes per
	// channel.
	RouteModes map[Channel]string
}

// Route is a route inventory entry that applies to the scope: a channel
// route (Kind channel, from gateway traffic or the connection's declared
// routes) or a route around PantherClaw.
type Route struct {
	ID      ids.UUID
	Kind    RouteKind
	Channel Channel
	Locator string
	// Observation is "observed", "declared" or "proposed". A proposed route
	// is a hypothesis: it never makes a scope known and is never closed by
	// being proposed (F455).
	Observation string
}

// ClosureRecord is a recorded closure as the calculus reads it.
type ClosureRecord struct {
	ID               ids.UUID
	Agent            ids.UUID
	Connection       ids.UUID
	SandboxSession   ids.UUID
	Probes           []ProbeResult
	ConfigChecks     []ConfigCheck
	SessionStartedAt time.Time
	ObservedAt       time.Time
	ExpiresAt        time.Time
	Bound            Bound
}

// Change is a recorded invalidation event of the scope.
type Change struct {
	ID         ids.UUID
	Kind       InvalidationKind
	OccurredAt time.Time
}

// Exclusion is an active exclusion that applies to the scope. An empty
// Kind excludes the whole scope.
type Exclusion struct {
	ID   ids.UUID
	Kind RouteKind
}

// Instance is an active instance of the agent; SandboxSession is set for a
// sandbox instance (design decision 2).
type Instance struct {
	ID             ids.UUID
	SandboxSession *ids.UUID
}

// Evidence is everything a scope's state is computed from, and nothing
// else.
type Evidence struct {
	Scope Scope
	Now   time.Time
	// TTL is how long evidence supports ENFORCED (coverage.enforced_ttl).
	TTL        time.Duration
	Connection Connection
	Routes     []Route
	// Closure is the newest closure of the agent and connection, passed or
	// failed; nil when there is none.
	Closure *ClosureRecord
	// Changes are the scope's closure-invalidating events since the
	// closure's session started.
	Changes    []Change
	Exclusions []Exclusion
	// VerifiedAt is when the latest passing target-verifier test of the
	// scope's own operation ran (M8, HR-202); nil when none passed. A pass
	// for one operation never lifts another (founder decision N15).
	VerifiedAt *time.Time
	// ReadOnly: the scope's operation only reads (its definition's access is
	// read). In M9 a target-verifier test lifts only a read; writes stay
	// PARTIAL (founder decision N15).
	ReadOnly bool
	// Instances are the agent's active instances.
	Instances []Instance
}

// RouteResult is one route of a computed record.
type RouteResult struct {
	Kind    RouteKind
	Channel Channel
	Locator string
	// Route is the inventory entry; zero for a kind no source observed.
	Route   ids.UUID
	Status  RouteStatus
	Closure ids.UUID
}

// Result is a scope's computed coverage.
type Result struct {
	State   State
	Reasons []string
	Routes  []RouteResult
	// Closure and ExpiresAt are set for ENFORCED only.
	Closure   *ids.UUID
	ExpiresAt *time.Time
	// Exclusions are the exclusions that applied, which the record and
	// every claim on it list (HR-212).
	Exclusions []ids.UUID
	// Excluded: a whole-scope exclusion applies. It never changes State.
	Excluded bool
}

// Compute derives a scope's coverage from its evidence (HR-210). The first
// matching step wins:
//
//  1. UNKNOWN: the scope has no observed or declared route.
//  2. OBSERVE_ONLY: none of its routes is a gateway channel in enforce
//     mode on an active connection.
//  3. ENFORCED, only when there is a current PASSED closure of the agent
//     and connection (unexpired, its bindings still the connection's, no
//     invalidating change since its session started) and every route is
//     covered: each channel is mediated in enforce mode on
//     PantherClaw-held access, or on target-enforced access with a
//     target-verifier test of the scope's own operation no older than
//     TTL, and only when that operation reads (in M9 a write is never
//     lifted, founder decision N15); a cooperative channel needs that test
//     (HR-024) and an opaque MCP server mediated connector egress
//     (HR-086); each containment kind, observed or not (F450), is closed
//     by the closure; and every active instance of the agent is a sandbox
//     instance of the closure's session (design decision 2). It expires
//     with the closure, or sooner with the verifier test (HR-211).
//  4. PARTIAL otherwise.
//
// Settings, route modes and access modes alone never yield ENFORCED
// (F460): they only lower what the evidence supports. Exclusions never
// raise a state (HR-212, design decision 1 as the founder decided): an
// excluded route stays open, so the scope stays PARTIAL at most, and the
// exclusion is listed.
func Compute(e Evidence) Result {
	closure := e.Closure
	if closure != nil && (closure.Agent != e.Scope.Agent || closure.Connection != e.Scope.Connection) {
		closure = nil // evidence of another scope proves nothing here (INV10)
	}
	var v Verdict
	var stale []string
	if closure != nil {
		stale = staleReasons(e, closure)
		if len(stale) == 0 {
			v = Evaluate(closure.Probes, closure.ConfigChecks)
		}
	}
	var r Result
	for _, x := range e.Exclusions {
		r.Exclusions = append(r.Exclusions, x.ID)
	}
	r.Routes, r.Excluded = routes(e, closure, v)
	var reasons []string
	r.State, reasons = state(e, r.Routes)
	if r.State == Partial {
		switch {
		case closure == nil:
			reasons = append(reasons, ReasonNoClosure)
		case len(stale) > 0:
			reasons = append(reasons, stale...)
		case !v.Passed:
			reasons = append(reasons, ReasonClosureFailed)
		}
		for _, rt := range r.Routes {
			if slices.Contains(ContainmentKinds, rt.Kind) && rt.Status != StatusClosed {
				if reason := ReasonRouteOpen + ":" + string(rt.Kind); !slices.Contains(reasons, reason) {
					reasons = append(reasons, reason)
				}
			}
		}
		if closure != nil && slices.ContainsFunc(e.Instances, func(i Instance) bool {
			return i.SandboxSession == nil || *i.SandboxSession != closure.SandboxSession
		}) {
			reasons = append(reasons, ReasonInstance)
		}
		if len(reasons) == 0 {
			r.State = Enforced
			id, at := closure.ID, closure.ExpiresAt
			if e.VerifiedAt != nil && usesVerifier(e, r.Routes) {
				at = earliest(at, e.VerifiedAt.Add(e.TTL))
			}
			r.Closure, r.ExpiresAt = &id, &at
		}
	}
	r.Reasons = reasons
	if len(r.Exclusions) > 0 {
		r.Reasons = append(r.Reasons, ReasonExcluded)
	}
	return r
}

// state is UNKNOWN, OBSERVE_ONLY or the PARTIAL that Compute may raise to
// ENFORCED, with the reasons from the channels and the connection.
func state(e Evidence, routes []RouteResult) (State, []string) {
	known := slices.ContainsFunc(e.Routes, func(r Route) bool { return r.Observation != "proposed" })
	if !known {
		return Unknown, []string{ReasonNoRoutes}
	}
	var channels []RouteStatus
	for _, rt := range routes {
		if rt.Kind == KindChannel {
			channels = append(channels, rt.Status)
		}
	}
	var reasons []string
	if e.Connection.State != "ACTIVE" {
		reasons = append(reasons, ReasonNotActive)
	}
	if len(channels) == 0 {
		return ObserveOnly, append(reasons, ReasonNoChannel)
	}
	if !slices.ContainsFunc(channels, func(s RouteStatus) bool { return s != StatusMonitored && s != StatusProposed }) {
		return ObserveOnly, append(reasons, ReasonMonitorMode)
	}
	uncontrolled, cooperative := ReasonAgentHeld, ReasonCooperative
	if e.Connection.AccessMode == AccessTargetEnforced {
		uncontrolled = ReasonUnverified
	}
	if verified(e) && !e.ReadOnly {
		// the test passed, but in M9 it lifts only a read (founder decision N15)
		cooperative = ReasonWriteCapped
		if e.Connection.AccessMode == AccessTargetEnforced {
			uncontrolled = ReasonWriteCapped
		}
	}
	for _, c := range []struct {
		s      RouteStatus
		reason string
	}{
		{StatusMonitored, ReasonMonitorMode},
		{StatusCooperative, cooperative},
		{StatusOpaque, ReasonOpaqueMCP},
		{StatusPossible, uncontrolled},
		{StatusProposed, ReasonRouteOpen + ":" + string(KindChannel)},
	} {
		if slices.Contains(channels, c.s) && !slices.Contains(reasons, c.reason) {
			reasons = append(reasons, c.reason)
		}
	}
	return Partial, reasons
}

// staleReasons are why a closure no longer applies, whether it passed or
// not: it expired, the connection's revision, gateway, package version or
// credential changed, or an invalidating change came at or after its
// session's start.
func staleReasons(e Evidence, c *ClosureRecord) []string {
	cur := e.Connection
	switch {
	case !e.Now.Before(c.ExpiresAt):
		return []string{ReasonClosureExpired}
	case c.Bound.ConnectionRevision != cur.Revision || c.Bound.Gateway != cur.Gateway ||
		c.Bound.PackageVersion != cur.PackageVersion || !sameVersion(c.Bound.CredentialVersion, cur.CredentialVersion):
		return []string{ReasonClosureRebound}
	}
	var out []string
	for _, ch := range e.Changes {
		if ch.Kind.Invalidates() && !ch.OccurredAt.Before(c.SessionStartedAt) {
			if reason := ReasonInvalidated + ":" + string(ch.Kind); !slices.Contains(out, reason) {
				out = append(out, reason)
			}
		}
	}
	return out
}

// routes lists the scope's channel routes, then one entry per equivalent
// route kind: its inventory entries, or a "not observed" entry when no
// source shows one (F450).
func routes(e Evidence, closure *ClosureRecord, v Verdict) (out []RouteResult, excluded bool) {
	excludedKinds := map[RouteKind]bool{}
	for _, x := range e.Exclusions {
		if x.Kind == "" {
			excluded = true
		} else {
			excludedKinds[x.Kind] = true
		}
	}
	channels := slices.DeleteFunc(slices.Clone(e.Routes), func(r Route) bool { return r.Kind != KindChannel })
	slices.SortStableFunc(channels, func(a, b Route) int {
		switch {
		case a.Channel < b.Channel:
			return -1
		case a.Channel > b.Channel:
			return 1
		}
		return 0
	})
	for _, rt := range channels {
		out = append(out, RouteResult{
			Kind: KindChannel, Channel: rt.Channel, Locator: rt.Locator, Route: rt.ID, Status: channelStatus(e, rt, v),
		})
	}
	for _, k := range EquivalentKinds {
		closed := slices.Contains(v.Closed, k)
		status := func(observation string) RouteStatus {
			switch {
			case closed:
				return StatusClosed
			case excludedKinds[k]:
				return StatusExcluded
			case observation == "proposed":
				return StatusProposed
			case observation == "":
				return StatusNotObserved
			}
			return StatusPossible
		}
		res := RouteResult{Kind: k}
		if closed {
			res.Closure = closure.ID
		}
		n := len(out)
		for _, rt := range e.Routes {
			if rt.Kind == k {
				x := res
				x.Route, x.Locator, x.Status = rt.ID, rt.Locator, status(rt.Observation)
				out = append(out, x)
			}
		}
		if len(out) == n {
			res.Status = status("")
			out = append(out, res)
		}
	}
	return out, excluded
}

// channelStatus is a channel route's status: proposed or monitored unless
// it is in enforce mode now on an active connection; then capped by the
// access mode and the HR-024 and HR-086 rules.
func channelStatus(e Evidence, rt Route, v Verdict) RouteStatus {
	c := e.Connection
	switch {
	case rt.Observation == "proposed":
		return StatusProposed
	case c.State != "ACTIVE" || c.modeOf(rt.Channel) != "enforce":
		return StatusMonitored
	case rt.Channel.Cooperative() && !lifted(e):
		return StatusCooperative
	case c.Kind == "mcp" || (c.Kind == "mcp_container" && !v.EgressMediated):
		return StatusOpaque
	}
	switch c.AccessMode {
	case AccessPantherClawHeld, AccessNone:
		return StatusMediated
	case AccessTargetEnforced:
		if lifted(e) {
			return StatusMediated
		}
	}
	return StatusPossible
}

// verified reports whether a target-verifier test passed no longer than
// TTL ago (HR-210).
func verified(e Evidence) bool {
	return e.VerifiedAt != nil && !e.VerifiedAt.After(e.Now) && e.Now.Before(e.VerifiedAt.Add(e.TTL))
}

// lifted reports whether the target-verifier test lifts the scope: it
// passed in time and the operation only reads (M9, founder decision N15).
func lifted(e Evidence) bool { return verified(e) && e.ReadOnly }

// usesVerifier reports whether a mediated channel rests on the
// target-verifier test, so ENFORCED expires with it.
func usesVerifier(e Evidence, routes []RouteResult) bool {
	return slices.ContainsFunc(routes, func(rt RouteResult) bool {
		return rt.Kind == KindChannel && rt.Status == StatusMediated &&
			(rt.Channel.Cooperative() || e.Connection.AccessMode == AccessTargetEnforced)
	})
}

// modeOf is the current route mode of channel ch.
func (c Connection) modeOf(ch Channel) string {
	if m, ok := c.RouteModes[ch]; ok {
		return m
	}
	return c.RouteMode
}

func sameVersion(a, b *int32) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// LapseExpired is the lapse reason of a state past its expiry.
const LapseExpired = "expired"

// Lapse reports why a stored state no longer holds at now, "" while it
// does (HR-211): LapseExpired once its expiry passed, else the kind of the
// first change to the scope the stored state did not see. A lapsed scope
// is recomputed from current evidence and read through Cap.
func Lapse(expiresAt *time.Time, unseen []Change, now time.Time) string {
	if expiresAt != nil && !now.Before(*expiresAt) {
		return LapseExpired
	}
	if len(unseen) > 0 {
		return string(unseen[0].Kind)
	}
	return ""
}

// Cap is a lapsed scope's state: recomputed from current evidence and
// capped at StaleState, so it may read lower (HR-211).
func Cap(recomputed State) State { return min(recomputed, StaleState) }
