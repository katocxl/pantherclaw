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
	ReasonConnectionRetired = "connection_retired"
	ReasonNoTraffic         = "no_observed_traffic"
	ReasonMonitorMode       = "monitor_mode"
	ReasonCooperative       = "cooperative_channel"
	ReasonOpaqueMCP         = "opaque_mcp_server"
	ReasonNotActive         = "connection_not_active"
	ReasonNoClosure         = "no_closure_evidence"
	ReasonClosureFailed     = "closure_failed"
	ReasonClosureExpired    = "closure_expired"
	ReasonClosureRebound    = "closure_binding_changed"
	ReasonInvalidated       = "invalidated"
	ReasonRouteOpen         = "route_not_closed"
	ReasonExcluded          = "excluded"
)

// Connection is what coverage reads of a connection now. Its fields are
// settings: they can lower a state, never raise one (HR-210, F460).
type Connection struct {
	// Kind is "http", "mcp" or "local"; an "mcp" connection fronts an
	// opaque MCP server (HR-086).
	Kind string
	// State is "ACTIVE", "QUARANTINED" or "RETIRED".
	State          string
	Revision       int32
	Gateway        ids.UUID
	PackageVersion ids.UUID
	// RouteMode is the mode, "monitor" or "enforce", of the operation's
	// package routes on a channel without an entry in RouteModes.
	RouteMode string
	// RouteModes are the current modes of the operation's routes per
	// channel.
	RouteModes map[Channel]string
}

// Traffic is a channel the gateway observed carrying the scope's action, in
// a route mode.
type Traffic struct {
	Channel Channel
	Mode    string
}

// Route is a route inventory entry that applies to the scope.
type Route struct {
	ID      ids.UUID
	Kind    RouteKind
	Channel Channel
	Locator string
	// Observation is "observed", "declared" or "proposed".
	Observation string
}

// ClosureRecord is a recorded closure as the calculus reads it.
type ClosureRecord struct {
	ID               ids.UUID
	Agent            ids.UUID
	Connection       ids.UUID
	Probes           []ProbeResult
	SessionStartedAt time.Time
	ObservedAt       time.Time
	ExpiresAt        time.Time
	Revision         int32
	Gateway          ids.UUID
	PackageVersion   ids.UUID
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

// Evidence is everything a scope's state is computed from, and nothing
// else.
type Evidence struct {
	Scope      Scope
	Now        time.Time
	Connection Connection
	Traffic    []Traffic
	Routes     []Route
	// Closure is the newest closure of the agent and connection, passed or
	// failed; nil when there is none.
	Closure *ClosureRecord
	// Changes are the scope's invalidation events since the closure's
	// session started.
	Changes    []Change
	Exclusions []Exclusion
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
	// Excluded: a whole-scope exclusion applies. It never changes State.
	Excluded bool
}

// Compute derives a scope's coverage from its evidence (HR-210):
//
//   - a retired connection, or a scope without observed traffic, is
//     UNKNOWN: a connection setting alone yields no state (F460);
//   - traffic observed only in monitor mode, or a route in monitor mode
//     now, is OBSERVE_ONLY;
//   - a cooperative channel is capped at PARTIAL unless the target is shown
//     to verify action tokens (HR-024), an opaque MCP server unless its
//     egress is shown mediated (HR-086);
//   - ENFORCED needs every observed channel mediated in enforce mode and a
//     passed, unexpired closure of the agent and connection, bound to the
//     connection's current revision, gateway and package version, followed
//     by no invalidating change, that closes every containment kind. It
//     expires with the closure (HR-211);
//   - anything else with a mediated route is PARTIAL.
//
// Exclusions never raise a state (HR-212).
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
			v = Evaluate(closure.Probes)
		}
	}
	var r Result
	r.Routes, r.Excluded = routes(e, closure, v)
	r.State, r.Reasons = state(e, r.Routes)
	if r.State == Partial {
		switch {
		case closure == nil:
			r.Reasons = append(r.Reasons, ReasonNoClosure)
		case len(stale) > 0:
			r.Reasons = append(r.Reasons, stale...)
		case !v.Passed:
			r.Reasons = append(r.Reasons, ReasonClosureFailed)
		}
		for _, rt := range r.Routes {
			if slices.Contains(ContainmentKinds, rt.Kind) && rt.Status != StatusClosed {
				r.Reasons = append(r.Reasons, ReasonRouteOpen+":"+string(rt.Kind))
			}
		}
		if len(r.Reasons) == 0 {
			r.State = Enforced
			id, at := closure.ID, closure.ExpiresAt
			r.Closure, r.ExpiresAt = &id, &at
		}
	}
	if r.Excluded {
		r.Reasons = append(r.Reasons, ReasonExcluded)
	}
	return r
}

// state is UNKNOWN, OBSERVE_ONLY or the PARTIAL that Compute may raise to
// ENFORCED, with the reasons from the channels and the connection.
func state(e Evidence, routes []RouteResult) (State, []string) {
	if e.Connection.State == "RETIRED" {
		return Unknown, []string{ReasonConnectionRetired}
	}
	var channels []RouteStatus
	for _, rt := range routes {
		if rt.Kind == KindChannel {
			channels = append(channels, rt.Status)
		}
	}
	if len(channels) == 0 {
		return Unknown, []string{ReasonNoTraffic}
	}
	if !slices.ContainsFunc(channels, func(s RouteStatus) bool { return s != StatusMonitored }) {
		return ObserveOnly, []string{ReasonMonitorMode}
	}
	var reasons []string
	for _, c := range []struct {
		s      RouteStatus
		reason string
	}{{StatusMonitored, ReasonMonitorMode}, {StatusCooperative, ReasonCooperative}, {StatusOpaque, ReasonOpaqueMCP}} {
		if slices.Contains(channels, c.s) {
			reasons = append(reasons, c.reason)
		}
	}
	if e.Connection.State != "ACTIVE" {
		reasons = append(reasons, ReasonNotActive)
	}
	return Partial, reasons
}

// staleReasons are why a closure no longer applies, whether it passed or
// not: it expired, the connection's revision, gateway or package version
// changed, or an invalidating change followed its session's start.
func staleReasons(e Evidence, c *ClosureRecord) []string {
	switch {
	case !e.Now.Before(c.ExpiresAt):
		return []string{ReasonClosureExpired}
	case c.Revision != e.Connection.Revision || c.Gateway != e.Connection.Gateway ||
		c.PackageVersion != e.Connection.PackageVersion:
		return []string{ReasonClosureRebound}
	}
	var out []string
	for _, ch := range e.Changes {
		if ch.Kind.Invalidates() && ch.OccurredAt.After(c.SessionStartedAt) {
			if reason := ReasonInvalidated + ":" + string(ch.Kind); !slices.Contains(out, reason) {
				out = append(out, reason)
			}
		}
	}
	return out
}

// routes lists the scope's channel routes from traffic, then one entry per
// equivalent route kind: its inventory entries, or a "not observed" entry
// when no source shows one (F450).
func routes(e Evidence, closure *ClosureRecord, v Verdict) (out []RouteResult, excluded bool) {
	excludedKinds := map[RouteKind]bool{}
	for _, x := range e.Exclusions {
		if x.Kind == "" {
			excluded = true
		} else {
			excludedKinds[x.Kind] = true
		}
	}
	var seen []Channel
	for _, t := range e.Traffic {
		if !slices.Contains(seen, t.Channel) {
			seen = append(seen, t.Channel)
		}
	}
	slices.Sort(seen)
	for _, ch := range seen {
		out = append(out, RouteResult{Kind: KindChannel, Channel: ch, Status: channelStatus(e, ch, v)})
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

// channelStatus is a channel route's status: monitored unless traffic in
// enforce mode was observed and the route is in enforce mode now; then
// capped by the HR-024 and HR-086 rules.
func channelStatus(e Evidence, ch Channel, v Verdict) RouteStatus {
	enforced := e.Connection.modeOf(ch) == "enforce" &&
		slices.ContainsFunc(e.Traffic, func(t Traffic) bool { return t.Channel == ch && t.Mode == "enforce" })
	switch {
	case !enforced:
		return StatusMonitored
	case ch.Cooperative() && !v.TargetVerifiesTokens:
		return StatusCooperative
	case e.Connection.Kind == "mcp" && !v.EgressMediated:
		return StatusOpaque
	}
	return StatusMediated
}

// ReadAt is what a computed ENFORCED state reads as at time now, given the
// changes after it was computed: PARTIAL once it expired or a change
// invalidated it (HR-211). Other states read as computed.
func ReadAt(s State, expiresAt *time.Time, changesSince int, now time.Time) (State, string) {
	if s != Enforced {
		return s, ""
	}
	if expiresAt == nil || !now.Before(*expiresAt) {
		return StaleState, ReasonClosureExpired
	}
	if changesSince > 0 {
		return StaleState, ReasonInvalidated
	}
	return s, ""
}

// Invalidates reports whether a change of kind k drops ENFORCED at once
// (HR-211). An exclusion or a lapsed expiry only asks for a reassessment:
// neither raises a state, and neither makes closure evidence stale.
func (k InvalidationKind) Invalidates() bool { return k != InvExclusion && k != InvEvidenceExpired }

// modeOf is the current route mode of channel ch.
func (c Connection) modeOf(ch Channel) string {
	if m, ok := c.RouteModes[ch]; ok {
		return m
	}
	return c.RouteMode
}
