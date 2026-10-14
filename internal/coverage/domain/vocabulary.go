// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds coverage's vocabulary (G0 M9 track A; F433–F460):
// the four coverage states, route kinds and statuses, the closure evidence
// the sandbox records, invalidation kinds and the freshness contract.
//
// A coverage claim is scoped to one agent, connection and operation
// (decision 6) and computed only from evidence (HR-210).
package domain

import "github.com/katocxl/pantherclaw/internal/platform/ids"

// State is a scope's coverage claim (F435–F438). The order is meaningful:
// a higher state claims more, and a cap is a maximum.
type State int

// States, weakest first.
const (
	Unknown State = iota + 1
	ObserveOnly
	Partial
	Enforced
)

var stateNames = map[State]string{Unknown: "UNKNOWN", ObserveOnly: "OBSERVE_ONLY", Partial: "PARTIAL", Enforced: "ENFORCED"}

// String returns the stored name, e.g. "OBSERVE_ONLY".
func (s State) String() string { return stateNames[s] }

// ParseState returns the state stored as name.
func ParseState(name string) (State, bool) {
	for s, n := range stateNames {
		if n == name {
			return s, true
		}
	}
	return 0, false
}

// RouteKind is a way to produce a connection's effects (§41.4).
type RouteKind string

// Route kinds, as stored.
const (
	KindChannel      RouteKind = "channel"
	KindDirectAPI    RouteKind = "direct_api"
	KindHost         RouteKind = "host"
	KindGitSSH       RouteKind = "git_ssh"
	KindCredential   RouteKind = "credential"
	KindBrowser      RouteKind = "browser"
	KindDelegated    RouteKind = "delegated"
	KindIntermediary RouteKind = "intermediary"
	KindTargetSide   RouteKind = "target_side"
)

// EquivalentKinds are the route kinds besides PantherClaw's channels that
// coverage considers for every scope, in display order.
var EquivalentKinds = []RouteKind{
	KindDirectAPI, KindHost, KindGitSSH, KindCredential, KindBrowser, KindDelegated, KindIntermediary, KindTargetSide,
}

// Channel is a PantherClaw channel a route goes through.
type Channel string

// Channels, as stored on transactions (M6).
const (
	ChannelHTTP Channel = "http"
	ChannelMCP  Channel = "mcp"
	ChannelSDK  Channel = "sdk"
	ChannelHook Channel = "hook"
)

// Cooperative reports whether the agent itself calls PantherClaw on the
// channel and could skip it (HR-024).
func (c Channel) Cooperative() bool { return c == ChannelSDK || c == ChannelHook }

// Scope names one agent, connection and operation.
type Scope struct {
	Agent      ids.UUID
	Connection ids.UUID
	Operation  string
}

// InvalidationKind is a change coverage hears about (HR-211). Most drop
// ENFORCED at once; see Invalidates.
type InvalidationKind string

// Invalidation kinds, as stored.
const (
	InvConnection      InvalidationKind = "connection"
	InvPackageVersion  InvalidationKind = "package_version"
	InvRouteMode       InvalidationKind = "route_mode"
	InvGateway         InvalidationKind = "gateway"
	InvCredential      InvalidationKind = "credential"
	InvSandboxImage    InvalidationKind = "sandbox_image"
	InvSandboxConfig   InvalidationKind = "sandbox_config"
	InvClosureFailed   InvalidationKind = "closure_failed"
	InvExclusion       InvalidationKind = "exclusion"
	InvEvidenceExpired InvalidationKind = "evidence_expired"
	InvRoute           InvalidationKind = "route"
	InvInstance        InvalidationKind = "instance"
)

// InvalidationKinds lists every kind, in the order the freshness contract
// publishes them.
var InvalidationKinds = []InvalidationKind{
	InvConnection, InvPackageVersion, InvRouteMode, InvGateway, InvCredential, InvSandboxImage, InvSandboxConfig,
	InvClosureFailed, InvInstance, InvExclusion, InvEvidenceExpired, InvRoute,
}

// Invalidates reports whether a change of kind k at or after a closure's
// session start makes the closure stale (HR-211). A new route, an exclusion
// or a lapsed expiry only makes the scope be recomputed: the closure still
// closes the route kinds its probes closed, and a session's own refused
// destinations are recorded as routes after it started.
func (k InvalidationKind) Invalidates() bool {
	return k != InvRoute && k != InvExclusion && k != InvEvidenceExpired
}

// Invalidation is a change the sandbox or another module reports to
// coverage. A nil Agent affects every agent of the connection.
type Invalidation struct {
	Kind       InvalidationKind
	Connection ids.UUID
	Agent      *ids.UUID
	Subject    *ids.UUID
	Detail     string
}
