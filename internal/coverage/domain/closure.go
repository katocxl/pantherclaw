// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Probe roles and outcomes in closure evidence.
const (
	RoleProbe           = "probe"
	RolePositiveControl = "positive_control"
	RoleNegativeControl = "negative_control"
	RoleCanary          = "canary"

	Blocked   = "blocked"
	Reachable = "reachable"
	ProbeErr  = "error"
)

// ProbeResult is one probe, control or canary result of a sandbox session.
// It passes only when what was observed is what was expected; an error
// never passes. Detail is UNTRUSTED text from the launcher's host.
type ProbeResult struct {
	Name     string `json:"name"`
	Role     string `json:"role"`
	Expect   string `json:"expect"`
	Observed string `json:"observed"`
	Detail   string `json:"detail,omitempty"`
}

// Passed reports whether the result is the expected one.
func (p ProbeResult) Passed() bool {
	return (p.Expect == Blocked || p.Expect == Reachable) && p.Observed == p.Expect
}

// ConfigCheck is one of pclaw's checks of the agent container's
// configuration: what no probe inside the sandbox can see, such as its
// mounts. Detail is UNTRUSTED text.
type ConfigCheck struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Engine is the container engine a sandbox session ran on (HR-218).
type Engine struct {
	Version    string
	APIVersion string
	// Runtime is "runc" or "runsc" (gVisor).
	Runtime string
}

// Bound are the bindings a sandbox session was opened under, captured by
// the server when the session opened. A closure whose bindings no longer
// match the connection's is stale (HR-211).
type Bound struct {
	ConnectionRevision int32
	PackageVersion     ids.UUID
	Gateway            ids.UUID
	// CredentialVersion is the active sealed credential's version; nil
	// when the connection had none.
	CredentialVersion *int32
}

// Closure is the closure evidence of one sandbox session for one agent and
// connection (F457, PN-008.2). Only the sandbox module records it, after it
// verified the signature over the results and their server nonce (HR-215);
// coverage computes whether it passed from the probes and configuration
// checks, never from the caller.
type Closure struct {
	Agent          ids.UUID
	Connection     ids.UUID
	SandboxSession ids.UUID
	// SessionStartedAt is when the session opened, by the database clock:
	// a change to the scope at or after it makes the closure unusable.
	SessionStartedAt time.Time
	// ObservedAt is when the probes ran.
	ObservedAt   time.Time
	Probes       []ProbeResult
	ConfigChecks []ConfigCheck
	// SigningKeyJKT is the RFC 7638 thumbprint of the per-session key.
	SigningKeyJKT string
	ServerNonce   string
	// ResultsSHA256 is the digest of the exact signed results.
	ResultsSHA256 [32]byte
	Engine        Engine
	// ImageDigests are the session's images, "sha256:<hex>".
	ImageDigests []string
	// ConfigSHA256 is the digest of the sandbox configuration.
	ConfigSHA256 [32]byte
	Bound        Bound
}

// ObservedRoute is a route the sandbox saw from inside a session: a
// destination the edge refused (direct_api, the host and port as its
// locator) or a credential it stripped or found (credential, its kind and
// a digest prefix, never the value). It is a sighting, never a grant.
type ObservedRoute struct {
	Agent          ids.UUID
	Connection     ids.UUID
	SandboxSession ids.UUID
	Kind           RouteKind
	// Locator is UNTRUSTED text, at most 512 characters.
	Locator string
}

// Probe names (the closure contract with the sandbox's probe catalog).
// Unknown names are kept and shown but close nothing.
const (
	ProbeDNSExternal       = "dns_external"
	ProbeDNSDockerResolver = "dns_docker_resolver"
	ProbeIPv6              = "ipv6"
	ProbeICMP              = "icmp"
	ProbeDirectHTTPS       = "direct_https"
	ProbeMetadata          = "metadata"
	ProbeHostGateway       = "host_gateway"
	ProbeDockerSocket      = "docker_socket"
	ProbeDirectSSH         = "direct_ssh"
	ProbeSSHPush           = "ssh_push"
	ProbePATPush           = "pat_push"
	ProbeExternalCanary    = "external_canary"

	// The named controls. edge_mediated (a mapped request through the edge
	// reaches the gateway's face), canary_control (a control nonce from the
	// edge's uplink reaches the canary) and edge_unmapped_refused are
	// required; edge_reachable and dns_resolver_works are optional.
	ProbeEdgeMediated        = "edge_mediated"
	ProbeCanaryControl       = "canary_control"
	ProbeEdgeUnmappedRefused = "edge_unmapped_refused"
	ProbeEdgeReachable       = "edge_reachable"
	ProbeDNSResolverWorks    = "dns_resolver_works"
	// ProbeConnectorEgress shows a connector's egress goes only through the
	// edge: it lifts the opaque-MCP cap (HR-086, track C).
	ProbeConnectorEgress = "connector_egress_mediated"
)

// Configuration check ids (pclaw inspects the agent container).
const (
	CheckNoDockerSocket = "agent_no_docker_socket"
	CheckNoHostBind     = "agent_no_host_bind"
)

// ContainmentKinds are the route kinds a sandbox closure can close, each by
// its own probes (F458: closing one route never closes another). Every one
// must be closed for ENFORCED. Target-side identities are not routes of a
// contained workload; they are exposure (F449, F048).
var ContainmentKinds = []RouteKind{
	KindDirectAPI, KindHost, KindGitSSH, KindCredential, KindBrowser, KindDelegated, KindIntermediary,
}

// closingProbes are the probes, each expected blocked, that close a kind.
// The Docker socket is never mounted (HR-084): its probe cannot have a
// positive twin, so the host route closes on pclaw's configuration checks
// instead (closingChecks).
var closingProbes = map[RouteKind][]string{
	KindDirectAPI: {
		ProbeDNSExternal, ProbeDNSDockerResolver, ProbeIPv6, ProbeICMP, ProbeDirectHTTPS, ProbeMetadata,
		ProbeHostGateway, ProbeExternalCanary,
	},
	KindHost:         {ProbeHostGateway},
	KindGitSSH:       {ProbeDirectSSH, ProbeSSHPush},
	KindCredential:   {ProbePATPush, ProbeSSHPush, ProbeMetadata},
	KindBrowser:      {ProbeDirectHTTPS, ProbePATPush},
	KindDelegated:    {ProbeDirectHTTPS, ProbeDirectSSH},
	KindIntermediary: {ProbeDirectHTTPS, ProbeDirectSSH},
}

// closingChecks are the configuration checks that must also be ok.
var closingChecks = map[RouteKind][]string{
	KindHost: {CheckNoDockerSocket, CheckNoHostBind},
}

// twinOptional are probes whose route may not exist even on the open
// control network (no IPv6, no metadata service on a laptop). They close
// on their blocked result alone; every other closing probe needs its
// positive twin (decision 15), so a probe that cannot see an open route,
// such as ICMP without NET_RAW, closes nothing.
var twinOptional = []string{ProbeIPv6, ProbeMetadata}

// twinOf is the positive control that shows a probe can see an open route:
// the probe again on the open control network, or for the canary the
// control nonce reaching it.
func twinOf(probe string) string {
	if probe == ProbeExternalCanary {
		return ProbeCanaryControl
	}
	return probe
}

// Verdict is what a closure's evidence proves.
type Verdict struct {
	// Passed: the evidence is sound. Every result and check passed, and
	// the named controls and the canary are present (HR-121). What it proves
	// is Closed: the calculus needs every containment kind closed that a
	// person did not exclude.
	Passed                     bool
	PositiveControls, Negative bool
	Canary                     bool
	// Closed are the containment kinds proven blocked, in ContainmentKinds
	// order; nothing is closed when a control failed or is missing.
	Closed []RouteKind
	// EgressMediated lifts the HR-086 cap; it counts only when the
	// controls passed.
	EgressMediated bool
	// Failed names the results and checks that did not pass, and the
	// required controls that are missing.
	Failed []string
}

// Evaluate computes what a closure's probe results and configuration
// checks prove. A name passes only when it has results and all of them
// passed with the expected outcome. Nothing closes unless the named
// positive and negative controls passed (a sandbox in which nothing is
// reachable proves nothing), and any failed result fails the closure. A
// passed closure that lacks a kind's probes simply does not close it.
func Evaluate(probes []ProbeResult, checks []ConfigCheck) Verdict {
	var v Verdict
	type key struct{ role, name string }
	byKey := map[key][]ProbeResult{}
	roles := map[string]bool{}
	for _, p := range probes {
		byKey[key{p.Role, p.Name}] = append(byKey[key{p.Role, p.Name}], p)
		if _, seen := roles[p.Role]; !seen {
			roles[p.Role] = true
		}
		if !p.Passed() {
			v.Failed = append(v.Failed, p.Name)
			roles[p.Role] = false
		}
	}
	ok := map[string]bool{}
	for _, c := range checks {
		if _, seen := ok[c.ID]; !seen {
			ok[c.ID] = true
		}
		if !c.OK {
			v.Failed = append(v.Failed, "config:"+c.ID)
			ok[c.ID] = false
		}
	}
	proven := func(role, name, outcome string) bool {
		rs := byKey[key{role, name}]
		return len(rs) > 0 && !slices.ContainsFunc(rs, func(p ProbeResult) bool { return !p.Passed() || p.Expect != outcome })
	}
	required := func(role, name, outcome string) bool {
		if proven(role, name, outcome) {
			return true
		}
		if len(byKey[key{role, name}]) == 0 {
			v.Failed = append(v.Failed, name)
		}
		return false
	}
	positive := required(RolePositiveControl, ProbeEdgeMediated, Reachable)
	positive = required(RolePositiveControl, ProbeCanaryControl, Reachable) && positive
	v.PositiveControls = positive && roles[RolePositiveControl]
	v.Negative = required(RoleNegativeControl, ProbeEdgeUnmappedRefused, Blocked) && roles[RoleNegativeControl]
	v.Canary = required(RoleCanary, ProbeExternalCanary, Blocked) && roles[RoleCanary]
	if !v.PositiveControls || !v.Negative {
		return v
	}
	closes := func(name string) bool {
		role := RoleProbe
		if name == ProbeExternalCanary {
			role = RoleCanary
		}
		if !proven(role, name, Blocked) {
			return false
		}
		return slices.Contains(twinOptional, name) || proven(RolePositiveControl, twinOf(name), Reachable)
	}
	for _, k := range ContainmentKinds {
		if slices.ContainsFunc(closingProbes[k], func(n string) bool { return !closes(n) }) ||
			slices.ContainsFunc(closingChecks[k], func(id string) bool { return !ok[id] }) {
			continue
		}
		v.Closed = append(v.Closed, k)
	}
	v.EgressMediated = proven(RolePositiveControl, ProbeConnectorEgress, Reachable)
	v.Passed = v.Canary && len(v.Failed) == 0
	return v
}
