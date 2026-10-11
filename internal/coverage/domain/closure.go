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
// never passes.
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

// Engine is the container engine a sandbox session ran on (HR-218).
type Engine struct {
	Version    string
	APIVersion string
	// Runtime is "runc" or "runsc" (gVisor).
	Runtime string
}

// Closure is the closure evidence of one sandbox session for one agent and
// connection (F457, PN-008.2). Only the sandbox module records it, after it
// verified the signature over the results and their server nonce (HR-215);
// coverage computes whether it passed from the probes, never from the
// caller.
type Closure struct {
	Agent          ids.UUID
	Connection     ids.UUID
	SandboxSession ids.UUID
	// SessionStartedAt is when the session started: a change to the scope
	// after it makes the closure unusable.
	SessionStartedAt time.Time
	// ObservedAt is when the probes ran.
	ObservedAt time.Time
	Probes     []ProbeResult
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
	Gateway      ids.UUID
}

// Probe names the calculus understands (the contract with the sandbox's
// probe catalog). Unknown names are kept and shown but close nothing.
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
	// ProbeTargetRequiresToken shows the target refuses a call without an
	// action token: it lifts the cooperative cap (HR-024).
	ProbeTargetRequiresToken = "target_requires_token"
	// ProbeConnectorEgress shows a connector's egress goes only through the
	// edge: it lifts the opaque-MCP cap (HR-086).
	ProbeConnectorEgress = "connector_egress_mediated"
)

// ContainmentKinds are the route kinds a sandbox closure can close, each by
// its own probes (F458: closing one route never closes another). Every one
// must be closed for ENFORCED. Target-side identities are not routes of a
// contained workload; they are exposure (F449, F048).
var ContainmentKinds = []RouteKind{
	KindDirectAPI, KindHost, KindGitSSH, KindCredential, KindBrowser, KindDelegated, KindIntermediary,
}

// closingProbes are the probes, each expected blocked, that close a kind.
var closingProbes = map[RouteKind][]string{
	KindDirectAPI: {
		ProbeDNSExternal, ProbeDNSDockerResolver, ProbeIPv6, ProbeICMP, ProbeDirectHTTPS, ProbeMetadata,
		ProbeHostGateway, ProbeExternalCanary,
	},
	KindHost:         {ProbeDockerSocket, ProbeHostGateway},
	KindGitSSH:       {ProbeDirectSSH, ProbeSSHPush},
	KindCredential:   {ProbePATPush, ProbeSSHPush, ProbeMetadata},
	KindBrowser:      {ProbeDirectHTTPS, ProbePATPush},
	KindDelegated:    {ProbeDirectHTTPS, ProbeDirectSSH},
	KindIntermediary: {ProbeDirectHTTPS, ProbeDirectSSH},
}

// Verdict is what a closure's probes prove.
type Verdict struct {
	// Passed: both controls and the canary passed and every containment
	// kind is closed (HR-121).
	Passed                     bool
	PositiveControls, Negative bool
	Canary                     bool
	// Closed are the containment kinds proven blocked, in ContainmentKinds
	// order; nothing is closed when a control failed.
	Closed []RouteKind
	// TargetVerifiesTokens and EgressMediated lift the HR-024 and HR-086
	// caps; they count only when the controls passed.
	TargetVerifiesTokens, EgressMediated bool
	// Failed names the results that did not pass.
	Failed []string
}

// Evaluate computes what a closure's probe results prove. A role counts
// only when at least one result has it and all of them passed; a probe
// closes only when every result with its name passed with the expected
// outcome, and only when both controls passed (a sandbox in which nothing
// is reachable proves nothing).
func Evaluate(probes []ProbeResult) Verdict {
	var v Verdict
	type key struct{ role, name string }
	byKey := map[key][]ProbeResult{}
	for _, p := range probes {
		byKey[key{p.Role, p.Name}] = append(byKey[key{p.Role, p.Name}], p)
		if !p.Passed() {
			v.Failed = append(v.Failed, p.Name)
		}
	}
	proven := func(role, name, outcome string) bool {
		rs := byKey[key{role, name}]
		return len(rs) > 0 && !slices.ContainsFunc(rs, func(p ProbeResult) bool { return !p.Passed() || p.Expect != outcome })
	}
	role := func(r string) bool {
		seen := false
		for _, p := range probes {
			if p.Role == r {
				if !p.Passed() {
					return false
				}
				seen = true
			}
		}
		return seen
	}
	v.PositiveControls, v.Negative, v.Canary = role(RolePositiveControl), role(RoleNegativeControl), role(RoleCanary)
	if !v.PositiveControls || !v.Negative {
		return v
	}
	blocked := func(name string) bool {
		if name == ProbeExternalCanary {
			return proven(RoleCanary, name, Blocked)
		}
		return proven(RoleProbe, name, Blocked)
	}
	for _, k := range ContainmentKinds {
		if !slices.ContainsFunc(closingProbes[k], func(n string) bool { return !blocked(n) }) {
			v.Closed = append(v.Closed, k)
		}
	}
	v.TargetVerifiesTokens = blocked(ProbeTargetRequiresToken)
	v.EgressMediated = proven(RolePositiveControl, ProbeConnectorEgress, Reachable)
	v.Passed = v.Canary && len(v.Closed) == len(ContainmentKinds)
	return v
}
