// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package labels names what the server, the chart, the admission webhook
// and the in-pod edge agree on for Kubernetes enforcement (G0 M32 D964). A
// namespace is under enforcement when it carries ProtectLabel =
// ProtectEnforce and OrgLabel = the org's id; every pod in such a namespace
// is an agent pod.
package labels

import "github.com/katocxl/pantherclaw/internal/platform/ids"

// Namespace labels.
const (
	// ProtectLabel marks a namespace whose pods the admission webhook
	// decides on.
	ProtectLabel = "pantherclaw.dev/protect"
	// ProtectEnforce is ProtectLabel's only value.
	ProtectEnforce = "enforce"
	// OrgLabel names the org (its UUID) an enforced namespace belongs to.
	OrgLabel = "pantherclaw.dev/org"
)

// The edge native sidecar.
const (
	// EdgeContainer is the edge's container name: an init container with
	// restartPolicy Always.
	EdgeContainer = "pantherclaw-edge"
	// EdgePort is the edge's listen port, on 127.0.0.1 only.
	EdgePort = 3128
	// EdgeCAMount is the emptyDir the edge writes its session CA
	// certificate to (ca.crt) and the app container reads it from.
	EdgeCAMount = "/pc-edge"
)

// Token audience prefixes; the org id follows.
const (
	// GatewayAudiencePrefix is the projected-token audience a gateway pod
	// enrolls with (D968).
	GatewayAudiencePrefix = "pantherclaw-gateway:"
	// AgentAudiencePrefix is the projected-token audience of agent
	// workloads (HR-140, as issuers.Audience).
	AgentAudiencePrefix = "pantherclaw:"
)

// GatewayAudience is the audience of a gateway pod's projected token.
func GatewayAudience(org ids.OrgID) string { return GatewayAudiencePrefix + org.String() }

// AgentAudience is the audience of an agent pod's projected token.
func AgentAudience(org ids.OrgID) string { return AgentAudiencePrefix + org.String() }
