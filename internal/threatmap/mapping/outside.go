// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import "slices"

// OutsideReason says why a technique is outside PantherClaw (G0 M28 D714).
type OutsideReason string

// Outside reasons (closed).
const (
	OutsideEndpoint            OutsideReason = "ENDPOINT"
	OutsideNetwork             OutsideReason = "NETWORK"
	OutsideEmail               OutsideReason = "EMAIL"
	OutsidePhysical            OutsideReason = "PHYSICAL"
	OutsideHuman               OutsideReason = "HUMAN"
	OutsidePreCompromise       OutsideReason = "PRE_COMPROMISE"
	OutsideCloudInfrastructure OutsideReason = "CLOUD_INFRASTRUCTURE"
	OutsideIdentityProvider    OutsideReason = "IDENTITY_PROVIDER"
	OutsideModelDevelopment    OutsideReason = "MODEL_DEVELOPMENT"
)

// OutsideReasons lists every OutsideReason.
func OutsideReasons() []OutsideReason {
	return []OutsideReason{
		OutsideEndpoint, OutsideNetwork, OutsideEmail, OutsidePhysical, OutsideHuman,
		OutsidePreCompromise, OutsideCloudInfrastructure, OutsideIdentityProvider, OutsideModelDevelopment,
	}
}

// Valid reports whether r is a listed OutsideReason.
func (r OutsideReason) Valid() bool { return slices.Contains(OutsideReasons(), r) }

// ToolKind is the kind of tool that covers a technique outside PantherClaw
// (D714), shown "Outside PantherClaw: covered by <tool kind>".
type ToolKind string

// Tool kinds (closed).
const (
	ToolEDR                ToolKind = "EDR"
	ToolNetworkSecurity    ToolKind = "NETWORK_SECURITY"
	ToolEmailSecurity      ToolKind = "EMAIL_SECURITY"
	ToolPhysicalSecurity   ToolKind = "PHYSICAL_SECURITY"
	ToolSecurityAwareness  ToolKind = "SECURITY_AWARENESS"
	ToolThreatIntelligence ToolKind = "THREAT_INTELLIGENCE"
	ToolCloudSecurity      ToolKind = "CLOUD_SECURITY"
	ToolIdentityProvider   ToolKind = "IDENTITY_PROVIDER"
	ToolModelSecurity      ToolKind = "MODEL_SECURITY"
)

// ToolKinds lists every ToolKind.
func ToolKinds() []ToolKind {
	return []ToolKind{
		ToolEDR, ToolNetworkSecurity, ToolEmailSecurity, ToolPhysicalSecurity, ToolSecurityAwareness,
		ToolThreatIntelligence, ToolCloudSecurity, ToolIdentityProvider, ToolModelSecurity,
	}
}

// Valid reports whether k is a listed ToolKind.
func (k ToolKind) Valid() bool { return slices.Contains(ToolKinds(), k) }

// OutsideEntry marks a technique outside PantherClaw. An entry on a
// technique covers its sub-techniques; one on a sub-technique covers only
// it (D712).
type OutsideEntry struct {
	ID        string        `json:"id"`
	Reason    OutsideReason `json:"reason"`
	CoveredBy ToolKind      `json:"covered_by"`
	// Note is an optional single line.
	Note string `json:"note,omitzero"`
}

// Outside is every technique outside PantherClaw (D714).
var Outside = []OutsideEntry{}
