// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "authzen.". The ledger stores each as "audit." + the kind.
const (
	AuthzenDecisionRequested = "authzen.decision_requested"
	AuthzenEnforcementPointActivated = "authzen.enforcement_point_activated"
	AuthzenEnforcementPointCreated = "authzen.enforcement_point_created"
	AuthzenEnforcementPointDisabled = "authzen.enforcement_point_disabled"
	AuthzenEnforcementPointNarrowed = "authzen.enforcement_point_narrowed"
	AuthzenEnforcementPointProposed = "authzen.enforcement_point_proposed"
)
