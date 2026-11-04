// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "agent.". The ledger stores each as "audit." + the kind.
const (
	AgentDiscovered = "agent.discovered"
	AgentDiscoveryChanged = "agent.discovery_changed"
	AgentDiscoveryReappeared = "agent.discovery_reappeared"
	AgentDiscoveryVanished = "agent.discovery_vanished"
	AgentPromoted = "agent.promoted"
	AgentPromotionConfirmed = "agent.promotion_confirmed"
	AgentPromotionExpired = "agent.promotion_expired"
	AgentPromotionRevoked = "agent.promotion_revoked"
	AgentTaskTypeSet = "agent.task_type_set"
)
