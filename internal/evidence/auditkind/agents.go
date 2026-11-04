// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "agents.". The ledger stores each as "audit." + the kind.
const (
	AgentsAgentClaimed = "agents.agent_claimed"
	AgentsAgentCreated = "agents.agent_created"
	AgentsAgentRetired = "agents.agent_retired"
	AgentsAgentSuspended = "agents.agent_suspended"
	AgentsAgentUpdated = "agents.agent_updated"
	AgentsDiscoveryReopened = "agents.discovery_reopened"
	AgentsExternalOwnerSet = "agents.external_owner_set"
	AgentsGithubScanSubmitted = "agents.github_scan_submitted"
	AgentsOwnershipTransferred = "agents.ownership_transferred"
	AgentsRiskUpdated = "agents.risk_updated"
	AgentsSaasImportSubmitted = "agents.saas_import_submitted"
	AgentsSaasScanSubmitted = "agents.saas_scan_submitted"
	AgentsScanDeviceLimit = "agents.scan_device_limit"
	AgentsScanSubmitted = "agents.scan_submitted"
)
