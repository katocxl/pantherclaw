// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Governed automations and the rest of M11 (G0 M11 part 2 D12).
// automation.read sees automations, versions, executions and their
// identities, scoped like agent.read. Everything that writes is human only:
// an automation's own steps never author, publish, start, approve or
// promote anything (HR-279), and no API key or service account may.
//
//   - automation.manage: create automations, author versions, ask for
//     enabling, narrow, pause, resume, retire, revoke authority, cancel.
//   - automation.publish: confirm an enabling with a security key (with
//     every confirmer permission of the version's step kinds, HR-272).
//   - automation.run: start a manual execution.
//   - automation.approve: decide an automation gate (HR-281).
//   - automation.endpoints.manage: inbound event sources and destinations.
//   - agent.promote: promote an agent's operations for production (HR-290).
//   - cohort.manage: fleet cohorts and their baselines (HR-291).
//   - protected_change.manage: protected-change settings and confirming
//     protected changes (HR-292).
//   - publisher.compromise: mark and clear a compromised publisher (HR-293).
const (
	PermAutomationRead            Permission = "automation.read"
	PermAutomationManage          Permission = "automation.manage"
	PermAutomationPublish         Permission = "automation.publish"
	PermAutomationRun             Permission = "automation.run"
	PermAutomationApprove         Permission = "automation.approve"
	PermAutomationEndpointsManage Permission = "automation.endpoints.manage"
	PermAgentPromote              Permission = "agent.promote"
	PermCohortManage              Permission = "cohort.manage"
	PermProtectedChangeManage     Permission = "protected_change.manage"
	PermPublisherCompromise       Permission = "publisher.compromise"
)

// automationsCatalog are the M11 part 2 permissions in catalog order.
var automationsCatalog = []Permission{
	PermAutomationRead, PermAutomationManage, PermAutomationPublish, PermAutomationRun, PermAutomationApprove,
	PermAutomationEndpointsManage, PermAgentPromote, PermCohortManage, PermProtectedChangeManage, PermPublisherCompromise,
}

// automationsHumanOnly are every M11 part 2 permission but automation.read.
var automationsHumanOnly = []Permission{
	PermAutomationManage, PermAutomationPublish, PermAutomationRun, PermAutomationApprove,
	PermAutomationEndpointsManage, PermAgentPromote, PermCohortManage, PermProtectedChangeManage, PermPublisherCompromise,
}
