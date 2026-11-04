// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "automation.". The ledger stores each as "audit." + the kind.
//
//nolint:gosec // G101: audit kind names, not credentials
const (
	AutomationAuthorityRevoked              = "automation.authority_revoked"
	AutomationCeilingEnded                  = "automation.ceiling_ended"
	AutomationCreated                       = "automation.created"
	AutomationDestinationActivated          = "automation.destination_activated"
	AutomationDestinationCreated            = "automation.destination_created"
	AutomationDestinationSecretRotated      = "automation.destination_secret_rotated"
	AutomationDestinationSignatureSchemeSet = "automation.destination_signature_scheme_set"
	AutomationDestinationStateChanged       = "automation.destination_state_changed"
	AutomationEnableRequested               = "automation.enable_requested"
	AutomationEnabled                       = "automation.enabled"
	AutomationEventReceived                 = "automation.event_received"
	AutomationEventSourceActivated          = "automation.event_source_activated"
	AutomationEventSourceCreated            = "automation.event_source_created"
	AutomationEventSourceDisabled           = "automation.event_source_disabled"
	AutomationEventSourceSecretRotated      = "automation.event_source_secret_rotated"
	AutomationExecutionCancelRequested      = "automation.execution_cancel_requested"
	AutomationExecutionFinished             = "automation.execution_finished"
	AutomationExecutionStarted              = "automation.execution_started"
	AutomationLaunchClaimed                 = "automation.launch_claimed"
	AutomationLaunchCompleted               = "automation.launch_completed"
	AutomationOwnerChanged                  = "automation.owner_changed"
	AutomationPaused                        = "automation.paused"
	AutomationProposalDecided               = "automation.proposal_decided"
	AutomationResumed                       = "automation.resumed"
	AutomationRetired                       = "automation.retired"
	AutomationRolloutNarrowed               = "automation.rollout_narrowed"
	AutomationRolloutWidened                = "automation.rollout_widened"
	AutomationSimulationStarted             = "automation.simulation_started"
	AutomationStepFinished                  = "automation.step_finished"
	AutomationTestsRun                      = "automation.tests_run"
	AutomationTestsSet                      = "automation.tests_set"
	AutomationTriggerRefused                = "automation.trigger_refused"
	AutomationTriggered                     = "automation.triggered"
	AutomationVersionCreated                = "automation.version_created"
	AutomationVersionUpdated                = "automation.version_updated"
	AutomationVersionValidated              = "automation.version_validated"
)
