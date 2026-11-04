// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "policy.". The ledger stores each as "audit." + the kind.
const (
	PolicyChangeApproved                  = "policy.change_approved"
	PolicyChangeConfirmed                 = "policy.change_confirmed"
	PolicyChangeDeclined                  = "policy.change_declined"
	PolicyChangeRequested                 = "policy.change_requested"
	PolicyChangeVoided                    = "policy.change_voided"
	PolicyCohortCreated                   = "policy.cohort_created"
	PolicyCohortMembersAdded              = "policy.cohort_members_added"
	PolicyCohortMembersRemoved            = "policy.cohort_members_removed"
	PolicyExceptionActivated              = "policy.exception_activated"
	PolicyExceptionDeclined               = "policy.exception_declined"
	PolicyExceptionExpired                = "policy.exception_expired"
	PolicyExceptionGroupActivated         = "policy.exception_group_activated"
	PolicyExceptionGroupDeclined          = "policy.exception_group_declined"
	PolicyExceptionGroupExpired           = "policy.exception_group_expired"
	PolicyExceptionGroupRequested         = "policy.exception_group_requested"
	PolicyExceptionGroupRevoked           = "policy.exception_group_revoked"
	PolicyExceptionRequested              = "policy.exception_requested"
	PolicyExceptionRevoked                = "policy.exception_revoked"
	PolicyExternalCheckActivated          = "policy.external_check_activated"
	PolicyExternalCheckCreated            = "policy.external_check_created"
	PolicyExternalCheckDisabled           = "policy.external_check_disabled"
	PolicyExternalCheckEndpointNotAllowed = "policy.external_check_endpoint_not_allowed"
	PolicyExternalCheckTested             = "policy.external_check_tested"
	PolicyPublished                       = "policy.published"
	PolicyRolloutCancelled                = "policy.rollout_cancelled"
	PolicyRolloutPilotExpanded            = "policy.rollout_pilot_expanded"
	PolicyRolloutPilotStarted             = "policy.rollout_pilot_started"
	PolicyRolloutStarted                  = "policy.rollout_started"
	PolicyRolloutTargetExcluded           = "policy.rollout_target_excluded"
	PolicySimulationCanceled              = "policy.simulation_canceled"
	PolicySimulationRequested             = "policy.simulation_requested"
	PolicyVersionCreated                  = "policy.version_created"
)
