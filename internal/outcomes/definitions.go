// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package outcomes is the outcome metrics (G0 M21 D303, F774; Business): the
// six measures M1 to M6, rolled up nightly into pc.outcome_metric_samples.
//
// A metric is a distribution of durations or a share. There is no count
// kind, so a raw volume can never stand for value (HR-539), and no time
// saved is claimed. A window with no measured case is not collected, never 0
// (HR-537), a containment is counted only once confirmed (HR-538), and every
// read states its scope, as-of time and what it could not see (HR-540).
// History is not backfilled: a window that began before the org's collection
// started is not collected.
package outcomes

import (
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Kind says what a metric's value is.
type Kind string

// Kinds. Every metric is one of these two (HR-539).
const (
	KindDuration Kind = "DURATION"
	KindShare    Kind = "SHARE"
)

// DefinitionSignedOff marks a definition the founder signed off (G17).
const DefinitionSignedOff = "SIGNED_OFF"

// ScopeOrganization is what a sample covers (HR-540).
const ScopeOrganization = "organization"

// Metric names.
const (
	MetricProtectedWorkTime   = "protected_work.time"
	MetricExplanationShare    = "explanation.delivered_share"
	MetricExplanationTime     = "explanation.time"
	MetricContainmentTime     = "containment.time"
	MetricRequestedToConfirm  = "containment.requested_to_confirmed"
	MetricApprovalWait        = "friction.approval_wait"
	MetricHoldShare           = "friction.hold_share"
	MetricOverrideShare       = "friction.override_share"
	MetricValidatedShare      = "assurance.validated_share"
	MetricTestedShare         = "assurance.tested_share"
	MetricSimulatedShare      = "assurance.simulated_share"
	MetricStagedShare         = "assurance.staged_share"
	MetricFailedTargetShare   = "assurance.failed_target_share"
	MetricEvidenceShare       = "automation.evidence_share"
	MetricNoEvidenceShare     = "automation.no_evidence_share"
	MetricPartialShare        = "automation.partial_share"
	MetricFailedShare         = "automation.failed_share"
	MetricReconciliationShare = "automation.reconciliation_share"
	MetricCancelledShare      = "automation.cancelled_share"
	MetricInterventionShare   = "automation.intervention_share"
	MetricCompensationShare   = "automation.compensation_share"
	MetricRevertedShare       = "automation.reverted_share"
)

// Definition is one metric: what it measures, what it cannot see and whose
// read permissions its sources need across the organization.
type Definition struct {
	Name     string
	Group    string
	Kind     Kind
	Title    string
	Measures string
	NotSeen  []string
	Status   string
	Reads    []td.Permission
}

var (
	readsDecisions   = []td.Permission{td.PermEvidenceRead}
	readsContainment = []td.Permission{td.PermCaseRead, td.PermIncidentRead}
	readsChanges     = []td.Permission{td.PermPolicyRead, td.PermAutomationRead}
	readsAutomations = []td.Permission{td.PermAutomationRead}

	notSeenM1 = []string{
		"Agents enrolled before collection started.",
		"Agents with no enforced decision yet, counted as open with their age.",
		"Routes never enforced in the window.",
	}
	notSeenM2Delivery = []string{
		"Delivery to the agent itself: a decision counts when the Authority answered with its explanation.",
		"Refusals at a gateway before the Authority was asked.",
	}
	notSeenM2Time = []string{
		"Reads before collection started.",
		"Decisions nobody opened, shown as unread with their age.",
		"Refusals that never reached a person.",
	}
	notSeenM3 = []string{
		"Alerts with no incident or case, which name no containment.",
		"Grant revokes and suspensions not linked to a case.",
		"Kill-switch episodes before the history table.",
		"Unsupported or failed actions, listed and never counted as contained.",
		"A declared incident without a confirmed action, listed and never counted as contained.",
	}
	notSeenM4Wait = []string{
		"Re-queued approvals from before collection, whose first approval time was overwritten.",
	}
	notSeenM4Hold = []string{
		"Retries: there is no chain between the transactions of a retry.",
		"An agent giving up, which is unknowable.",
	}
	notSeenM4Override = []string{
		"A decision's rule is not stored in a column: an exception matches on the agent and the operation.",
		"DENYs less than 7 days old, whose follow-up is still running.",
		"Retries, and an agent giving up.",
	}
	notSeenM5 = []string{
		"Emergency and break-glass changes, listed separately.",
		"Rollout stage history from before collection.",
		"Downstream verification where it is not configured.",
	}
	notSeenM6 = []string{
		"Reverts not linked to an execution.",
		"SHADOW and TEST runs, which are excluded.",
	}
)

// Definitions lists every metric, in display order. Each stays a draft
// until the founder signs it off in the M21 brief (G17).
var Definitions = []Definition{
	{
		Name: MetricProtectedWorkTime, Group: "M1", Kind: KindDuration, Title: "Time to protected work",
		Measures: "Per agent, from its first enrolment to its first non-simulated decision in enforce mode.",
		NotSeen:  notSeenM1, Status: DefinitionSignedOff, Reads: readsDecisions,
	},
	{
		Name: MetricExplanationShare, Group: "M2", Kind: KindShare, Title: "Explanations delivered with the decision",
		Measures: "The share of non-ALLOW decisions answered with their agent-safe explanation in the same response.",
		NotSeen:  notSeenM2Delivery, Status: DefinitionSignedOff, Reads: readsDecisions,
	},
	{
		Name: MetricExplanationTime, Group: "M2", Kind: KindDuration, Title: "Time to explanation",
		Measures: "From a non-ALLOW decision to the first read of its evidence by a person with access.",
		NotSeen:  notSeenM2Time, Status: DefinitionSignedOff, Reads: readsDecisions,
	},
	{
		Name: MetricContainmentTime, Group: "M3", Kind: KindDuration, Title: "Time to containment",
		Measures: "From the earliest of alert, incident or case to the first confirmed containment for it.",
		NotSeen:  notSeenM3, Status: DefinitionSignedOff, Reads: readsContainment,
	},
	{
		Name: MetricRequestedToConfirm, Group: "M3", Kind: KindDuration, Title: "Requested to confirmed",
		Measures: "From a response action's request to its confirmation. A request is never a confirmation.",
		NotSeen:  notSeenM3, Status: DefinitionSignedOff, Reads: readsContainment,
	},
	{
		Name: MetricApprovalWait, Group: "M4", Kind: KindDuration, Title: "Approval wait",
		Measures: "From an approval request to its first decision.",
		NotSeen:  notSeenM4Wait, Status: DefinitionSignedOff, Reads: readsDecisions,
	},
	{
		Name: MetricHoldShare, Group: "M4", Kind: KindShare, Title: "Hold rate",
		Measures: "Held decisions over decisions in enforce mode.",
		NotSeen:  notSeenM4Hold, Status: DefinitionSignedOff, Reads: readsDecisions,
	},
	{
		Name: MetricOverrideShare, Group: "M4", Kind: KindShare, Title: "Override rate",
		Measures: "DENYs followed within 7 days by an activated exception for the same agent and operation.",
		NotSeen:  notSeenM4Override, Status: DefinitionSignedOff, Reads: readsDecisions,
	},
	{
		Name: MetricValidatedShare, Group: "M5", Kind: KindShare, Title: "Published after validation",
		Measures: "The share of versions published in the window that passed validation first. Shown apart from the other checks, never as one score.",
		NotSeen:  notSeenM5, Status: DefinitionSignedOff, Reads: readsChanges,
	},
	{
		Name: MetricTestedShare, Group: "M5", Kind: KindShare, Title: "Published after a scenario test",
		Measures: "The share of versions published in the window that passed a scenario test first.",
		NotSeen:  notSeenM5, Status: DefinitionSignedOff, Reads: readsChanges,
	},
	{
		Name: MetricSimulatedShare, Group: "M5", Kind: KindShare, Title: "Published after a simulation",
		Measures: "The share of versions published in the window that had a finished simulation first.",
		NotSeen:  notSeenM5, Status: DefinitionSignedOff, Reads: readsChanges,
	},
	{
		Name: MetricStagedShare, Group: "M5", Kind: KindShare, Title: "Published through a staged rollout",
		Measures: "The share of policy versions published in the window through a staged rollout. Automation rollouts keep no stage history, so they are not collected.",
		NotSeen:  notSeenM5, Status: DefinitionSignedOff, Reads: readsChanges,
	},
	{
		Name: MetricFailedTargetShare, Group: "M5", Kind: KindShare, Title: "Rollout targets that failed",
		Measures: "The share of targets of rollouts started in the window that reached FAILED.",
		NotSeen:  notSeenM5, Status: DefinitionSignedOff, Reads: readsChanges,
	},
	{
		Name: MetricEvidenceShare, Group: "M6", Kind: KindShare, Title: "Completed with evidence",
		Measures: "Per automation, the share of live executions ended in the window that completed with evidence. No time saved is claimed.",
		NotSeen:  notSeenM6, Status: DefinitionSignedOff, Reads: readsAutomations,
	},
	{
		Name: MetricNoEvidenceShare, Group: "M6", Kind: KindShare, Title: "Completed without evidence",
		Measures: "Per automation, the share of live executions ended in the window that succeeded without evidence.",
		NotSeen:  notSeenM6, Status: DefinitionSignedOff, Reads: readsAutomations,
	},
	{
		Name: MetricPartialShare, Group: "M6", Kind: KindShare, Title: "Partly completed",
		Measures: "Per automation, the share of live executions ended in the window that partly completed.",
		NotSeen:  notSeenM6, Status: DefinitionSignedOff, Reads: readsAutomations,
	},
	{
		Name: MetricFailedShare, Group: "M6", Kind: KindShare, Title: "Failed",
		Measures: "Per automation, the share of live executions ended in the window that failed.",
		NotSeen:  notSeenM6, Status: DefinitionSignedOff, Reads: readsAutomations,
	},
	{
		Name: MetricReconciliationShare, Group: "M6", Kind: KindShare, Title: "Needs reconciliation",
		Measures: "Per automation, the share of live executions ended in the window that need reconciliation.",
		NotSeen:  notSeenM6, Status: DefinitionSignedOff, Reads: readsAutomations,
	},
	{
		Name: MetricCancelledShare, Group: "M6", Kind: KindShare, Title: "Cancelled", //nolint:misspell // the state's name, British spelling as in ARCHITECTURE §6.2
		Measures: "Per automation, the share of live executions ended in the window that were cancelled.", //nolint:misspell // the state's name, British spelling as in ARCHITECTURE §6.2
		NotSeen:  notSeenM6, Status: DefinitionSignedOff, Reads: readsAutomations,
	},
	{
		Name: MetricInterventionShare, Group: "M6", Kind: KindShare, Title: "Interventions",
		Measures: "Per automation, the share of live executions ended in the window that a person decided a gate of.",
		NotSeen:  notSeenM6, Status: DefinitionSignedOff, Reads: readsAutomations,
	},
	{
		Name: MetricCompensationShare, Group: "M6", Kind: KindShare, Title: "Compensation rate",
		Measures: "Per automation, the share of live executions ended in the window that ran compensation.",
		NotSeen:  notSeenM6, Status: DefinitionSignedOff, Reads: readsAutomations,
	},
	{
		Name: MetricRevertedShare, Group: "M6", Kind: KindShare, Title: "Reverted by a person",
		Measures: "Per automation, the share of live executions ended in the window with an action a person later reverted.",
		NotSeen:  notSeenM6, Status: DefinitionSignedOff, Reads: readsAutomations,
	},
}

// DefinitionOf returns the named metric's definition.
func DefinitionOf(name string) (Definition, bool) {
	for _, d := range Definitions {
		if d.Name == name {
			return d, true
		}
	}
	return Definition{}, false
}
