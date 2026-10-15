// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package assurance proves an automation before and while it runs (G0 M11
// part 2, coordinator decisions D34–D38): scenario tests and the TESTED
// gate, historical simulation and forecasts, shadow and cohort rollout
// evidence, automation exposure and the blast-radius preview, and the
// operations view of automation exceptions and outcomes.
package assurance

import "github.com/katocxl/pantherclaw/internal/operations"

// Owned failure kinds an automation raises (D38). Each routes to the
// automation's owner and queues as an AUTOMATION_EXCEPTION; routine
// success never notifies or pages.
const (
	FailureLaunchBlocked       = operations.AutomationFailurePrefix + "launch_blocked"
	FailureGateStalled         = operations.AutomationFailurePrefix + "gate_stalled"
	FailureContainmentFailed   = operations.AutomationFailurePrefix + "containment_failed"
	FailureRecoveryFailed      = operations.AutomationFailurePrefix + "recovery_failed"
	FailureAuthorityChanged    = operations.AutomationFailurePrefix + "authority_changed"
	FailureLoopStopped         = operations.AutomationFailurePrefix + "loop_stopped"
	FailureNeedsReconciliation = operations.AutomationFailurePrefix + "needs_reconciliation"
	FailureLimitReached        = operations.AutomationFailurePrefix + "limit_reached"
	FailureReviewDue           = operations.AutomationFailurePrefix + "review_due"
)

// FailureKinds lists every D38 kind.
var FailureKinds = []string{
	FailureLaunchBlocked, FailureGateStalled, FailureContainmentFailed, FailureRecoveryFailed, FailureAuthorityChanged,
	FailureLoopStopped, FailureNeedsReconciliation, FailureLimitReached, FailureReviewDue,
}

// Thresholds of the derived failures (D38).
const (
	// GateStalledShare is the share of a gate's deadline after which an
	// undecided gate is stalled.
	GateStalledShare = 0.5
	// RecoveryFailedRun is how many consecutive FAILED executions make a
	// recovery failure.
	RecoveryFailedRun = 3
)
