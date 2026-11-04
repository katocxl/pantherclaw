// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "sandbox.". The ledger stores each as "audit." + the kind.
const (
	SandboxReportAccepted = "sandbox.report_accepted"
	SandboxReportRejected = "sandbox.report_rejected"
	SandboxRoutesReported = "sandbox.routes_reported"
	SandboxSessionEnded = "sandbox.session_ended"
	SandboxSessionExpired = "sandbox.session_expired"
	SandboxSessionStarted = "sandbox.session_started"
)
