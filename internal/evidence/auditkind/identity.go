// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "identity.". The ledger stores each as "audit." + the kind.
const (
	IdentityEnrollmentTokenCreated = "identity.enrollment_token_created"
	IdentityInstanceAdmitted = "identity.instance_admitted"
	IdentityInstanceAutoAdmitted = "identity.instance_auto_admitted"
	IdentityInstanceEnrolled = "identity.instance_enrolled"
	IdentityInstanceRejected = "identity.instance_rejected"
	IdentityInstanceRevoked = "identity.instance_revoked"
	IdentityIssuerActivated = "identity.issuer_activated"
	IdentityIssuerDisabled = "identity.issuer_disabled"
	IdentityIssuerNarrowed = "identity.issuer_narrowed"
	IdentityIssuerProposed = "identity.issuer_proposed"
	IdentityIssuerWithdrawn = "identity.issuer_withdrawn"
	IdentityWorkloadDiscovered = "identity.workload_discovered"
)
