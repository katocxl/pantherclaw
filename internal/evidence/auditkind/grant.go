// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds under "grant.". The ledger stores each as "audit." + the kind.
const (
	GrantDelegateRefused = "grant.delegate_refused"
	GrantDelegated       = "grant.delegated"
	GrantIssueRefused    = "grant.issue_refused"
	GrantIssued          = "grant.issued"
	GrantRevised         = "grant.revised"
	GrantRevoked         = "grant.revoked"
)
