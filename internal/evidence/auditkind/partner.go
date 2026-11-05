// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of MSSP partner access (G0 M38 D1100–D1102; HR-810..816).
// Link events are recorded in both the partner org and the customer org;
// partner.call, partner.summary_read and the session events in the
// customer org, with actor partner/<partner org>/<user>. The ledger
// stores each as "audit." + the kind.
const (
	PartnerCall              = "partner.call"
	PartnerLinkApproved      = "partner.link_approved"
	PartnerLinkDenied        = "partner.link_denied"
	PartnerLinkExpired       = "partner.link_expired"
	PartnerLinkRequested     = "partner.link_requested"
	PartnerLinkRevoked       = "partner.link_revoked"
	PartnerProposalAccepted  = "partner.proposal_accepted"
	PartnerProposalCreated   = "partner.proposal_created"
	PartnerProposalDeclined  = "partner.proposal_declined"
	PartnerProposalExpired   = "partner.proposal_expired"
	PartnerProposalWithdrawn = "partner.proposal_withdrawn"
	PartnerSessionEnded      = "partner.session_ended"
	PartnerSessionOpened     = "partner.session_opened"
	PartnerSummaryRead       = "partner.summary_read"
)
