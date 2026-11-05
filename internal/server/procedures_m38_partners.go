// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m38PartnerProcedures are PartnerService's procedures (G0 M38 D1100–D1102,
// D1100a). Deciding a link and opening a partner session are refused over
// the API (STEP_UP_REQUIRED): they happen on their pages. ProposeRollout
// and GetCurrentPartnerSession declare authenticated: the use cases admit a
// partner session (PROPOSE scope) or a person of the partner org holding
// partner.manage, and only a partner session, respectively.
var m38PartnerProcedures = map[string]td.Permission{
	pantherclawv1connect.PartnerServiceRequestPartnerLinkProcedure:       td.PermPartnerManage,
	pantherclawv1connect.PartnerServiceRenewPartnerLinkProcedure:         td.PermPartnerManage,
	pantherclawv1connect.PartnerServiceListPartnerLinksProcedure:         td.PermPartnerRead,
	pantherclawv1connect.PartnerServiceGetPartnerLinkProcedure:           td.PermPartnerRead,
	pantherclawv1connect.PartnerServiceDecidePartnerLinkProcedure:        td.PermPartnerApprove,
	pantherclawv1connect.PartnerServiceRevokePartnerLinkProcedure:        td.PermPartnerApprove,
	pantherclawv1connect.PartnerServiceListPartnerCustomersProcedure:     td.PermPartnerRead,
	pantherclawv1connect.PartnerServiceOpenPartnerSessionProcedure:       td.PermPartnerOperate,
	pantherclawv1connect.PartnerServiceGetCurrentPartnerSessionProcedure: td.PermAuthenticated,
	pantherclawv1connect.PartnerServiceProposeRolloutProcedure:           td.PermAuthenticated,
	pantherclawv1connect.PartnerServiceListPartnerProposalsProcedure:     td.PermPartnerRead,
	pantherclawv1connect.PartnerServiceGetPartnerProposalProcedure:       td.PermPartnerRead,
	pantherclawv1connect.PartnerServiceAcceptPartnerProposalProcedure:    td.PermPolicyAuthor,
	pantherclawv1connect.PartnerServiceDeclinePartnerProposalProcedure:   td.PermPolicyAuthor,
	pantherclawv1connect.PartnerServiceWithdrawPartnerProposalProcedure:  td.PermPartnerManage,
}

// m38PartnerClasses are their plan-gate classes: a lapsed org keeps
// reading and can still revoke a link, which only takes access away;
// everything that opens access or drafts is a change.
var m38PartnerClasses = map[string]entitlements.Class{
	pantherclawv1connect.PartnerServiceRequestPartnerLinkProcedure:       entitlements.ClassChange,
	pantherclawv1connect.PartnerServiceRenewPartnerLinkProcedure:         entitlements.ClassChange,
	pantherclawv1connect.PartnerServiceListPartnerLinksProcedure:         entitlements.ClassRead,
	pantherclawv1connect.PartnerServiceGetPartnerLinkProcedure:           entitlements.ClassRead,
	pantherclawv1connect.PartnerServiceDecidePartnerLinkProcedure:        entitlements.ClassChange,
	pantherclawv1connect.PartnerServiceRevokePartnerLinkProcedure:        entitlements.ClassSafety,
	pantherclawv1connect.PartnerServiceListPartnerCustomersProcedure:     entitlements.ClassRead,
	pantherclawv1connect.PartnerServiceOpenPartnerSessionProcedure:       entitlements.ClassChange,
	pantherclawv1connect.PartnerServiceGetCurrentPartnerSessionProcedure: entitlements.ClassRead,
	pantherclawv1connect.PartnerServiceProposeRolloutProcedure:           entitlements.ClassChange,
	pantherclawv1connect.PartnerServiceListPartnerProposalsProcedure:     entitlements.ClassRead,
	pantherclawv1connect.PartnerServiceGetPartnerProposalProcedure:       entitlements.ClassRead,
	pantherclawv1connect.PartnerServiceAcceptPartnerProposalProcedure:    entitlements.ClassChange,
	pantherclawv1connect.PartnerServiceDeclinePartnerProposalProcedure:   entitlements.ClassChange,
	pantherclawv1connect.PartnerServiceWithdrawPartnerProposalProcedure:  entitlements.ClassChange,
}

func init() {
	maps.Copy(procedurePermissions, m38PartnerProcedures)
	maps.Copy(procedureClasses, m38PartnerClasses)
}
