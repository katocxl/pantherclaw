// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m35FederationProcedures are FederationService's procedures and the
// gateway's federation token and receipt calls (G0 M35 D1025). The service
// refuses any caller of a manage, confirm or issue but a person.
var m35FederationProcedures = map[string]td.Permission{
	pantherclawv1connect.FederationServiceGetFederationDocumentProcedure:   td.PermFederationRead,
	pantherclawv1connect.FederationServiceSetFederationEndpointProcedure:   td.PermFederationManage,
	pantherclawv1connect.FederationServiceRotateFederationKeyProcedure:     td.PermFederationManage,
	pantherclawv1connect.FederationServiceProposeFederationTrustProcedure:  td.PermFederationManage,
	pantherclawv1connect.FederationServiceConfirmFederationTrustProcedure:  td.PermFederationManage,
	pantherclawv1connect.FederationServiceRefreshFederationTrustProcedure:  td.PermFederationManage,
	pantherclawv1connect.FederationServiceRevokeFederationTrustProcedure:   td.PermFederationManage,
	pantherclawv1connect.FederationServiceListFederationTrustsProcedure:    td.PermFederationRead,
	pantherclawv1connect.FederationServiceGetFederationTrustProcedure:      td.PermFederationRead,
	pantherclawv1connect.FederationServiceCreateFederationListingProcedure: td.PermFederationManage,
	pantherclawv1connect.FederationServiceRetireFederationListingProcedure: td.PermFederationManage,
	pantherclawv1connect.FederationServiceListFederationListingsProcedure:  td.PermFederationRead,
	pantherclawv1connect.FederationServiceListFederatedPeerAgentsProcedure: td.PermFederationRead,
	pantherclawv1connect.FederationServiceIssueCrossOrgGrantProcedure:      td.PermGrantIssue,
	pantherclawv1connect.FederationServiceRevokeCrossOrgGrantProcedure:     td.PermGrantRevoke,
	pantherclawv1connect.FederationServiceListFederationReceiptsProcedure:  td.PermFederationRead,
	pantherclawv1connect.FederationServiceSignListingCardProcedure:         td.PermGatewayAuthorize,
	pantherclawv1connect.AuthorityServiceIssueFederationTokenProcedure:     td.PermGatewayDispatch,
	pantherclawv1connect.AuthorityServiceRecordFederationReceiptProcedure:  td.PermGatewayDispatch,
	pantherclawv1connect.AuthorityServiceStartFederatedCallProcedure:       td.PermGatewayAuthorize,
}

// m35FederationClasses are their plan-gate classes: a lapsed org keeps
// reading and can still revoke a trust, retire a listing or revoke a
// cross-org grant, which only narrows; every other change widens who may
// reach the org's agents. The Enterprise edition is checked again by the
// service (FEDERATION_EDITION).
var m35FederationClasses = map[string]entitlements.Class{
	pantherclawv1connect.FederationServiceGetFederationDocumentProcedure:   entitlements.ClassRead,
	pantherclawv1connect.FederationServiceSetFederationEndpointProcedure:   entitlements.ClassChange,
	pantherclawv1connect.FederationServiceRotateFederationKeyProcedure:     entitlements.ClassChange,
	pantherclawv1connect.FederationServiceProposeFederationTrustProcedure:  entitlements.ClassChange,
	pantherclawv1connect.FederationServiceConfirmFederationTrustProcedure:  entitlements.ClassChange,
	pantherclawv1connect.FederationServiceRefreshFederationTrustProcedure:  entitlements.ClassChange,
	pantherclawv1connect.FederationServiceRevokeFederationTrustProcedure:   entitlements.ClassSafety,
	pantherclawv1connect.FederationServiceListFederationTrustsProcedure:    entitlements.ClassRead,
	pantherclawv1connect.FederationServiceGetFederationTrustProcedure:      entitlements.ClassRead,
	pantherclawv1connect.FederationServiceCreateFederationListingProcedure: entitlements.ClassChange,
	pantherclawv1connect.FederationServiceRetireFederationListingProcedure: entitlements.ClassChange,
	pantherclawv1connect.FederationServiceListFederationListingsProcedure:  entitlements.ClassRead,
	pantherclawv1connect.FederationServiceListFederatedPeerAgentsProcedure: entitlements.ClassRead,
	pantherclawv1connect.FederationServiceIssueCrossOrgGrantProcedure:      entitlements.ClassChange,
	pantherclawv1connect.FederationServiceRevokeCrossOrgGrantProcedure:     entitlements.ClassSafety,
	pantherclawv1connect.FederationServiceListFederationReceiptsProcedure:  entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m35FederationProcedures)
	maps.Copy(procedureClasses, m35FederationClasses)
}
