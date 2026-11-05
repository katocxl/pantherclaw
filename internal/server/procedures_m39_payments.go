// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m39PaymentsProcedures are PaymentsService's procedures (G0 M39 D1121,
// D1123). Changes need payments.manage, which only a person holds; reads
// and agent signature checks need payments.read (a person or a service
// credential bound to a role that holds it). Activation over the API is
// always refused (STEP_UP_REQUIRED). The use cases check the Business
// edition again.
var m39PaymentsProcedures = map[string]td.Permission{
	pantherclawv1connect.PaymentsServiceCreatePaymentTrustAnchorProcedure:   td.PermPaymentsManage,
	pantherclawv1connect.PaymentsServiceActivatePaymentTrustAnchorProcedure: td.PermPaymentsManage,
	pantherclawv1connect.PaymentsServiceRevokePaymentTrustAnchorProcedure:   td.PermPaymentsManage,
	pantherclawv1connect.PaymentsServiceListPaymentTrustAnchorsProcedure:    td.PermPaymentsRead,
	pantherclawv1connect.PaymentsServiceGetPaymentTrustAnchorProcedure:      td.PermPaymentsRead,
	pantherclawv1connect.PaymentsServiceVerifyAgentSignatureProcedure:       td.PermPaymentsRead,
}

// m39PaymentsClasses are their plan-gate classes: a lapsed org keeps
// reading and can still revoke an anchor, which only stops trust;
// creating and activating add trust, and a signature check records a
// nonce.
var m39PaymentsClasses = map[string]entitlements.Class{
	pantherclawv1connect.PaymentsServiceCreatePaymentTrustAnchorProcedure:   entitlements.ClassChange,
	pantherclawv1connect.PaymentsServiceActivatePaymentTrustAnchorProcedure: entitlements.ClassChange,
	pantherclawv1connect.PaymentsServiceRevokePaymentTrustAnchorProcedure:   entitlements.ClassSafety,
	pantherclawv1connect.PaymentsServiceListPaymentTrustAnchorsProcedure:    entitlements.ClassRead,
	pantherclawv1connect.PaymentsServiceGetPaymentTrustAnchorProcedure:      entitlements.ClassRead,
	pantherclawv1connect.PaymentsServiceVerifyAgentSignatureProcedure:       entitlements.ClassChange,
}

func init() {
	maps.Copy(procedurePermissions, m39PaymentsProcedures)
	maps.Copy(procedureClasses, m39PaymentsClasses)
}
