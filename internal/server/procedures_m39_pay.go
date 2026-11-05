// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m39PayProcedures are PaymentCapService's procedures (G0 M39 D1124a,
// D1124c). Changes need payments.manage, which only a person holds; the
// use cases check that the caller is a person and the Business edition
// again. A cap becomes ACTIVE only through its two-person PAYMENT_CAP
// change request.
var m39PayProcedures = map[string]td.Permission{
	pantherclawv1connect.PaymentCapServiceProposePaymentCapProcedure:   td.PermPaymentsManage,
	pantherclawv1connect.PaymentCapServiceListPaymentCapsProcedure:     td.PermPaymentsRead,
	pantherclawv1connect.PaymentCapServiceRetirePaymentCapProcedure:    td.PermPaymentsManage,
	pantherclawv1connect.PaymentCapServiceSetMerchantAudienceProcedure: td.PermPaymentsManage,
}

// m39PayClasses are their plan-gate classes: retiring a cap only makes
// payments hold for a person again; proposing a cap and setting an
// audience add trust.
var m39PayClasses = map[string]entitlements.Class{
	pantherclawv1connect.PaymentCapServiceProposePaymentCapProcedure:   entitlements.ClassChange,
	pantherclawv1connect.PaymentCapServiceListPaymentCapsProcedure:     entitlements.ClassRead,
	pantherclawv1connect.PaymentCapServiceRetirePaymentCapProcedure:    entitlements.ClassSafety,
	pantherclawv1connect.PaymentCapServiceSetMerchantAudienceProcedure: entitlements.ClassChange,
}

func init() {
	maps.Copy(procedurePermissions, m39PayProcedures)
	maps.Copy(procedureClasses, m39PayClasses)
}
