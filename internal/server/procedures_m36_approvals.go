// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m36ApprovalProcedures are approval reach's procedures (G0 M36
// D1063..D1066). None of them approves anything; the services check each
// caller again (another person's deputy needs waitlist.manage; preferences
// and push subscriptions are always the caller's own).
var m36ApprovalProcedures = map[string]td.Permission{
	pantherclawv1connect.ApprovalServiceGetApprovalFatigueProcedure:               td.PermWaitlistRead,
	pantherclawv1connect.ApprovalServiceSetApprovalFatigueRoutingProcedure:        td.PermWaitlistManage,
	pantherclawv1connect.ApprovalServiceSetApprovalDeputyProcedure:                td.PermApprovalRespond,
	pantherclawv1connect.ApprovalServiceCancelApprovalDeputyProcedure:             td.PermApprovalRespond,
	pantherclawv1connect.ApprovalServiceListApprovalDeputiesProcedure:             td.PermAuthenticated,
	pantherclawv1connect.ApprovalServiceListApprovalGroupsProcedure:               td.PermAuthenticated,
	pantherclawv1connect.NotificationServiceGetMyNotificationPreferencesProcedure: td.PermAuthenticated,
	pantherclawv1connect.NotificationServiceSetMyNotificationPreferencesProcedure: td.PermAuthenticated,
	pantherclawv1connect.NotificationServiceGetWebPushKeyProcedure:                td.PermAuthenticated,
	pantherclawv1connect.NotificationServiceRegisterPushSubscriptionProcedure:     td.PermAuthenticated,
	pantherclawv1connect.NotificationServiceRemovePushSubscriptionProcedure:       td.PermAuthenticated,
	pantherclawv1connect.NotificationServiceListMyPushSubscriptionsProcedure:      td.PermAuthenticated,
}

// m36ApprovalClasses are their plan-gate classes: a lapsed org keeps
// reading, cancelling a deputy and removing a push subscription, which
// only narrow who is told; the rest are changes.
var m36ApprovalClasses = map[string]entitlements.Class{
	pantherclawv1connect.ApprovalServiceGetApprovalFatigueProcedure:               entitlements.ClassRead,
	pantherclawv1connect.ApprovalServiceSetApprovalFatigueRoutingProcedure:        entitlements.ClassChange,
	pantherclawv1connect.ApprovalServiceSetApprovalDeputyProcedure:                entitlements.ClassChange,
	pantherclawv1connect.ApprovalServiceCancelApprovalDeputyProcedure:             entitlements.ClassSafety,
	pantherclawv1connect.ApprovalServiceListApprovalDeputiesProcedure:             entitlements.ClassRead,
	pantherclawv1connect.ApprovalServiceListApprovalGroupsProcedure:               entitlements.ClassRead,
	pantherclawv1connect.NotificationServiceGetMyNotificationPreferencesProcedure: entitlements.ClassRead,
	pantherclawv1connect.NotificationServiceSetMyNotificationPreferencesProcedure: entitlements.ClassChange,
	pantherclawv1connect.NotificationServiceGetWebPushKeyProcedure:                entitlements.ClassRead,
	pantherclawv1connect.NotificationServiceRegisterPushSubscriptionProcedure:     entitlements.ClassChange,
	pantherclawv1connect.NotificationServiceRemovePushSubscriptionProcedure:       entitlements.ClassSafety,
	pantherclawv1connect.NotificationServiceListMyPushSubscriptionsProcedure:      entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m36ApprovalProcedures)
	maps.Copy(procedureClasses, m36ApprovalClasses)
}
