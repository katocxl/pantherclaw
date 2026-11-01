// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m22RotationProcedures are CredentialRotationService's procedures (G0 M22
// D5, F831, HR-553), with the permissions the use cases require.
var m22RotationProcedures = map[string]td.Permission{
	pantherclawv1connect.CredentialRotationServiceRequestRotationProcedure:       td.PermConnectionManage,
	pantherclawv1connect.CredentialRotationServiceSealRotationCandidateProcedure: td.PermCredentialSeal,
	pantherclawv1connect.CredentialRotationServiceTestRotationProcedure:          td.PermConnectionManage,
	pantherclawv1connect.CredentialRotationServiceActivateRotationProcedure:      td.PermCredentialSeal,
	pantherclawv1connect.CredentialRotationServiceRollBackRotationProcedure:      td.PermCredentialSeal,
	pantherclawv1connect.CredentialRotationServiceConfirmRotationProcedure:       td.PermConnectionManage,
	pantherclawv1connect.CredentialRotationServiceCancelRotationProcedure:        td.PermConnectionManage,
	pantherclawv1connect.CredentialRotationServiceGetRotationProcedure:           td.PermConnectionRead,
	pantherclawv1connect.CredentialRotationServiceListRotationsProcedure:         td.PermConnectionRead,
}

// m22RotationClasses are its plan-gate classes: confirming removes the old
// key and canceling revokes a candidate, so a lapsed plan can always do them.
var m22RotationClasses = map[string]entitlements.Class{
	pantherclawv1connect.CredentialRotationServiceRequestRotationProcedure:       entitlements.ClassChange,
	pantherclawv1connect.CredentialRotationServiceSealRotationCandidateProcedure: entitlements.ClassChange,
	pantherclawv1connect.CredentialRotationServiceTestRotationProcedure:          entitlements.ClassChange,
	pantherclawv1connect.CredentialRotationServiceActivateRotationProcedure:      entitlements.ClassChange,
	pantherclawv1connect.CredentialRotationServiceRollBackRotationProcedure:      entitlements.ClassChange,
	pantherclawv1connect.CredentialRotationServiceConfirmRotationProcedure:       entitlements.ClassSafety,
	pantherclawv1connect.CredentialRotationServiceCancelRotationProcedure:        entitlements.ClassSafety,
	pantherclawv1connect.CredentialRotationServiceGetRotationProcedure:           entitlements.ClassRead,
	pantherclawv1connect.CredentialRotationServiceListRotationsProcedure:         entitlements.ClassRead,
}

func init() {
	maps.Copy(procedurePermissions, m22RotationProcedures)
	maps.Copy(procedureClasses, m22RotationClasses)
}
