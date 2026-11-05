// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m37BundleProcedures are BundleService's procedures (G0 M37 D1081–D1083).
// Pins need publisher.manage, which only a person holds; installs and
// revocations bundle.install; reads bundle.read. Activation over the API
// is always refused (STEP_UP_REQUIRED).
var m37BundleProcedures = map[string]td.Permission{
	pantherclawv1connect.BundleServicePinPublisherKeyProcedure:      td.PermPublisherManage,
	pantherclawv1connect.BundleServiceListPublisherPinsProcedure:    td.PermBundleRead,
	pantherclawv1connect.BundleServiceGetPublisherPinProcedure:      td.PermBundleRead,
	pantherclawv1connect.BundleServiceActivatePublisherPinProcedure: td.PermPublisherManage,
	pantherclawv1connect.BundleServiceRevokePublisherPinProcedure:   td.PermPublisherManage,
	pantherclawv1connect.BundleServiceInstallBundleProcedure:        td.PermBundleInstall,
	pantherclawv1connect.BundleServiceListBundleInstallsProcedure:   td.PermBundleRead,
	pantherclawv1connect.BundleServiceGetBundleInstallProcedure:     td.PermBundleRead,
	pantherclawv1connect.BundleServiceRevokeBundleInstallProcedure:  td.PermBundleInstall,
	pantherclawv1connect.BundleServiceSubmitRevocationProcedure:     td.PermBundleInstall,
}

// m37BundleClasses are their plan-gate classes: a lapsed org keeps reading
// and can still revoke, which only stops use; pinning, activating and
// installing add trust.
var m37BundleClasses = map[string]entitlements.Class{
	pantherclawv1connect.BundleServicePinPublisherKeyProcedure:      entitlements.ClassChange,
	pantherclawv1connect.BundleServiceListPublisherPinsProcedure:    entitlements.ClassRead,
	pantherclawv1connect.BundleServiceGetPublisherPinProcedure:      entitlements.ClassRead,
	pantherclawv1connect.BundleServiceActivatePublisherPinProcedure: entitlements.ClassChange,
	pantherclawv1connect.BundleServiceRevokePublisherPinProcedure:   entitlements.ClassSafety,
	pantherclawv1connect.BundleServiceInstallBundleProcedure:        entitlements.ClassChange,
	pantherclawv1connect.BundleServiceListBundleInstallsProcedure:   entitlements.ClassRead,
	pantherclawv1connect.BundleServiceGetBundleInstallProcedure:     entitlements.ClassRead,
	pantherclawv1connect.BundleServiceRevokeBundleInstallProcedure:  entitlements.ClassSafety,
	pantherclawv1connect.BundleServiceSubmitRevocationProcedure:     entitlements.ClassSafety,
}

func init() {
	maps.Copy(procedurePermissions, m37BundleProcedures)
	maps.Copy(procedureClasses, m37BundleClasses)
}
