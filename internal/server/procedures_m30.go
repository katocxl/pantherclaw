// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m30Procedures are OwnedAccountService's procedures (G0 M30 D933). The
// service refuses any caller of Add or Remove but a person.
var m30Procedures = map[string]td.Permission{
	pantherclawv1connect.OwnedAccountServiceListOwnedAccountsProcedure:  td.PermOwnedAccountsRead,
	pantherclawv1connect.OwnedAccountServiceAddOwnedAccountProcedure:    td.PermOwnedAccountsManage,
	pantherclawv1connect.OwnedAccountServiceRemoveOwnedAccountProcedure: td.PermOwnedAccountsManage,
}

// m30Classes are their plan-gate classes: a lapsed org keeps reading the
// list and can still remove an account, which only makes shares hold;
// adding one loosens, so it is a change.
var m30Classes = map[string]entitlements.Class{
	pantherclawv1connect.OwnedAccountServiceListOwnedAccountsProcedure:  entitlements.ClassRead,
	pantherclawv1connect.OwnedAccountServiceAddOwnedAccountProcedure:    entitlements.ClassChange,
	pantherclawv1connect.OwnedAccountServiceRemoveOwnedAccountProcedure: entitlements.ClassSafety,
}

func init() {
	maps.Copy(procedurePermissions, m30Procedures)
	maps.Copy(procedureClasses, m30Classes)
}
