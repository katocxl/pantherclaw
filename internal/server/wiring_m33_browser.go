// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/browsersites/adapters/browserrpc"
	bsapp "github.com/katocxl/pantherclaw/internal/browsersites/app"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// m33BrowserProcedures are BrowserService's procedures (G0 M33 D976), with
// the owned accounts' permissions, and the gateway's cloaking compare
// report (D986). The service refuses any caller of Add or Remove but a
// person.
var m33BrowserProcedures = map[string]td.Permission{
	pantherclawv1connect.BrowserServiceListBrowserSitesProcedure:  td.PermOwnedAccountsRead,
	pantherclawv1connect.BrowserServiceAddBrowserSiteProcedure:    td.PermOwnedAccountsManage,
	pantherclawv1connect.BrowserServiceRemoveBrowserSiteProcedure: td.PermOwnedAccountsManage,
	pantherclawv1connect.GatewayServiceReportPageCompareProcedure: "gateway.observe",
}

// m33BrowserClasses are their plan-gate classes, as the owned accounts':
// a lapsed org keeps reading the list and can still remove a site, which
// only makes browser actions hold; adding one loosens, so it is a change.
var m33BrowserClasses = map[string]entitlements.Class{
	pantherclawv1connect.BrowserServiceListBrowserSitesProcedure:  entitlements.ClassRead,
	pantherclawv1connect.BrowserServiceAddBrowserSiteProcedure:    entitlements.ClassChange,
	pantherclawv1connect.BrowserServiceRemoveBrowserSiteProcedure: entitlements.ClassSafety,
}

func init() {
	maps.Copy(procedurePermissions, m33BrowserProcedures)
	maps.Copy(procedureClasses, m33BrowserClasses)
}

// registerM33Browser serves BrowserService (G0 M33 D976) and holds every
// addition to the site list behind the Gate.
func registerM33Browser(rs *connect.Server, d apiDeps) {
	svc := &bsapp.Service{Pool: d.pool}
	svc.RegisterProtect(d.m11protect.gate)
	pantherclawv1connect.RegisterBrowserServiceHandler(rs, browserrpc.New(svc))
}

// browserPageCompares records the gateways' cloaking compare reports (G0
// M33 D986), throttled in this server's memory.
func browserPageCompares(pool *db.Pool) *bsapp.Compares { return &bsapp.Compares{Pool: pool} }
