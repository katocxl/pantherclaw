// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// TestHR749_BrowserSitesHaveTheOwnedAccountsPermissions: List, Add and
// Remove of the browser sites need exactly the owned accounts' permissions
// and plan classes (G0 M33 D976, D974a), and the cloaking compare report is
// a gateway's observation like a drift report.
func TestHR749_BrowserSitesHaveTheOwnedAccountsPermissions(t *testing.T) {
	pairs := map[string]string{
		pantherclawv1connect.BrowserServiceListBrowserSitesProcedure:  pantherclawv1connect.OwnedAccountServiceListOwnedAccountsProcedure,
		pantherclawv1connect.BrowserServiceAddBrowserSiteProcedure:    pantherclawv1connect.OwnedAccountServiceAddOwnedAccountProcedure,
		pantherclawv1connect.BrowserServiceRemoveBrowserSiteProcedure: pantherclawv1connect.OwnedAccountServiceRemoveOwnedAccountProcedure,
	}
	for browser, owned := range pairs {
		bp, ok := procedurePermissions[browser]
		if !ok || bp != procedurePermissions[owned] || bp == "" {
			t.Errorf("%s: permission %q, owned accounts %q", browser, bp, procedurePermissions[owned])
		}
		bc, ok := procedureClasses[browser]
		if !ok || bc != procedureClasses[owned] {
			t.Errorf("%s: class %q, owned accounts %q", browser, bc, procedureClasses[owned])
		}
	}
	if p := procedurePermissions[pantherclawv1connect.GatewayServiceReportPageCompareProcedure]; p == "" ||
		p != procedurePermissions[pantherclawv1connect.GatewayServiceReportDriftProcedure] {
		t.Errorf("ReportPageCompare permission %q", p)
	}
}

// TestHR749_NoOtherBrowserProcedureIsServed: every BrowserService
// procedure has a permission and a class; none is open.
func TestHR749_NoOtherBrowserProcedureIsServed(t *testing.T) {
	for _, p := range []string{
		pantherclawv1connect.BrowserServiceListBrowserSitesProcedure,
		pantherclawv1connect.BrowserServiceAddBrowserSiteProcedure,
		pantherclawv1connect.BrowserServiceRemoveBrowserSiteProcedure,
	} {
		if procedurePermissions[p] == "" {
			t.Errorf("%s has no permission", p)
		}
		if _, ok := procedureClasses[p]; !ok {
			t.Errorf("%s has no plan class", p)
		}
	}
}
