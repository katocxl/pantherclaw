// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/connections/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestF346_CapabilitiesAreReadThroughTheService: a reader gets the
// declaration of a connection from its org's pinned package and its route
// modes as stored, SUPPORTED enforcement only once every route is enforced;
// a caller without connection.read is refused, and
// another org's connection is NotFound.
func TestF346_CapabilitiesAreReadThroughTheService(t *testing.T) {
	e := newEnv(t)
	c := e.payments(t, "payments")
	if _, err := e.svc.SetRouteMode(e.admin, c.ID, "payments-refund", app.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Capabilities(e.caller(td.KindUser, td.RoleDeveloper), c.ID)
	if err != nil || got.Enforcement.Level != app.Partial || len(got.Operations) != 2 || got.Operations[0].Mode != app.ModeEnforce ||
		got.Operations[1].Mode != app.ModeMonitor || len(got.Permissions) != 2 || !strings.Contains(got.Enforcement.Detail, "1 of 2 routes") {
		t.Fatalf("capabilities %+v %v", got, err)
	}
	if _, err := e.svc.SetRouteMode(e.admin, c.ID, "payments-refund-get", app.ModeEnforce); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.Capabilities(e.admin, c.ID); err != nil || got.Enforcement.Level != app.Supported {
		t.Fatalf("every route enforced: %+v %v", got.Enforcement, err)
	}
	if _, err := e.svc.Capabilities(e.caller(td.KindUser, td.RoleFactProvider), c.ID); !denied(err) {
		t.Errorf("without connection.read: %v", err)
	}
	theirs := e.withOrg(t).payments(t, "payments")
	if _, err := e.svc.Capabilities(e.admin, theirs.ID); !is(err, app.ErrNotFound) {
		t.Errorf("another org's: %v", err)
	}
}
