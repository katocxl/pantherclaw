// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateways/app"
)

// TestHR392_GatewaysOfADeletedOrgFailClosed: once its org is DELETED (D22),
// a gateway's valid certificate no longer authenticates and an unused
// enrollment token no longer enrolls, before any of the org's rows are
// removed.
func TestHR392_GatewaysOfADeletedOrgFailClosed(t *testing.T) {
	e := newEnv(t)
	_, id := e.enroll(t, "edge")
	g, err := e.svc.CreateGateway(e.admin, "edge-2")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := e.svc.CreateEnrollmentToken(e.admin, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := e.svc.Authenticate(ctx, id); err != nil {
		t.Fatalf("before deletion: %v", err)
	}
	e.exec(t, "UPDATE pc.orgs SET state = 'DELETED' WHERE id = $1", e.org)
	fresh := app.New(e.pool, e.svc.CA(), "", nil) // no cache
	if err := fresh.Authenticate(ctx, id); !errors.Is(err, app.ErrGatewayCredentials) {
		t.Fatalf("a gateway of a deleted org authenticates: %v", err)
	}
	if _, err := fresh.Enroll(ctx, tok.Secret.Reveal(), csr(t)); !errors.Is(err, app.ErrEnrollment) {
		t.Fatalf("a gateway enrolls into a deleted org: %v", err)
	}
}
