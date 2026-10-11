// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// as is a context whose caller holds role r at org scope.
func (f *fixture) as(r td.RoleName) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: f.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.user},
			Bindings: []td.Binding{{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: f.org.UUID()}}},
		},
		Credential: tenancy.CredAccessToken,
	})
}

// TestIntClosuresAreReadWithCoverageRead: a holder of coverage.read gets a
// closure with what it closed; a viewer does not.
func TestIntClosuresAreReadWithCoverageRead(t *testing.T) {
	f := newFixture(t)
	id, err := f.record(t, f.closure(probes(false), f.dbNow(t)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.GetClosure(f.as(td.RoleAuditor), id)
	if err != nil || len(got.Verdict.Closed) != len(domain.ContainmentKinds) || len(got.Probes) != len(probes(false)) {
		t.Fatalf("closure %+v (%v)", got, err)
	}
	list, next, err := f.svc.ListClosures(f.as(td.RoleSecurityAdmin), app.Filter{Agent: &f.agent}, 10, "")
	if err != nil || len(list) != 1 || list[0].ID != id || next != "" {
		t.Fatalf("list = %v %q (%v)", list, next, err)
	}
	if _, err := f.svc.GetClosure(f.as(td.RoleViewer), id); !errors.Is(err, td.ErrPermissionDenied(td.PermCoverageRead)) {
		t.Fatalf("a viewer read a closure: %v", err)
	}
	if _, err := f.svc.GetClosure(f.as(td.RoleAuditor), f.agent); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("an unknown closure: %v", err)
	}
}
