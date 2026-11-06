// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package capture_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/capture"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR695_ACaptureProfileCannotNameAModelConnection: a profile on an
// http connection is created; one naming a model connection, alone or
// beside another, is refused and nothing is stored (G0 M29 D820).
//
// Covers: F980, HR-695
func TestHR695_ACaptureProfileCannotNameAModelConnection(t *testing.T) {
	p := dbtest.New(t).AppPool(t)
	org, gw, web, llm, user := ids.New[ids.Org](), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	ctx := context.Background()
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for _, s := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", []any{org}},
			{"INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", []any{org, gw}},
			{"INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'manager')", []any{org, user}},
			{`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, created_by, updated_by)
				VALUES ($1, $2, 'payments', 'http', $3, 'pc.mock-payments', 'https://payments.example', 'none', 'test', 'test')`, []any{org, web, gw}},
			{`INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, created_by, updated_by)
				VALUES ($1, $2, 'llm', 'model', $3, 'pc.anthropic', 'https://api.anthropic.com/v1', 'pantherclaw_held', 'test', 'test')`, []any{org, llm, gw}},
		} {
			if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	as := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: td.RoleRecordsManager, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}, Credential: tenancy.CredAccessToken})
	svc := &capture.Service{Pool: p}
	req := func(conns ...ids.UUID) capture.ProfileRequest {
		return capture.ProfileRequest{
			Purpose: "dispute investigation", Connections: conns, Operations: []string{"anthropic.messages.create", "payments.refund.create"},
			Request: true, Response: true, ByteCap: 4096, RetentionDays: 7, ExpiresInDays: 30,
		}
	}
	for name, conns := range map[string][]ids.UUID{"model": {llm}, "model beside http": {web, llm}} {
		if _, err := svc.CreateProfile(as, req(conns...)); !errors.Is(err, capture.ErrModelCapture) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := svc.CreateProfile(as, req(web)); err != nil {
		t.Fatalf("http: %v", err)
	}
	var n int
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.capture_profiles").Scan(&n)
	}); err != nil || n != 1 {
		t.Fatalf("%d profiles stored, %v", n, err)
	}
}
