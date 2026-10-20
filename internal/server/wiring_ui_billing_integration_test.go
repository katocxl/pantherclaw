// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/extension"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR354_ExtensionBillingAuthorityAndAudit (D70): billing.manage is
// checked with the core's evaluation for the session principal, and the
// extension writes only billing. records without secrets.
func TestHR354_ExtensionBillingAuthorityAndAudit(t *testing.T) {
	d := dbtest.New(t)
	pool := d.AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	admin, viewer := ids.NewV7(), ids.NewV7()
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	for i, u := range []ids.UUID{admin, viewer} {
		exec(`INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)`, org, u, u.String())
		exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			org, ids.NewV7(), []string{"org_admin", "viewer"}[i], u)
	}
	as := func(user ids.UUID) context.Context {
		return extension.WithPrincipal(ctx, extension.Principal{OrgID: org.String(), UserID: user.String()})
	}
	az := extAuthorizer{pool: pool}
	if err := az.Require(as(admin), "billing.manage"); err != nil {
		t.Errorf("org admin: %v", err)
	}
	if err := az.Require(as(viewer), "billing.manage"); err == nil {
		t.Error("a viewer may manage billing")
	}
	if err := az.Require(as(viewer), "entitlements.read"); err != nil {
		t.Errorf("viewer reading the plan: %v", err)
	}
	if err := az.Require(as(admin), "billing.everything"); err == nil {
		t.Error("an unknown permission passed")
	}
	if err := az.Require(extension.WithPrincipal(ctx, extension.Principal{AccountID: ids.NewV7().String()}), "billing.manage"); err == nil {
		t.Error("an account session (no org) passed")
	}
	if err := az.Require(ctx, "billing.manage"); err == nil {
		t.Error("no principal passed")
	}
	exec("UPDATE pc.users SET state = 'DISABLED' WHERE org_id = $1 AND id = $2", org, admin)
	if err := az.Require(as(admin), "billing.manage"); err == nil {
		t.Error("a disabled user passed")
	}

	au := extAudit{pool: pool}
	if err := au.Record(as(viewer), org.String(), "billing.checkout_started", map[string]string{"plan_id": "team"}); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"not billing":   au.Record(ctx, org.String(), "tenancy.org_deleted", nil),
		"secret key":    au.Record(ctx, org.String(), "billing.x", map[string]string{"card_token": "tok"}),
		"platform org":  au.Record(ctx, ids.PlatformOrg.String(), "billing.x", nil),
		"not an org id": au.Record(ctx, "acme", "billing.x", nil),
	} {
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	var n int
	if err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*)::int FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.billing.checkout_started' AND actor_id = $2",
			org, viewer.String()).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("billing records by the viewer = %d", n)
	}
}
