// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package externalchecks

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR438_OnlyCreateAndActivateNeedTheEdition: without the Business
// edition a Security Admin cannot create a check, but can still disable
// an existing one, which the next decision stops asking (D96a).
// Covers: F366
func TestHR438_OnlyCreateAndActivateNeedTheEdition(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	org, user, id := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'checks')", org)
	exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", org, user)
	exec(`INSERT INTO pc.external_policy_checks (org_id, id, name, endpoint, operations, created_by)
		VALUES ($1, $2, 'opa', 'https://opa.example.com/v1', '{stripe.*}', 'user:x')`, org, id)
	ctx := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}, Credential: tenancy.CredBrowserSession})
	s := New(p, Config{AllowedPrefixes: []string{"https://opa.example.com/"}}, nil, nil)
	if _, err := s.Create(ctx, NewCheck{Name: "other", Endpoint: "https://opa.example.com/v2", Operations: []string{"a.b"}}); !errors.Is(err, ErrEdition) {
		t.Fatalf("Create without the edition: %v", err)
	}
	c, err := s.Disable(ctx, id)
	if err != nil || c.State != StateDisabled {
		t.Fatalf("Disable without the edition: %+v %v", c, err)
	}
}
