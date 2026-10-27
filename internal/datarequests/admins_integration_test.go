// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package datarequests

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func TestHR390_DeletionSnapshotKeepsEveryLinkedAdministrator(t *testing.T) {
	d, s, org := setup(t)
	d.AdminExec(t, `INSERT INTO pc.accounts(id,issuer,subject,email,email_verified,display_name)
        SELECT gen_random_uuid(),'test','admin-'||i,'admin-'||i||'@example.com',true,'Admin'
        FROM generate_series(1,51) i`)
	d.AdminExec(t, `INSERT INTO pc.users(org_id,id,issuer,subject,email,display_name,account_id)
        SELECT $1,gen_random_uuid(),issuer,subject,email,display_name,id FROM pc.accounts WHERE issuer='test'`, org)
	d.AdminExec(t, `INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by)
        SELECT $1,gen_random_uuid(),'org_admin',id,'ORG','system:test' FROM pc.users WHERE org_id=$1`, org)
	if err := s.Pool.InTenantTx(t.Context(), org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		admins, err := deletionAdmins(ctx, q, org)
		if err != nil {
			return err
		}
		accounts, err := q.AccountsOfUsers(ctx, org, admins)
		if err != nil {
			return err
		}
		if len(admins) != 51 || len(accounts) != 51 {
			t.Fatalf("truncated ACL: users=%d accounts=%d", len(admins), len(accounts))
		}
		id, user, reason := ids.NewV7(), admins[0], "requested"
		now, err := q.TenantDatabaseTime(ctx)
		if err != nil {
			return err
		}
		return q.InsertDataRequest(ctx, dbq.InsertDataRequestParams{OrgID: org, ID: id, Kind: "DELETION", State: "PENDING", CreatedBy: &user, Reason: &reason, WindowEnd: &now, AdminAccounts: accounts})
	}); err != nil {
		t.Fatal(err)
	}
	var count int
	d.AdminQueryRow(t, "SELECT cardinality(admin_accounts) FROM pc.data_requests WHERE org_id=$1", []any{org}, &count)
	if count != 51 {
		t.Fatalf("stored ACL=%d", count)
	}
}

func TestHR390_DeletionAdministratorBoundRefusesInsteadOfTruncating(t *testing.T) {
	d, s, org := setup(t)
	d.AdminExec(t, `INSERT INTO pc.users(org_id,id,issuer,subject,email,display_name)
        SELECT $1,gen_random_uuid(),'test','admin-'||i,'admin-'||i||'@example.com','Admin'
        FROM generate_series(1,10001) i`, org)
	d.AdminExec(t, `INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by)
        SELECT $1,gen_random_uuid(),'org_admin',id,'ORG','system:test' FROM pc.users WHERE org_id=$1`, org)
	err := s.Pool.InTenantTx(t.Context(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := deletionAdmins(ctx, dbq.New(tx), org)
		return err
	})
	if !errors.Is(err, ErrAdminLimit) {
		t.Fatalf("oversized administrator set: %v", err)
	}
}
