// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// scopedPackage is a package whose operation declares its credential scope
// (G0 M8 dispatch.credential_scope).
const scopedPackage = `{"definitions": [{"operation": "payments.refund.create",
	"dispatch": {"credential_scope": {"contents": "write", "metadata": "read"}}}]}`

func (f *fixture) refreshFindings(t *testing.T) []dbq.PcCoverageFinding {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return f.svc.RefreshFindings(ctx, tx, f.conn)
	}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := f.svc.ListFindings(f.as(td.RoleAuditor), nil, &f.conn, 10, "")
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestF048_CredentialReachBeyondTheNeedIsAFinding: a GitHub App
// installation the scan found for the connection, holding permissions its
// operations do not declare, is an open finding with the excess and its
// severity; reduced to the need it is resolved; a dismissal needs a
// person's written reason and survives the next refresh.
func TestF048_CredentialReachBeyondTheNeedIsAFinding(t *testing.T) {
	f := newFixture(t)
	version := ids.NewV7()
	f.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.1.0', $4, $5, 'ACTIVE')`, f.org, version, f.pkg, digest, []byte(scopedPackage))
	f.exec(t, `UPDATE pc.package_pins SET version_id = $2, version = '1.1.0' WHERE org_id = $1`, f.org, version)
	scanned, discovery := ids.NewV7(), ids.NewV7()
	f.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'App pantherclaw-ci', 'DISCOVERED', 'test')", f.org, scanned)
	observed := func(perms string) []byte {
		return []byte(`{"kind": "github_app", "connection": "` + f.conn.String() + `", "app_slug": "pantherclaw-ci", "permissions": "` + perms + `"}`)
	}
	f.exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed) VALUES ($1, $2, $3, 'scan', $4, $5)`,
		f.org, discovery, scanned, make([]byte, 32), observed("contents:write,administration:write,metadata:read"))
	rows := f.refreshFindings(t)
	if len(rows) != 1 || rows[0].State != "OPEN" || !slices.Equal(rows[0].Excess, []string{"administration:write"}) ||
		rows[0].Severity != "high" || !slices.Equal(rows[0].Declared, []string{"contents:write", "metadata:read"}) {
		t.Fatalf("findings %+v", rows)
	}
	f.exec(t, "UPDATE pc.discoveries SET observed = $2 WHERE id = $1", discovery, observed("contents:write,metadata:read"))
	if rows := f.refreshFindings(t); len(rows) != 1 || rows[0].State != "RESOLVED" {
		t.Fatalf("reduced to the need: %+v", rows)
	}
	f.exec(t, "UPDATE pc.discoveries SET observed = $2 WHERE id = $1", discovery, observed("contents:write,workflows:write"))
	rows = f.refreshFindings(t)
	if len(rows) != 1 || rows[0].State != "OPEN" || rows[0].Severity != "high" {
		t.Fatalf("reopened: %+v", rows)
	}
	if _, err := f.svc.DismissFinding(f.as(td.RoleSecurityAdmin), rows[0].ID, "ok"); !errors.Is(err, app.ErrDismissal) {
		t.Fatalf("a dismissal without a reason: %v", err)
	}
	if _, err := f.svc.DismissFinding(f.as(td.RoleAuditor), rows[0].ID, "Accepted for the pilot by the CISO."); err == nil {
		t.Fatal("an auditor dismissed a finding")
	}
	if _, err := f.svc.DismissFinding(f.as(td.RoleSecurityAdmin), rows[0].ID, "Accepted for the pilot by the CISO."); err != nil {
		t.Fatal(err)
	}
	if rows := f.refreshFindings(t); len(rows) != 1 || rows[0].State != "DISMISSED" {
		t.Fatalf("after a refresh: %+v", rows)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.coverage.finding_dismissed'`); n != 1 {
		t.Fatalf("%d audited dismissals", n)
	}
}
