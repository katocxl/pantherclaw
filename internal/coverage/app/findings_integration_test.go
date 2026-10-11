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
// installation the scan found for the connection, holding permissions the
// operations the org's grants allow do not declare, is an open finding with
// the excess, its severity and the scopes of the operations executed in
// the last 30 days; reduced to the need it is resolved; another excess is
// a new finding; a dismissal needs a person's written reason and survives
// the next refresh until the excess changes. Dismissing the discovery
// itself hides nothing: the reach is still there.
func TestF048_CredentialReachBeyondTheNeedIsAFinding(t *testing.T) {
	f := newFixture(t)
	f.grant(t, "payments.refund.create")
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
	txn, permit := ids.NewV7(), ids.NewV7()
	f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, channel, mode) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'OK', 'gw', $6,
		'http', 'enforce')`, f.org, txn, f.run, ids.NewV7(), make([]byte, 32), f.conn)
	f.exec(t, `INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, state, expires_at, dispatching_at, finished_at)
		VALUES ($1, $2, $3, 'gw', 1, 'DISPATCHED', now() + interval '5 seconds', now(), now())`, f.org, permit, txn)
	f.exec(t, `INSERT INTO pc.execution_attempts (org_id, id, permit_id, transaction_id, outcome, target_status, target_ref)
		VALUES ($1, $2, $3, $4, 'accepted', 200, 're_1')`, f.org, ids.NewV7(), permit, txn)
	rows := f.refreshFindings(t)
	if len(rows) != 1 || rows[0].State != "OPEN" || !slices.Equal(rows[0].Excess, []string{"administration:write"}) ||
		rows[0].Severity != "high" || !slices.Equal(rows[0].Declared, []string{"contents:write", "metadata:read"}) ||
		!slices.Equal(rows[0].Used, rows[0].Declared) {
		t.Fatalf("findings %+v", rows)
	}
	f.exec(t, "UPDATE pc.discoveries SET observed = $2 WHERE id = $1", discovery, observed("contents:write,metadata:read"))
	if rows := f.refreshFindings(t); len(rows) != 1 || rows[0].State != "RESOLVED" {
		t.Fatalf("reduced to the need: %+v", rows)
	}
	f.exec(t, "UPDATE pc.discoveries SET observed = $2 WHERE id = $1", discovery, observed("contents:write,workflows:write"))
	rows = f.refreshFindings(t)
	if len(rows) != 2 || rows[0].State != "OPEN" || rows[0].Severity != "high" ||
		!slices.Equal(rows[0].Excess, []string{"workflows:write"}) || rows[1].State != "RESOLVED" {
		t.Fatalf("another excess: %+v", rows)
	}
	if _, err := f.svc.AcknowledgeFinding(f.as(td.RoleSecurityAdmin), rows[0].ID, "ok"); !errors.Is(err, app.ErrDismissal) {
		t.Fatalf("a dismissal without a reason: %v", err)
	}
	if _, err := f.svc.AcknowledgeFinding(f.as(td.RoleAuditor), rows[0].ID, "Accepted for the pilot by the CISO."); err == nil {
		t.Fatal("an auditor dismissed a finding")
	}
	if _, err := f.svc.AcknowledgeFinding(f.as(td.RoleSecurityAdmin), rows[0].ID, "Accepted for the pilot by the CISO."); err != nil {
		t.Fatal(err)
	}
	if rows := f.refreshFindings(t); len(rows) != 2 || rows[0].State != "DISMISSED" {
		t.Fatalf("after a refresh: %+v", rows)
	}
	f.exec(t, "UPDATE pc.discoveries SET observed = $2 WHERE id = $1", discovery, observed("contents:write,workflows:write,administration:write"))
	if rows := f.refreshFindings(t); len(rows) != 3 || rows[0].State != "OPEN" || rows[1].State != "DISMISSED" {
		t.Fatalf("a dismissed finding whose excess grew: %+v", rows)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.coverage.finding_dismissed'`); n != 1 {
		t.Fatalf("%d audited dismissals", n)
	}
	f.exec(t, "UPDATE pc.discoveries SET state = 'DISMISSED' WHERE id = $1", discovery)
	if rows := f.refreshFindings(t); len(rows) != 3 || rows[0].State != "OPEN" {
		t.Fatalf("after the discovery was dismissed: %+v", rows)
	}
}
