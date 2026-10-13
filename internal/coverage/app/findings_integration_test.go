// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"
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

// TestF048_CredentialReachBeyondTheNeedIsAFinding: the GitHub App
// installation behind the connection, as last read, holding permissions the
// operations the org's grants allow do not declare, is an open finding with
// the excess, its severity and the scopes of the operations executed in
// the last 30 days; reduced to the need it is resolved; another excess is
// a new finding; a dismissal needs a person's written reason and survives
// the next refresh until the excess changes, and a dismissed exposure found
// again after it went away is open again. (G0 M8 G3,
// connection_github).
func TestF048_CredentialReachBeyondTheNeedIsAFinding(t *testing.T) {
	f := newFixture(t)
	f.grant(t, "payments.refund.create")
	version := ids.NewV7()
	f.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.1.0', $4, $5, 'ACTIVE')`, f.org, version, f.pkg, digest, []byte(scopedPackage))
	f.exec(t, `UPDATE pc.package_pins SET version_id = $2, version = '1.1.0' WHERE org_id = $1`, f.org, version)
	installed := func(perms string) []byte {
		m := map[string]string{}
		for _, p := range strings.Split(perms, ",") {
			k, v, _ := strings.Cut(p, ":")
			m[k] = v
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	f.exec(t, `INSERT INTO pc.connection_github (org_id, connection_id, app_client_id, installation_id, account_login, permissions,
		repository_selection, read_at, updated_by) VALUES ($1, $2, 'Iv1.ci', 7, 'acme', $3, 'all', now(), 'test')`,
		f.org, f.conn, installed("contents:write,administration:write,metadata:read"))
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
	f.exec(t, "UPDATE pc.connection_github SET permissions = $2 WHERE connection_id = $1", f.conn, installed("contents:write,metadata:read"))
	if rows := f.refreshFindings(t); len(rows) != 1 || rows[0].State != "RESOLVED" {
		t.Fatalf("reduced to the need: %+v", rows)
	}
	f.exec(t, "UPDATE pc.connection_github SET permissions = $2 WHERE connection_id = $1", f.conn, installed("contents:write,workflows:write"))
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
	f.exec(t, "UPDATE pc.connection_github SET permissions = $2 WHERE connection_id = $1", f.conn, installed("contents:write,workflows:write,administration:write"))
	if rows := f.refreshFindings(t); len(rows) != 3 || rows[0].State != "OPEN" || rows[1].State != "RESOLVED" {
		t.Fatalf("a dismissed finding whose excess grew: %+v", rows)
	}
	// The dismissed exposure went away; found again later, it is open again.
	f.exec(t, "UPDATE pc.connection_github SET permissions = $2 WHERE connection_id = $1", f.conn, installed("contents:write,workflows:write"))
	if rows := f.refreshFindings(t); len(rows) != 3 || rows[1].State != "OPEN" || rows[0].State != "RESOLVED" {
		t.Fatalf("a dismissed exposure found again: %+v", rows)
	}
	if n := f.count(t, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.coverage.finding_dismissed'`); n != 1 {
		t.Fatalf("%d audited dismissals", n)
	}
}

// TestF048_TheConnectionsOwnInstallationIsReach: only the GitHub App
// installation behind the connection, as last read (G0 M8 G3), is compared
// with the need. The org's other Apps that the org scan found (source
// github_scan, one finding per App on the organization) are routes of their
// own, not this credential, and a GitHub App a person's pclaw scan reports
// (source scan) counts for nothing (N20).
func TestF048_TheConnectionsOwnInstallationIsReach(t *testing.T) {
	f := newFixture(t)
	f.grant(t, "payments.refund.create")
	version := ids.NewV7()
	f.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.1.0', $4, $5, 'ACTIVE')`, f.org, version, f.pkg, digest, []byte(scopedPackage))
	f.exec(t, `UPDATE pc.package_pins SET version_id = $2, version = '1.1.0' WHERE org_id = $1`, f.org, version)
	f.exec(t, `INSERT INTO pc.connection_github (org_id, connection_id, app_client_id, installation_id, account_login, permissions,
		repository_selection, read_at, updated_by) VALUES ($1, $2, 'Iv1.abc', 42, 'acme', $3, 'all', now(), 'test')`,
		f.org, f.conn, []byte(`{"contents": "write", "metadata": "read", "administration": "write"}`))
	scanned := ids.NewV7()
	f.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'App other', 'DISCOVERED', 'test')", f.org, scanned)
	f.exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed) VALUES ($1, $2, $3, 'github_scan', $4, $5)`,
		f.org, ids.NewV7(), scanned, make([]byte, 32), []byte(`{"kind": "github_app", "connection": "`+f.conn.String()+
			`", "app_slug": "other", "permissions": "contents:write,secrets:write"}`))
	forged := ids.NewV7()
	f.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'App forged', 'DISCOVERED', 'test')", f.org, forged)
	f.exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed) VALUES ($1, $2, $3, 'scan', $4, $5)`,
		f.org, ids.NewV7(), forged, append(forged[:], make([]byte, 16)...), []byte(`{"kind": "github_app", "connection": "`+f.conn.String()+
			`", "app_slug": "forged", "permissions": "administration:admin"}`))
	rows := f.refreshFindings(t)
	subjects := map[string][]string{}
	for _, r := range rows {
		subjects[r.Subject] = r.Excess
	}
	if len(rows) != 1 || !slices.Equal(subjects["GitHub App installation 42 on acme"], []string{"administration:write"}) {
		t.Fatalf("findings %+v", rows)
	}
	f.exec(t, `UPDATE pc.connection_github SET permissions = '{"contents": "write"}' WHERE connection_id = $1`, f.conn)
	if rows := f.refreshFindings(t); len(rows) != 1 || rows[0].State != "RESOLVED" {
		t.Fatalf("the installation reduced to the need: %+v", rows)
	}
}
