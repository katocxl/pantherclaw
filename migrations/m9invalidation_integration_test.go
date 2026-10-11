// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// These tests check the coverage invalidation triggers and the reassess
// lister (G0 M9 slice A5, migration 00087).

// m9iKinds returns the kinds of the connection's invalidations, oldest first,
// and checks that each id is a UUIDv7.
func (f m9cFixture) m9iKinds(t *testing.T) []string {
	t.Helper()
	var kinds []string
	err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, `SELECT id, kind FROM pc.coverage_invalidations WHERE connection_id = $1 ORDER BY id`, f.connection)
		if err != nil {
			return err
		}
		type row struct {
			id   string
			kind string
		}
		got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.kind)
		})
		for _, x := range got {
			if _, err := ids.Parse[ids.Org](x.id); err != nil {
				t.Errorf("invalidation id %s is not a UUIDv7", x.id)
			}
			kinds = append(kinds, x.kind)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return kinds
}

// TestHR211_EveryChangeIsRecordedAsAnInvalidation: a change to a
// connection, its gateway, route modes, credentials or package pin records
// an invalidation in the same transaction; a change that does not affect
// coverage records none.
func TestHR211_EveryChangeIsRecordedAsAnInvalidation(t *testing.T) {
	f := newM9cFixture(t)
	steps := []struct {
		name, want string
		sql        string
		args       []any
	}{
		{"timeout only", "", "UPDATE pc.connections SET timeout_ms = 5000 WHERE id = $1", []any{f.connection}},
		{"target", "connection", "UPDATE pc.connections SET base_url = 'https://api2.example.com' WHERE id = $1", []any{f.connection}},
		{"access mode", "connection", "UPDATE pc.connections SET access_mode = 'agent_held' WHERE id = $1", []any{f.connection}},
		{"default mode", "route_mode", "UPDATE pc.connections SET default_mode = 'enforce' WHERE id = $1", []any{f.connection}},
		{"a route's mode", "route_mode", `INSERT INTO pc.connection_routes (org_id, connection_id, route, mode, changed_by)
			VALUES ($1, $2, 'refunds', 'monitor', 'test')`, []any{f.org, f.connection}},
		{"the same mode again", "", "UPDATE pc.connection_routes SET mode = 'monitor' WHERE connection_id = $1", []any{f.connection}},
		{"another gateway", "gateway", "UPDATE pc.connections SET gateway_id = $2 WHERE id = $1", []any{f.connection, f.gateway2(t)}},
		{"the gateway revoked", "gateway", "UPDATE pc.gateways SET state = 'REVOKED', revoked_by = 'test', revoked_at = now() WHERE id = (SELECT gateway_id FROM pc.connections WHERE id = $1)", []any{f.connection}},
		{"a new package version", "package_version", "UPDATE pc.package_pins SET version_id = $1, version = '1.0.1'", []any{f.version2(t)}},
		{"a credential sealed", "credential", m6Credential, []any{f.org, m5ID(), f.connection, 1, f.brokerKey(t), m6Bytes(1200, 1)}},
		{"a credential revoked", "credential", "UPDATE pc.credentials SET state = 'REVOKED', revoked_by = 'test', revoked_at = now()", nil},
		{"quarantined", "connection", "UPDATE pc.connections SET state = 'QUARANTINED', quarantine_reason = 'circuit_open' WHERE id = $1", []any{f.connection}},
	}
	// The fixture pinned the package: that is the first one.
	want := []string{"package_version"}
	if got := f.m9iKinds(t); !slices.Equal(got, want) {
		t.Fatalf("after the fixture: %v", got)
	}
	for _, s := range steps {
		f.mustExec(t, s.sql, s.args...)
		if s.want != "" {
			want = append(want, s.want)
		}
		if got := f.m9iKinds(t); !slices.Equal(got, want) {
			t.Fatalf("after %s: invalidations %v, want %v", s.name, got, want)
		}
	}
}

func (f m9cFixture) gateway2(t *testing.T) string {
	t.Helper()
	id := m5ID()
	f.mustExec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge-2', 'test')", f.org, id)
	return id
}

func (f m9cFixture) version2(t *testing.T) string {
	t.Helper()
	id := m5ID()
	f.mustExec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		SELECT org_id, $2, package_id, '1.0.1', $3, '\x7b7d', 'ACTIVE' FROM pc.package_pins WHERE org_id = $1`, f.org, id, m9cDigest)
	return id
}

// brokerKey is the fixture gateway's active broker key.
func (f m9cFixture) brokerKey(t *testing.T) string {
	t.Helper()
	var id ids.UUID
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.broker_keys WHERE gateway_id = $1 AND state = 'ACTIVE'", f.gateway).Scan(&id)
	}); err != nil {
		t.Fatal(err)
	}
	return id.String()
}

// TestIntCoverageReassessListerFindsDueOrgs: the lister lists an org with a
// pending invalidation and one with an expired current ENFORCED snapshot,
// and not an org with nothing to reassess.
func TestIntCoverageReassessListerFindsDueOrgs(t *testing.T) {
	f := newM9cFixture(t)
	listed := func() bool {
		refs, err := f.p.CrossOrgList(context.Background(), "coverage_reassess", 10000)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(refs, func(r db.OrgRef) bool { return r.Org == f.org })
	}
	if !listed() {
		t.Fatal("an org whose package was pinned is not listed")
	}
	f.mustExec(t, "UPDATE pc.coverage_invalidations SET reassessed_at = now()")
	if listed() {
		t.Fatal("an org with nothing to reassess is listed")
	}
	f.mustExec(t, "UPDATE pc.connections SET base_url = 'https://api2.example.com' WHERE id = $1", f.connection)
	if !listed() {
		t.Fatal("an org with a pending invalidation is not listed")
	}
	f.mustExec(t, "UPDATE pc.coverage_invalidations SET reassessed_at = now()")
	closure, err := f.closure("PASSED", true, "0 seconds", "24 hours")
	if err != nil {
		t.Fatal(err)
	}
	f.mustExec(t, `INSERT INTO pc.coverage_snapshots (org_id, id, agent_id, connection_id, operation, state, reasons, closure_id,
		body, body_sha256, ledger_entry_id, computed_at, expires_at) VALUES ($1, $2, $3, $4, 'payments.refund.create',
		'ENFORCED', '{}', $5, '{}', `+m5Hash+`, $6, now() - interval '2 days', now() - interval '1 day')`,
		f.org, m5ID(), f.agent, f.connection, closure, f.ledger(t))
	if !listed() {
		t.Fatal("an org with an expired ENFORCED snapshot is not listed")
	}
}
