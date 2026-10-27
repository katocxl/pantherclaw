// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check migration 00185 (v0.1.0 known limit, D24 follow-up).
// Names are prefixed v010 so that they never collide with other
// milestones' schema tests in this package.

func (f m5Fixture) v010Revision(t *testing.T, test string) (revision *int32) {
	t.Helper()
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT connection_revision FROM pc.connection_tests WHERE id = $1", test).Scan(&revision)
	}); err != nil {
		t.Fatal(err)
	}
	return revision
}

// TestTenancy_connection_tests_revision: a connection test records the
// revision of its own org's connection at insert, whatever the caller
// sends, and pc_app cannot change it afterwards; a test of another org's
// connection cannot be recorded (that org's row is invisible, so no
// revision is found), and another org sees nothing.
func TestTenancy_connection_tests_revision(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	_, conn := m8cConnection(t, a)
	d.AdminExec(t, "UPDATE pc.connections SET revision = 3 WHERE id = $1", conn)

	task, test := m5ID(), m5ID()
	a.mustExec(t, m7Verification, a.org, task, "connection_test", nil, conn, nil, nil)
	a.mustExec(t, m8cLeasedTest, a.org, test, conn, "target_verifier", task, "payments.refund.get")
	if r := a.v010Revision(t, test); r == nil || *r != 3 {
		t.Fatalf("recorded revision %v, want 3", r)
	}
	// A caller cannot name another revision.
	forged := m5ID()
	a.mustExec(t, `INSERT INTO pc.connection_tests (org_id, id, connection_id, kind, state, result, checks, requested_by, finished_at,
		connection_revision) VALUES ($1, $2, $3, 'credential', 'DONE', 'PASSED', '[]', 'test', now(), 99)`, a.org, forged, conn)
	if r := a.v010Revision(t, forged); r == nil || *r != 3 {
		t.Fatalf("a forged revision was kept: %v", r)
	}
	// A later change of the connection leaves the recorded revision.
	d.AdminExec(t, "UPDATE pc.connections SET revision = 4 WHERE id = $1", conn)
	if r := a.v010Revision(t, test); r == nil || *r != 3 {
		t.Fatalf("the recorded revision moved: %v", r)
	}
	a.want(t, m5Denied, "change the recorded revision", "UPDATE pc.connection_tests SET connection_revision = 4 WHERE id = $1", test)

	// Another org: sees nothing, changes nothing, cannot test our connection.
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.connection_tests"); n != 0 {
		t.Fatalf("another org sees %d tests", n)
	}
	b.want(t, "23503", "a test of another org's connection", m8cCredentialTest, b.org, m5ID(), conn)
	b.want(t, m5Denied, "another org changes the revision", "UPDATE pc.connection_tests SET connection_revision = 1")
	if r := a.v010Revision(t, test); r == nil || *r != 3 {
		t.Fatalf("another org changed our revision: %v", r)
	}
}
