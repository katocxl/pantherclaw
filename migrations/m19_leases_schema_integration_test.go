// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// This test checks migration 00226 (G0 M19 D201): another org neither
// reads nor changes an org's stream leases, and cannot take one in its
// name.

const m19Lease = `INSERT INTO pc.stream_leases (org_id, kind, key, id, holder, expires_at)
	VALUES ($1, 'OPS_STREAM', 'principal', $2, 'replica-a', now() + interval '30 seconds')`

// TestTenancy_stream_leases: another org sees no lease of an org, renews
// or deletes none, and cannot insert one for it.
// Covers: HR-491
func TestTenancy_stream_leases(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	a.mustExec(t, m19Lease, a.org, m5ID())
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.stream_leases"); n != 0 {
		t.Fatalf("another org sees %d leases", n)
	}
	b.mustExec(t, "UPDATE pc.stream_leases SET expires_at = now() + interval '1 day'")
	b.mustExec(t, "DELETE FROM pc.stream_leases")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.stream_leases WHERE expires_at < now() + interval '1 minute'"); n != 1 {
		t.Fatalf("another org changed or deleted the lease: %d left", n)
	}
	// The org write guard (00181) refuses it before row security would.
	b.want(t, "23514", "a lease in another org's name", m19Lease, a.org, m5ID())
	a.want(t, "23514", "an unknown kind", "INSERT INTO pc.stream_leases (org_id, kind, key, id, holder, expires_at) VALUES ($1, 'OTHER', 'k', $2, 'h', now())", a.org, m5ID())
}
