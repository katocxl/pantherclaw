// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check migrations 00186 and 00187 (G0 M15 D11, D12): another
// org neither reads nor changes a gateway's replicas or MCP state, and
// cannot add rows to them for a gateway of another org.

func m15Gateway(t *testing.T, f m5Fixture) string {
	t.Helper()
	gw := m5ID()
	f.mustExec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, $3, 'test')", f.org, gw, "gw-"+gw[30:])
	return gw
}

func m15Connection(t *testing.T, f m5Fixture, gw string) string {
	t.Helper()
	conn := m5ID()
	f.mustExec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, created_by, updated_by)
		VALUES ($1, $2, $3, 'http', $4, 'pc.mock-payments', 'https://payments.example.test', 'none', 'test', 'test')`,
		f.org, conn, "c-"+conn[30:], gw)
	return conn
}

const (
	m15Replica = `INSERT INTO pc.gateway_replicas (org_id, gateway_id, replica_id, version, build, config_version, last_seen)
		VALUES ($1, $2, 'AAAAAAAAAAAAAAAAAAAAAA', '1.5.0', 'abc', 1, now())`
	m15Hold = `INSERT INTO pc.gateway_mcp_state (org_id, gateway_id, kind, key, connection_id, action_id, version, expire_time,
		update_time) VALUES ($1, $2, 'HOLD', $3, $4, 'act', 1, now() + interval '1 hour', now())`
)

// TestTenancy_gateway_replicas: another org sees no replica of an org's
// gateway, changes or deletes none, and cannot record one for it.
func TestTenancy_gateway_replicas(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	gw := m15Gateway(t, a)
	a.mustExec(t, m15Replica, a.org, gw)
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.gateway_replicas"); n != 0 {
		t.Fatalf("another org sees %d replicas", n)
	}
	b.mustExec(t, "UPDATE pc.gateway_replicas SET last_seen = now() - interval '2 days'")
	b.mustExec(t, "DELETE FROM pc.gateway_replicas")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.gateway_replicas WHERE last_seen > now() - interval '1 hour'"); n != 1 {
		t.Fatalf("another org changed or deleted the replica: %d left", n)
	}
	// The org write guard (00181) refuses it before row security would.
	b.want(t, "23514", "a replica in another org's name", m15Replica, a.org, gw)
	b.want(t, "23503", "a replica of another org's gateway", m15Replica, b.org, gw)
}

// TestTenancy_gateway_mcp_state: another org sees no MCP state of an org's
// gateway, changes or deletes none, and cannot write any for it.
func TestTenancy_gateway_mcp_state(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	gw := m15Gateway(t, a)
	conn := m15Connection(t, a, gw)
	a.mustExec(t, m15Hold, a.org, gw, m5Secret(1), conn)
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.gateway_mcp_state"); n != 0 {
		t.Fatalf("another org sees %d entries", n)
	}
	b.mustExec(t, "UPDATE pc.gateway_mcp_state SET action_id = 'forged', version = version + 1")
	b.mustExec(t, "DELETE FROM pc.gateway_mcp_state")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.gateway_mcp_state WHERE action_id = 'act' AND version = 1"); n != 1 {
		t.Fatalf("another org changed or deleted the entry: %d left", n)
	}
	// The org write guard (00181) refuses it before row security would.
	b.want(t, "23514", "an entry in another org's name", m15Hold, a.org, gw, m5Secret(2), conn)
	b.want(t, "23503", "an entry of another org's gateway", m15Hold, b.org, gw, m5Secret(3), conn)
}
