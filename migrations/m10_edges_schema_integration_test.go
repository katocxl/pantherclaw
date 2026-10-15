// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR259_EdgesTablesKeepTargetsAndActivationsFixed (G0 M10 D35, D37;
// 00126, 00127): pc_app may never change a destination's URL, internal
// flag, data classes or creator, nor a transmitter's issuer, keys or
// audience; both are inserted PENDING, activated once by a person with a
// key, and DISABLED is final; a SIEM cursor never moves backwards; and
// every table has RLS forced.
func TestHR259_EdgesTablesKeepTargetsAndActivationsFixed(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	fixed := map[string][]string{
		"siem_destinations": {"id", "org_id", "name", "url", "internal", "data_classes", "format", "created_by", "created_at"},
		"ssf_transmitters":  {"id", "org_id", "name", "issuer", "jwks_uri", "audience", "created_by", "created_at"},
		"ssf_events":        {"id", "org_id", "transmitter_id", "jti", "event_type", "issued_at", "user_id", "match_basis", "outcome", "received_at", "expires_at"},
		"siem_batches":      {"id", "org_id", "destination_id", "from_seq", "to_seq", "event_count", "body_bytes", "created_at"},
		"siem_cursors":      {"org_id", "destination_id"},
	}
	for table, cols := range fixed {
		for _, c := range cols {
			var got bool
			if err := m.Pgx().QueryRow(ctx, `SELECT has_column_privilege('pc_app', 'pc.' || $1, $2, 'UPDATE')`, table, c).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got {
				t.Errorf("pc_app may UPDATE pc.%s.%s", table, c)
			}
		}
		var forced bool
		if err := m.Pgx().QueryRow(ctx, `SELECT relforcerowsecurity FROM pg_class WHERE oid = ('pc.' || $1)::regclass`, table).Scan(&forced); err != nil || !forced {
			t.Errorf("pc.%s: RLS forced %v (%v)", table, forced, err)
		}
	}
	for _, c := range []string{"secret", "prev_secret"} {
		var got bool
		if err := m.Pgx().QueryRow(ctx, `SELECT has_column_privilege('pc_audit_ro', 'pc.siem_destinations', $1, 'SELECT')`, c).Scan(&got); err != nil || got {
			t.Errorf("pc_audit_ro may read siem_destinations.%s: %v %v", c, got, err)
		}
	}

	p := d.AppPool(t)
	org, user, cred := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	exec := func(sql string, args ...any) error {
		return p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	must := func(sql string, args ...any) {
		t.Helper()
		if err := exec(sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	refused := func(name, sql string, args ...any) {
		t.Helper()
		if err := exec(sql, args...); err == nil {
			t.Errorf("%s was allowed", name)
		}
	}
	must("INSERT INTO pc.orgs (id, name) VALUES ($1, 'edges')", org)
	must("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'a')", org, user)
	must(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		org, cred, user, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))

	dest, secret := ids.NewV7(), bytes.Repeat([]byte{7}, 32)
	refused("a destination inserted ACTIVE", `INSERT INTO pc.siem_destinations (org_id, id, name, url, data_classes, secret, created_by, state)
		VALUES ($1, $2, 'd', 'https://siem.example.net/', '{alerts}', $3, 'x', 'ACTIVE')`, org, dest, secret)
	refused("a destination with an unknown data class", `INSERT INTO pc.siem_destinations (org_id, id, name, url, data_classes, secret, created_by)
		VALUES ($1, $2, 'd', 'https://siem.example.net/', '{payloads}', $3, 'x')`, org, dest, secret)
	refused("an http destination", `INSERT INTO pc.siem_destinations (org_id, id, name, url, data_classes, secret, created_by)
		VALUES ($1, $2, 'd', 'http://siem.example.net/', '{alerts}', $3, 'x')`, org, dest, secret)
	must(`INSERT INTO pc.siem_destinations (org_id, id, name, url, data_classes, secret, created_by)
		VALUES ($1, $2, 'd', 'https://siem.example.net/', '{alerts}', $3, 'x')`, org, dest, secret)
	refused("activation without a person", "UPDATE pc.siem_destinations SET state = 'ACTIVE' WHERE id = $1", dest)
	must("UPDATE pc.siem_destinations SET state = 'ACTIVE', activated_by = $2, activated_credential = $3 WHERE id = $1", dest, user, cred)
	refused("a second activation", "UPDATE pc.siem_destinations SET activated_by = $2, activated_credential = $2 WHERE id = $1", dest, ids.NewV7())
	refused("a return to PENDING", "UPDATE pc.siem_destinations SET state = 'PENDING' WHERE id = $1", dest)
	refused("a URL change", "UPDATE pc.siem_destinations SET url = 'https://evil.example/' WHERE id = $1", dest)
	must("INSERT INTO pc.siem_cursors (org_id, destination_id, seq) VALUES ($1, $2, 10)", org, dest)
	refused("a cursor moving back", "UPDATE pc.siem_cursors SET seq = 9 WHERE destination_id = $1", dest)
	must("UPDATE pc.siem_cursors SET seq = 11 WHERE destination_id = $1", dest)
	must("UPDATE pc.siem_destinations SET state = 'DISABLED' WHERE id = $1", dest)
	refused("re-enabling a disabled destination", "UPDATE pc.siem_destinations SET state = 'ACTIVE' WHERE id = $1", dest)

	tx := ids.NewV7()
	refused("a transmitter inserted ACTIVE", `INSERT INTO pc.ssf_transmitters (org_id, id, name, issuer, jwks_uri, audience, created_by, state)
		VALUES ($1, $2, 't', 'https://idp.example.com', 'https://idp.example.com/jwks', 'aud', 'x', 'ACTIVE')`, org, tx)
	must(`INSERT INTO pc.ssf_transmitters (org_id, id, name, issuer, jwks_uri, audience, created_by)
		VALUES ($1, $2, 't', 'https://idp.example.com', 'https://idp.example.com/jwks', 'aud', 'x')`, org, tx)
	refused("a key set change", "UPDATE pc.ssf_transmitters SET jwks_uri = 'https://evil.example/jwks' WHERE id = $1", tx)
	must("UPDATE pc.ssf_transmitters SET state = 'ACTIVE', activated_by = $2, activated_credential = $3 WHERE id = $1", tx, user, cred)
	must(`INSERT INTO pc.ssf_events (org_id, id, transmitter_id, jti, event_type, issued_at, outcome)
		VALUES ($1, $2, $3, 'j1', 'https://x', now(), 'IGNORED')`, org, ids.NewV7(), tx)
	refused("a replayed jti", `INSERT INTO pc.ssf_events (org_id, id, transmitter_id, jti, event_type, issued_at, outcome)
		VALUES ($1, $2, $3, 'j1', 'https://x', now(), 'IGNORED')`, org, ids.NewV7(), tx)
	refused("an accepted event without a person", `INSERT INTO pc.ssf_events (org_id, id, transmitter_id, jti, event_type, issued_at, outcome)
		VALUES ($1, $2, $3, 'j2', 'https://x', now(), 'ACCEPTED')`, org, ids.NewV7(), tx)

	var tables []string
	rows, err := m.Pgx().Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'pc' AND (tablename LIKE 'siem_%' OR tablename LIKE 'ssf_%')`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, n)
	}
	rows.Close()
	for n := range fixed {
		if !slices.Contains(tables, n) {
			t.Errorf("table pc.%s is missing", n)
		}
	}
}
