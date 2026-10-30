// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const m20Destination = `INSERT INTO pc.export_destinations (org_id, id, name, kind, url, bucket, region, data_classes, secret, created_by)
	VALUES ($1, $2, 'd', 's3', 'https://s3.example.net', 'bkt', 'eu-west-1', '{evidence_packs}', $3, 'x')`

// TestHR513_ExportDestinationsKeepTargetsAndActivationsFixed (G0 M20 D252;
// 00237): pc_app may never change a destination's target, data classes or
// creator; it is inserted PENDING, activated once by a person with a key,
// and DISABLED is final.
// Covers: F517
func TestHR513_ExportDestinationsKeepTargetsAndActivationsFixed(t *testing.T) {
	d := dbtest.New(t)
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	var forced bool
	if err := m.Pgx().QueryRow(ctx, `SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
		WHERE oid = 'pc.export_destinations'::regclass`).Scan(&forced); err != nil || !forced {
		t.Fatalf("row security not forced: %v %v", forced, err)
	}
	var readable bool
	if err := m.Pgx().QueryRow(ctx, `SELECT has_column_privilege('pc_audit_ro', 'pc.export_destinations', 'secret', 'SELECT')`).Scan(&readable); err != nil || readable {
		t.Fatalf("pc_audit_ro may read the credential: %v %v", readable, err)
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
	must("INSERT INTO pc.orgs (id, name) VALUES ($1, 'exports')", org)
	must("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'a')", org, user)
	must(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		org, cred, user, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))

	dest, secret := ids.NewV7(), bytes.Repeat([]byte{7}, 32)
	refused("a destination inserted ACTIVE", `INSERT INTO pc.export_destinations (org_id, id, name, kind, url, data_classes, secret, created_by, state)
		VALUES ($1, $2, 'd', 'https_put', 'https://s.example.net/', '{org_exports}', $3, 'x', 'ACTIVE')`, org, dest, secret)
	refused("an unknown data class", `INSERT INTO pc.export_destinations (org_id, id, name, kind, url, data_classes, secret, created_by)
		VALUES ($1, $2, 'd', 'https_put', 'https://s.example.net/', '{payloads}', $3, 'x')`, org, dest, secret)
	refused("an http target", `INSERT INTO pc.export_destinations (org_id, id, name, kind, url, data_classes, secret, created_by)
		VALUES ($1, $2, 'd', 'https_put', 'http://s.example.net/', '{org_exports}', $3, 'x')`, org, dest, secret)
	refused("an s3 destination without a bucket", `INSERT INTO pc.export_destinations (org_id, id, name, kind, url, data_classes, secret, created_by)
		VALUES ($1, $2, 'd', 's3', 'https://s.example.net/', '{org_exports}', $3, 'x')`, org, dest, secret)
	refused("a dot segment in the prefix", `INSERT INTO pc.export_destinations (org_id, id, name, kind, url, key_prefix, data_classes, secret, created_by)
		VALUES ($1, $2, 'd', 'https_put', 'https://s.example.net/', 'a/../b', '{org_exports}', $3, 'x')`, org, dest, secret)
	must(m20Destination, org, dest, secret)
	refused("activation without a person", "UPDATE pc.export_destinations SET state = 'ACTIVE' WHERE id = $1", dest)
	must("UPDATE pc.export_destinations SET state = 'ACTIVE', activated_by = $2, activated_credential = $3 WHERE id = $1", dest, user, cred)
	refused("a second activation", "UPDATE pc.export_destinations SET activated_by = $2, activated_credential = $2 WHERE id = $1", dest, ids.NewV7())
	refused("a return to PENDING", "UPDATE pc.export_destinations SET state = 'PENDING' WHERE id = $1", dest)
	for name, sql := range map[string]string{
		"a URL change":        "UPDATE pc.export_destinations SET url = 'https://evil.example/' WHERE id = $1",
		"a bucket change":     "UPDATE pc.export_destinations SET bucket = 'evil' WHERE id = $1",
		"an internal change":  "UPDATE pc.export_destinations SET internal = true WHERE id = $1",
		"a data class change": "UPDATE pc.export_destinations SET data_classes = '{org_exports}' WHERE id = $1",
		"a prefix change":     "UPDATE pc.export_destinations SET key_prefix = 'x' WHERE id = $1",
		"a kind change":       "UPDATE pc.export_destinations SET kind = 'https_put' WHERE id = $1",
		"a creator change":    "UPDATE pc.export_destinations SET created_by = 'y' WHERE id = $1",
		"a deletion":          "DELETE FROM pc.export_destinations WHERE id = $1",
	} {
		refused(name, sql, dest)
	}
	must("UPDATE pc.export_destinations SET state = 'DISABLED' WHERE id = $1", dest)
	refused("re-enabling a disabled destination", "UPDATE pc.export_destinations SET state = 'ACTIVE' WHERE id = $1", dest)
}

// TestTenancy_export_destinations: another org sees no destination of an
// org, changes none, and cannot store one in its name.
func TestTenancy_export_destinations(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	dest := ids.NewV7()
	a.mustExec(t, m20Destination, a.org, dest, m5Secret(1))
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.export_destinations"); n != 0 {
		t.Fatalf("another org sees %d destinations", n)
	}
	b.mustExec(t, "UPDATE pc.export_destinations SET state = 'DISABLED'")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.export_destinations WHERE state = 'PENDING'"); n != 1 {
		t.Fatalf("another org changed the destination: %d left", n)
	}
	// The org write guard (00181) refuses it before row security would.
	b.want(t, "23514", "a destination in another org's name", m20Destination, a.org, ids.NewV7(), m5Secret(2))
}
