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

const m20Receipt = `INSERT INTO pc.export_receipts (org_id, id, destination_id, class, artifact_id, requested_by, object_key)
	VALUES ($1, $2, $3, 'evidence_packs', $4, $5, 'evidence_packs/x')`

// TestHR514_AReceiptOutlivesItsPush (00238): a receipt is inserted QUEUED
// and never deleted; what it says about delivered bytes never changes; a
// removal is recorded once and a sent notice stays sent.
// Covers: F517
func TestHR514_AReceiptOutlivesItsPush(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a := newM5Fixture(t, p)
	user, dest, id := ids.NewV7(), ids.NewV7(), ids.NewV7()
	a.mustExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'a')", a.org, user)
	a.mustExec(t, m20Destination, a.org, dest, m5Secret(1))
	a.want(t, "23514", "a receipt inserted DELIVERED", `INSERT INTO pc.export_receipts (org_id, id, destination_id, class, artifact_id, requested_by,
		object_key, state, delivered_at, sha256) VALUES ($1, $2, $3, 'evidence_packs', $4, $5, 'k', 'DELIVERED', now(), $6)`,
		a.org, id, dest, ids.NewV7(), user, bytes.Repeat([]byte{1}, 32))
	a.mustExec(t, m20Receipt, a.org, id, dest, ids.NewV7(), user)
	a.mustExec(t, "UPDATE pc.export_receipts SET state = 'PUSHING' WHERE id = $1", id)
	a.want(t, "23514", "a delivery without a hash", "UPDATE pc.export_receipts SET state = 'DELIVERED', delivered_at = now() WHERE id = $1", id)
	a.mustExec(t, "UPDATE pc.export_receipts SET state = 'DELIVERED', delivered_at = now(), sha256 = $2, size_bytes = 5 WHERE id = $1", id, bytes.Repeat([]byte{1}, 32))
	a.want(t, "23514", "a delivered size change", "UPDATE pc.export_receipts SET size_bytes = 6 WHERE id = $1", id)
	a.want(t, "23514", "a delivered hash change", "UPDATE pc.export_receipts SET sha256 = $2 WHERE id = $1", id, bytes.Repeat([]byte{2}, 32))
	a.want(t, "23514", "an undelivered delivery", "UPDATE pc.export_receipts SET state = 'FAILED', failure_code = 'x', delivered_at = NULL WHERE id = $1", id)
	a.want(t, "42501", "a changed object key", "UPDATE pc.export_receipts SET object_key = 'y' WHERE id = $1", id)
	a.want(t, "42501", "a deletion", "DELETE FROM pc.export_receipts WHERE id = $1", id)
	a.mustExec(t, "UPDATE pc.export_receipts SET removed_here_at = now(), notice_state = 'PENDING' WHERE id = $1", id)
	a.want(t, "23514", "a second removal", "UPDATE pc.export_receipts SET removed_here_at = now() + interval '1 day' WHERE id = $1", id)
	a.mustExec(t, "UPDATE pc.export_receipts SET notice_state = 'SENT', notice_sent_at = now() WHERE id = $1", id)
	a.want(t, "23514", "a notice taken back", "UPDATE pc.export_receipts SET notice_state = 'PENDING', notice_sent_at = NULL WHERE id = $1", id)
}

// TestTenancy_export_receipts: another org sees no receipt of an org,
// changes none, and cannot store one in its name or for its destination.
func TestTenancy_export_receipts(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	a, b := newM5Fixture(t, p), newM5Fixture(t, p)
	user, dest, id := ids.NewV7(), ids.NewV7(), ids.NewV7()
	a.mustExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'a')", a.org, user)
	a.mustExec(t, m20Destination, a.org, dest, m5Secret(1))
	a.mustExec(t, m20Receipt, a.org, id, dest, ids.NewV7(), user)
	if n := m10Count(t, p, b.org, "SELECT count(*) FROM pc.export_receipts"); n != 0 {
		t.Fatalf("another org sees %d receipts", n)
	}
	b.mustExec(t, "UPDATE pc.export_receipts SET state = 'PUSHING'")
	if n := m10Count(t, p, a.org, "SELECT count(*) FROM pc.export_receipts WHERE state = 'QUEUED'"); n != 1 {
		t.Fatalf("another org changed the receipt: %d left", n)
	}
	b.want(t, "23514", "a receipt in another org's name", m20Receipt, a.org, ids.NewV7(), dest, ids.NewV7(), user)
	b.want(t, "23503", "a receipt for another org's destination", m20Receipt, b.org, ids.NewV7(), dest, ids.NewV7(), user)
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
