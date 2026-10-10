// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/migrations"
)

// These tests check the schema's second line of defense for M7 track B
// (G0 M7, migration 00065): the application enforces the same rules first.
// Names are prefixed m7b so that they never collide with other milestones'
// schema tests in this package.

const (
	m7bFK    = "23503"
	m7bTile  = `INSERT INTO pc.ledger_tiles (org_id, level, tile_index, width, hashes) VALUES ($1, $2, $3, $4, $5)`
	m7bPoint = `INSERT INTO pc.checkpoints (org_id, tree_size, root_hash, note, kid, pq_kid) VALUES ($1, $2, $3, $4, 'checkpoints-k', $5)`
	m7bLeaf  = `INSERT INTO pc.anchor_leaves (org_id, anchor_id, leaf_index, nonce, checkpoint_size) VALUES ($1, $2, $3, $4, $5)`
	m7bAnch  = `INSERT INTO pc.anchors (id, period, leaves, root, statement, signature, kid) VALUES ($1, $2, $3, $4, '\x7b7d', $5, 'anchors-k')`
	m7bKey   = `INSERT INTO pc.keys (org_id, id, kid, purpose, algorithm, public_key, wrapped_private_key, kek_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'kek')`
)

func m7bNote() []byte { return m6Bytes(100, 'n') }

func TestHR194_TilesAndCheckpointsAreAppendOnly(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	f.mustExec(t, m7bTile, f.org, 0, 0, 1, m6Bytes(32, 1))
	// A tile that grows is a new, wider row.
	f.mustExec(t, m7bTile, f.org, 0, 0, 2, m6Bytes(64, 1))
	f.want(t, m5Unique, "the same tile width twice", m7bTile, f.org, 0, 0, 2, m6Bytes(64, 2))
	f.mustExec(t, m7bPoint, f.org, 2, m6Bytes(32, 3), m7bNote(), nil)
	f.mustExec(t, m7bLeaf, f.org, m5ID(), 0, m6Bytes(32, 4), 2)
	f.mustExec(t, "INSERT INTO pc.evidence_integrity (org_id) VALUES ($1)", f.org)
	for _, table := range []string{"ledger_tiles", "checkpoints", "anchor_leaves"} {
		f.want(t, m5Denied, "UPDATE "+table, "UPDATE pc."+table+" SET org_id = org_id")
		f.want(t, m5Denied, "DELETE "+table, "DELETE FROM pc."+table)
	}
	f.want(t, m5Denied, "DELETE evidence_integrity", "DELETE FROM pc.evidence_integrity")
	f.want(t, m5Denied, "an integrity row moves to another org", "UPDATE pc.evidence_integrity SET org_id = org_id")
	f.mustExec(t, "UPDATE pc.evidence_integrity SET verified_size = 2, verified_at = now(), updated_at = now()")
}

func TestHR194_TileAndCheckpointShapes(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	f.want(t, m5Check, "hashes that are not 32 bytes per entry", m7bTile, f.org, 0, 0, 2, m6Bytes(63, 1))
	f.want(t, m5Check, "a tile wider than 256", m7bTile, f.org, 0, 0, 257, m6Bytes(257*32, 1))
	f.want(t, m5Check, "an empty tile", m7bTile, f.org, 0, 0, 0, []byte{})
	f.want(t, m5Check, "a tile level above 63", m7bTile, f.org, 64, 0, 1, m6Bytes(32, 1))
	f.want(t, m5Check, "a negative tile index", m7bTile, f.org, 0, -1, 1, m6Bytes(32, 1))
	f.want(t, m5Check, "a checkpoint of an empty tree", m7bPoint, f.org, 0, m6Bytes(32, 3), m7bNote(), nil)
	f.want(t, m5Check, "a root that is not 32 bytes", m7bPoint, f.org, 1, m6Bytes(31, 3), m7bNote(), nil)
	f.want(t, m5Check, "a note too short to be signed", m7bPoint, f.org, 1, m6Bytes(32, 3), m6Bytes(10, 'n'), nil)
	f.want(t, m5Check, "an empty co-signing key id", m7bPoint, f.org, 1, m6Bytes(32, 3), m7bNote(), "")
	f.mustExec(t, m7bPoint, f.org, 1, m6Bytes(32, 3), m7bNote(), "checkpoints-pq-k")
	f.want(t, m5Unique, "two checkpoints of one size", m7bPoint, f.org, 1, m6Bytes(32, 4), m7bNote(), nil)
	const integrity = `INSERT INTO pc.evidence_integrity (org_id, state, failure_code, failed_at, verified_size, verified_at)
		VALUES ($1, $2, $3, $4::timestamptz, $5, $6::timestamptz)`
	f.want(t, m5Check, "a failure without its reason", integrity, f.org, "FAILED", nil, "2026-10-10T00:00:00Z", nil, nil)
	f.want(t, m5Check, "a failure code that is free text", integrity, f.org, "FAILED", "the chain broke",
		"2026-10-10T00:00:00Z", nil, nil)
	f.want(t, m5Check, "a reason on a healthy org", integrity, f.org, "OK", "CHAIN_LINK", "2026-10-10T00:00:00Z", nil, nil)
	f.want(t, m5Check, "a verification without its size", integrity, f.org, "OK", nil, nil, nil, "2026-10-10T00:00:00Z")
	f.mustExec(t, integrity, f.org, "FAILED", "CHAIN_LINK", "2026-10-10T00:00:00Z", 1, "2026-10-09T00:00:00Z")
}

func TestHR195_AnchorsHoldOnlyBlindedLeaves(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	f := newM5Fixture(t, p)
	// The global table has no tenant column, nonce or checkpoint reference.
	var cols []string
	err := p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, `SELECT column_name::text FROM information_schema.columns
			WHERE table_schema = 'pc' AND table_name = 'anchors' ORDER BY ordinal_position`)
		if err != nil {
			return err
		}
		cols, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"id", "period", "leaves", "root", "statement", "signature", "kid", "state", "attempts", "next_at",
		"error_code", "rekor_entry", "timestamp_token", "created_at", "anchored_at",
	}
	if !slices.Equal(cols, want) {
		t.Fatalf("anchors columns = %v, want %v (no tenant data, HR-195)", cols, want)
	}
	a := m5ID()
	f.want(t, m5Check, "leaves that are not whole hashes", m7bAnch, a, "2026-10-10T00:00:00Z", m6Bytes(33, 1),
		m6Bytes(32, 2), m6Bytes(64, 3))
	f.mustExec(t, m7bAnch, a, "2026-10-10T00:00:00Z", m6Bytes(64, 1), m6Bytes(32, 2), m6Bytes(64, 3))
	f.want(t, m5Unique, "two anchors of one period", m7bAnch, m5ID(), "2026-10-10T00:00:00Z", m6Bytes(32, 1),
		m6Bytes(32, 2), m6Bytes(64, 3))
	f.want(t, m5Check, "anchored without the log entry and timestamp",
		"UPDATE pc.anchors SET state = 'ANCHORED', anchored_at = now() WHERE id = $1", a)
	f.mustExec(t, `UPDATE pc.anchors SET state = 'ANCHORED', anchored_at = now(), rekor_entry = '\x7b7d',
		timestamp_token = '\x30' WHERE id = $1`, a)
	f.want(t, m5Denied, "an anchor's leaves cannot change", "UPDATE pc.anchors SET leaves = leaves")
	f.want(t, m5Denied, "an anchor's statement cannot change", "UPDATE pc.anchors SET statement = statement")
	f.want(t, m5Denied, "DELETE anchors", "DELETE FROM pc.anchors")

	f.mustExec(t, m7bPoint, f.org, 5, m6Bytes(32, 3), m7bNote(), nil)
	f.want(t, m7bFK, "a leaf for a checkpoint that does not exist", m7bLeaf, f.org, a, 0, m6Bytes(32, 4), 6)
	f.want(t, m5Check, "a nonce that is not 32 bytes", m7bLeaf, f.org, a, 0, m6Bytes(31, 4), 5)
	f.mustExec(t, m7bLeaf, f.org, a, 0, m6Bytes(32, 4), 5)

	// Another org sees neither the leaf nor its nonce.
	other := ids.New[ids.Org]()
	err = p.InTenantTx(context.Background(), other, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'other')", other); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM pc.anchor_leaves").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("another org sees %d anchor leaves", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHR095_KeyAlgorithmIsPinnedToItsPurpose(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	wrapped := m6Bytes(60, 9)
	ok := []struct {
		purpose, alg string
		size         int
	}{
		{"checkpoints", "EdDSA", 32},
		{"evidence_packs", "EdDSA", 32},
		{"anchors", "ES256", 91},
		{"checkpoints_pq", "ML-DSA-65", 1952},
	}
	for _, k := range ok {
		f.mustExec(t, m7bKey, f.org, m5ID(), k.purpose+"-k", k.purpose, k.alg, m6Bytes(k.size, 1), wrapped)
	}
	bad := []struct {
		name, purpose, alg string
		size               int
	}{
		{"an Ed25519 anchor key", "anchors", "EdDSA", 32},
		{"an ECDSA receipt key", "receipts", "ES256", 91},
		{"an ML-DSA checkpoint key under the Ed25519 purpose", "checkpoints", "ML-DSA-65", 1952},
		{"an ECDSA key of the wrong length", "anchors", "ES256", 65},
		{"an ML-DSA-65 key of the wrong length", "checkpoints_pq", "ML-DSA-65", 1312},
		{"an Ed25519 key of the wrong length", "evidence_packs", "EdDSA", 33},
		{"an unknown algorithm", "anchors", "RS256", 91},
		{"an unknown purpose", "witness", "EdDSA", 32},
	}
	for _, k := range bad {
		f.want(t, m5Check, k.name, m7bKey, f.org, m5ID(), m5ID(), k.purpose, k.alg, m6Bytes(k.size, 1), wrapped)
	}
}

func TestHR198_TombstonesNameTheirPolicyAndPcAppCannotSetThem(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	entry := f.ledger(t)
	f.want(t, m5Check, "a removal without its policy", `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type,
		actor_id, body, body_removed_at) VALUES ($1, $2, 'receipt.test', 'test', 'test', '\x7b7d', now())`, f.org, m5ID())
	for _, table := range []string{"ledger_entries", "decision_receipts", "execution_receipts", "effect_receipts"} {
		f.want(t, m5Denied, "pc_app removes a body of "+table,
			"UPDATE pc."+table+" SET body_removed_at = now(), removed_by_policy = $1", m5ID())
	}
	f.want(t, m5Check, "an effect receipt removed without its policy", `INSERT INTO pc.effect_receipts (org_id,
		transaction_id, seq, state, level_required, basis, receipt_jws, ledger_entry_id, body_removed_at)
		VALUES ($1, $2, 1, 'UNKNOWN', 'acceptance', 'deadline', 'eyJhbGciOiJFZERTQSJ9.e30.sig', $3, now())`,
		f.org, f.txn, entry)
}

// TestM7B_DownMigrationRunsAndUpAgain: 00065's Down section runs as
// pc_migrator and leaves the lister without the M7 track B purposes, and
// its Up section applies again.
func TestM7B_DownMigrationRunsAndUpAgain(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00065_checkpoints.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("no Down section")
	}
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	if _, err := m.Pgx().Exec(ctx, down); err != nil {
		t.Fatalf("Down: %v", err)
	}
	p := d.AppPool(t)
	if _, err := p.CrossOrgList(ctx, db.ListCheckpointsDue, 10); err == nil {
		t.Error("checkpoints_due survives the Down migration")
	}
	if _, err := p.CrossOrgList(ctx, db.ListVerificationsDue, 10); err != nil {
		t.Errorf("the Down migration lost an earlier purpose: %v", err)
	}
	if _, err := m.Pgx().Exec(ctx, up); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	if _, err := p.CrossOrgList(ctx, db.ListCheckpointsDue, 10); err != nil {
		t.Errorf("checkpoints_due after Up again: %v", err)
	}
}

func TestHR194_ListerFindsOrgsDueForCheckpointsAndVerification(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	due := func(purpose db.ListerPurpose, org ids.OrgID) bool {
		t.Helper()
		refs, err := p.CrossOrgList(ctx, purpose, 10000)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(refs, func(r db.OrgRef) bool { return r.Org == org })
	}
	f := newM5Fixture(t, p)
	f.mustExec(t, "INSERT INTO pc.ledger_heads (org_id, seq) VALUES ($1, 2)", f.org)
	if !due(db.ListCheckpointsDue, f.org) || due(db.ListIntegrityDue, f.org) {
		t.Fatal("an org with two chained entries and no checkpoint must be due for a checkpoint only")
	}
	f.mustExec(t, m7bPoint, f.org, 1, m6Bytes(32, 3), m7bNote(), nil)
	if !due(db.ListCheckpointsDue, f.org) || !due(db.ListIntegrityDue, f.org) {
		t.Fatal("a chain past its checkpoint must be due for both")
	}
	f.mustExec(t, m7bPoint, f.org, 2, m6Bytes(32, 3), m7bNote(), nil)
	if due(db.ListCheckpointsDue, f.org) {
		t.Fatal("a checkpointed head is due again")
	}
	f.mustExec(t, "INSERT INTO pc.evidence_integrity (org_id, verified_size, verified_at) VALUES ($1, 2, now())", f.org)
	if due(db.ListIntegrityDue, f.org) {
		t.Fatal("an org verified today is due again")
	}
	f.mustExec(t, "UPDATE pc.evidence_integrity SET verified_at = now() - interval '25 hours'")
	if !due(db.ListIntegrityDue, f.org) {
		t.Fatal("an org verified more than a day ago is not due")
	}
	f.mustExec(t, "UPDATE pc.ledger_heads SET seq = 3")
	f.mustExec(t, "UPDATE pc.evidence_integrity SET state = 'FAILED', failure_code = 'CHAIN_LINK', failed_at = now()")
	if due(db.ListCheckpointsDue, f.org) || due(db.ListIntegrityDue, f.org) {
		t.Fatal("an org whose integrity failed must stay stopped until an operator investigates")
	}
}
