// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/migrations"
)

// These tests check the schema of the release of an unknown outcome (G0 M7
// slice A11, migration 00071): a BINDING ceremony names exactly one of an
// approval request, a batch and a reconciliation, and a person has at most
// one open ceremony per reconciliation. Names are prefixed m7a11.

const m7a11Ceremony = `INSERT INTO pc.webauthn_ceremonies (org_id, id, session_id, user_id, purpose, challenge,
	approval_request_id, reconciliation_id, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + interval '5 minutes')`

// m7a11Subject00050 is the binding-subject constraint as 00050 wrote it:
// what 00071's Down restores.
const m7a11Subject00050 = `CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id) <= 1)`

func TestHR192_ReleaseCeremoniesNameOneReconciliationInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM7Fixture(t, d.AppPool(t))
	task := m5ID()
	f.mustExec(t, m7Task, f.org, task, f.txn, "unknown_outcome")
	binding := m5Secret(70)
	first := m5ID()
	f.mustExec(t, m7a11Ceremony, f.org, first, f.session, f.user, "BINDING", binding, nil, task)
	f.mustExec(t, m7a11Ceremony, f.org, m5ID(), f.session2, f.user2, "BINDING", binding, nil, task) // two people, one release
	f.want(t, m5Unique, "two open ceremonies of one person for one reconciliation", m7a11Ceremony,
		f.org, m5ID(), f.session, f.user, "BINDING", m5Secret(71), nil, task)
	req := f.request(t, 72)
	f.want(t, m5Check, "a ceremony naming a request and a reconciliation", m7a11Ceremony,
		f.org, m5ID(), f.session, f.user, "BINDING", m5Secret(73), req, task)
	f.want(t, m5Check, "a step-up naming a reconciliation", m7a11Ceremony,
		f.org, m5ID(), f.session, f.user, "STEP_UP", m5Secret(74), nil, task)
	f.want(t, m7bFK, "a ceremony for a reconciliation that does not exist", m7a11Ceremony,
		f.org, m5ID(), f.session, f.user, "BINDING", m5Secret(75), nil, m5ID())
	f.mustExec(t, m7a11Ceremony, f.org, m5ID(), f.session, f.user, "BINDING", m5Secret(76), req, nil) // approvals unchanged
	f.mustExec(t, "UPDATE pc.webauthn_ceremonies SET consumed_at = now() WHERE id = $1", first)
	f.mustExec(t, m7a11Ceremony, f.org, m5ID(), f.session, f.user, "BINDING", binding, nil, task) // a used ceremony frees the slot
	f.want(t, m5Denied, "a ceremony's reconciliation cannot change",
		"UPDATE pc.webauthn_ceremonies SET reconciliation_id = reconciliation_id WHERE id = $1", first)
}

// TestM7A11_DownRestoresTheBindingSubjectAndUpAgain: 00071's Down section
// runs as pc_migrator, removes the column and the index, and restores
// 00050's binding-subject constraint exactly; its Up section applies again.
func TestM7A11_DownRestoresTheBindingSubjectAndUpAgain(t *testing.T) {
	d := dbtest.New(t)
	b, err := fs.ReadFile(migrations.FS, "00071_reconciliation_release.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatal("no Down section")
	}
	m := d.Pool(t, d.Migrator)
	ctx := context.Background()
	def := func(name string) string {
		t.Helper()
		var out string
		if err := m.Pgx().QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
			WHERE conrelid = 'pc.webauthn_ceremonies'::regclass AND conname = $1`, name).Scan(&out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return out
	}
	if !strings.Contains(def("webauthn_ceremonies_binding_subject"), "reconciliation_id") {
		t.Fatal("after Up, the binding subject does not name the reconciliation")
	}
	if _, err := m.Pgx().Exec(ctx, down); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if _, err := m.Pgx().Exec(ctx, "ALTER TABLE pc.webauthn_ceremonies ADD CONSTRAINT m7a11_expected "+m7a11Subject00050); err != nil {
		t.Fatal(err)
	}
	if got, want := def("webauthn_ceremonies_binding_subject"), def("m7a11_expected"); got != want {
		t.Errorf("after Down: %s, want 00050's %s", got, want)
	}
	var left int
	if err := m.Pgx().QueryRow(ctx, `SELECT count(*) FROM pg_attribute WHERE attrelid = 'pc.webauthn_ceremonies'::regclass
		AND attname = 'reconciliation_id' AND NOT attisdropped`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("the column survives the Down migration: %d %v", left, err)
	}
	if _, err := m.Pgx().Exec(ctx, "ALTER TABLE pc.webauthn_ceremonies DROP CONSTRAINT m7a11_expected"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Pgx().Exec(ctx, up); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	if !strings.Contains(def("webauthn_ceremonies_binding_subject"), "reconciliation_id") {
		t.Fatal("after Up again, the binding subject does not name the reconciliation")
	}
}
