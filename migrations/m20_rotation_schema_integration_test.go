// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/migrations"
)

// The schema's second line of defense for M20 S20c (migration 00239):
// target-confirmed rotation of a GitHub App key. The credentials app holds
// to the same rules first.

const (
	m20Candidate = `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts,
		header, created_by, state) VALUES ($1, $2, $3, $4, $5, $6, '{api.example.com}', 'Authorization', 'test', 'CANDIDATE')`
	m20Rotation = `INSERT INTO pc.credential_rotations (org_id, id, connection_id, old_credential_id, preview_digest, requested_by)
		VALUES ($1, $2, $3, $4, 'sha256:' || repeat('0', 64), 'test')`
	m20Task = `INSERT INTO pc.verifications (org_id, id, purpose, connection_id, operation, request, next_at, deadline_at)
		VALUES ($1, $2, $3, $4, 'github.app.rotation', '{}', now(), now() + interval '15 minutes')`
)

// m20Fixture is the M6 fixture with an ACTIVE credential (version 1), a
// CANDIDATE (version 2) and a rotation in TESTING whose test passed.
type m20Fixture struct {
	m6Fixture
	old, candidate, rotation string
}

func newM20Fixture(t *testing.T, p *db.Pool) m20Fixture {
	t.Helper()
	f := m20Fixture{m6Fixture: newM6Fixture(t, p), old: m5ID(), candidate: m5ID(), rotation: m5ID()}
	f.mustExec(t, m6Credential, f.org, f.old, f.connection, 1, f.brokerKey, m6Bytes(1200, 1))
	f.mustExec(t, m20Candidate, f.org, f.candidate, f.connection, 2, f.brokerKey, m6Bytes(1200, 2))
	f.mustExec(t, m20Rotation, f.org, f.rotation, f.connection, f.old)
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'CANDIDATE_SEALED', candidate_credential_id = $2 WHERE id = $1",
		f.rotation, f.candidate)
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'TESTING' WHERE id = $1", f.rotation)
	f.mustExec(t, "UPDATE pc.credential_rotations SET test_passed_at = now() WHERE id = $1", f.rotation)
	return f
}

// activate activates the fixture's rotation as the app does: the rotation
// first, then the credentials. back moves activated_at into the past.
func (f m20Fixture) activate(t *testing.T, back string) {
	t.Helper()
	f.mustExec(t, `UPDATE pc.credential_rotations SET state = 'ACTIVATING', activated_by = 'test',
		activated_at = now() - $2::interval, rollback_until = now() - $2::interval + interval '24 hours' WHERE id = $1`, f.rotation, back)
	f.mustExec(t, "UPDATE pc.credentials SET state = 'SUPERSEDED', superseded_at = now() WHERE id = $1", f.old)
	f.mustExec(t, "UPDATE pc.credentials SET state = 'ACTIVE' WHERE id = $1", f.candidate)
}

// TestHR517_CandidateIsNeverInGatewayConfigInSchema: a CANDIDATE is not in
// the gateway's sealed credentials, at most one exists per connection, it
// becomes ACTIVE only while its rotation is ACTIVATING, and no credential
// becomes a CANDIDATE again.
// Covers: F424
func TestHR517_CandidateIsNeverInGatewayConfigInSchema(t *testing.T) {
	ctx := context.Background()
	f := newM20Fixture(t, dbtest.New(t).AppPool(t))
	gw, err := ids.ParseUUID(f.gateway)
	if err != nil {
		t.Fatal(err)
	}
	served := func() []string {
		var out []string
		if err := f.p.InTenantTx(ctx, f.org, func(ctx context.Context, tx db.TenantTx) error {
			rows, err := dbq.New(tx).GatewaySealedCredentials(ctx, f.org, gw)
			for _, r := range rows {
				out = append(out, r.ID.String())
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := served(); len(got) != 1 || got[0] != f.old {
		t.Fatalf("gateway serves %v, want only the old credential %s", got, f.old)
	}
	f.want(t, m5Unique, "a second candidate", m20Candidate, f.org, m5ID(), f.connection, 3, f.brokerKey, m6Bytes(1200, 3))
	f.want(t, m5Check, "a candidate made ACTIVE while TESTING", "UPDATE pc.credentials SET state = 'ACTIVE' WHERE id = $1", f.candidate)
	f.want(t, m5Check, "a candidate SUPERSEDED", "UPDATE pc.credentials SET state = 'SUPERSEDED', superseded_at = now() WHERE id = $1", f.candidate)
	f.want(t, m5Check, "an ACTIVE credential made a candidate", "UPDATE pc.credentials SET state = 'CANDIDATE' WHERE id = $1", f.old)
	f.activate(t, "0 seconds")
	if got := served(); len(got) != 1 || got[0] != f.candidate {
		t.Fatalf("after activation the gateway serves %v, want only the candidate %s", got, f.candidate)
	}
	f.mustExec(t, "UPDATE pc.credentials SET state = 'REVOKED', superseded_at = NULL, revoked_at = now(), revoked_by = 'test' WHERE id = $1", f.old)
	f.want(t, m5Check, "a REVOKED credential made ACTIVE", "UPDATE pc.credentials SET state = 'ACTIVE', revoked_at = NULL, revoked_by = NULL WHERE id = $1", f.old)
}

// TestHR518_ActivationNeedsAPassedTestInSchema: a rotation is activated
// only from TESTING, only with a passed target test, and with its rollback
// window at most 24 hours.
// Covers: F424
func TestHR518_ActivationNeedsAPassedTestInSchema(t *testing.T) {
	f := newM20Fixture(t, dbtest.New(t).AppPool(t))
	other := m5ID()
	f.mustExec(t, `UPDATE pc.credential_rotations SET state = 'FAILED', end_reason = 'test', finished_at = now() WHERE id = $1`, f.rotation)
	f.mustExec(t, m20Rotation, f.org, other, f.connection, f.old)
	f.want(t, m5Check, "activated while REQUESTED", `UPDATE pc.credential_rotations SET state = 'ACTIVATING', activated_by = 'test',
		activated_at = now(), rollback_until = now() + interval '1 hour' WHERE id = $1`, other)
	f.mustExec(t, "UPDATE pc.credentials SET state = 'REVOKED', revoked_at = now(), revoked_by = 'test' WHERE id = $1", f.candidate)
	cand := m5ID()
	f.mustExec(t, m20Candidate, f.org, cand, f.connection, 3, f.brokerKey, m6Bytes(1200, 3))
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'CANDIDATE_SEALED', candidate_credential_id = $2 WHERE id = $1", other, cand)
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'TESTING' WHERE id = $1", other)
	f.want(t, m5Check, "activated without a passed test", `UPDATE pc.credential_rotations SET state = 'ACTIVATING', activated_by = 'test',
		activated_at = now(), rollback_until = now() + interval '1 hour' WHERE id = $1`, other)
	f.mustExec(t, "UPDATE pc.credential_rotations SET test_passed_at = now() WHERE id = $1", other)
	f.want(t, m5Check, "a rollback window over 24 hours", `UPDATE pc.credential_rotations SET state = 'ACTIVATING', activated_by = 'test',
		activated_at = now(), rollback_until = now() + interval '25 hours' WHERE id = $1`, other)
	f.want(t, m5Check, "a candidate swapped after sealing", "UPDATE pc.credential_rotations SET candidate_credential_id = $2 WHERE id = $1", other, f.candidate)
}

// TestHR519_RollbackOnlyBeforeConfirmationInSchema: the old key becomes
// ACTIVE again only while its rotation is ACTIVATING, and the rotation is
// ROLLED_BACK only within its window; after the window, or once it moved
// on, both are refused.
// Covers: F424
func TestHR519_RollbackOnlyBeforeConfirmationInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM20Fixture(t, d.AppPool(t))
	f.activate(t, "1 hour")
	f.mustExec(t, "UPDATE pc.credentials SET state = 'REVOKED', revoked_at = now(), revoked_by = 'test' WHERE id = $1", f.candidate)
	f.mustExec(t, "UPDATE pc.credentials SET state = 'ACTIVE', superseded_at = NULL WHERE id = $1", f.old)
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'ROLLED_BACK', end_reason = 'test', finished_at = now() WHERE id = $1", f.rotation)
	f.want(t, m5Check, "a rolled-back rotation moved on", "UPDATE pc.credential_rotations SET state = 'AWAITING_OLD_REMOVAL', finished_at = NULL, end_reason = NULL WHERE id = $1", f.rotation)

	late := newM20Fixture(t, d.AppPool(t))
	late.activate(t, "25 hours")
	late.want(t, m5Check, "rolled back after 24 hours",
		"UPDATE pc.credential_rotations SET state = 'ROLLED_BACK', end_reason = 'test', finished_at = now() WHERE id = $1", late.rotation)

	moved := newM20Fixture(t, d.AppPool(t))
	moved.activate(t, "1 hour")
	moved.mustExec(t, "UPDATE pc.credential_rotations SET state = 'AWAITING_OLD_REMOVAL' WHERE id = $1", moved.rotation)
	moved.mustExec(t, "UPDATE pc.credentials SET state = 'REVOKED', revoked_at = now(), revoked_by = 'test' WHERE id = $1", moved.candidate)
	moved.want(t, m5Check, "the old key made ACTIVE after the window closed",
		"UPDATE pc.credentials SET state = 'ACTIVE', superseded_at = NULL WHERE id = $1", moved.old)
	moved.want(t, m5Check, "rolled back from AWAITING_OLD_REMOVAL",
		"UPDATE pc.credential_rotations SET state = 'ROLLED_BACK', end_reason = 'test', finished_at = now() WHERE id = $1", moved.rotation)
}

// TestT224_RotationScheduleInSchema: one open rotation per connection, only
// the state machine's moves, a finished rotation never changes, the two
// rotation purposes are tasks of no transaction, and pc_audit_ro reads
// rotations but never sealed bytes.
// Covers: F424
func TestT224_RotationScheduleInSchema(t *testing.T) {
	d := dbtest.New(t)
	f := newM20Fixture(t, d.AppPool(t))
	f.want(t, m5Unique, "a second open rotation", m20Rotation, f.org, m5ID(), f.connection, f.old)
	f.want(t, m5Check, "TESTING back to CANDIDATE_SEALED", "UPDATE pc.credential_rotations SET state = 'CANDIDATE_SEALED' WHERE id = $1", f.rotation)
	f.want(t, m5Check, "confirmed without activation", "UPDATE pc.credential_rotations SET state = 'CONFIRMED', confirmed_at = now(), finished_at = now() WHERE id = $1", f.rotation)
	f.activate(t, "0 seconds")
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'AWAITING_OLD_REMOVAL' WHERE id = $1", f.rotation)
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'CONFIRMING' WHERE id = $1", f.rotation)
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'AWAITING_OLD_REMOVAL' WHERE id = $1", f.rotation)
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'CONFIRMING' WHERE id = $1", f.rotation)
	f.mustExec(t, "UPDATE pc.credential_rotations SET state = 'CONFIRMED', confirmed_at = now(), finished_at = now() WHERE id = $1", f.rotation)
	f.want(t, m5Check, "a confirmed rotation changed", "UPDATE pc.credential_rotations SET end_reason = 'x' WHERE id = $1", f.rotation)
	f.mustExec(t, m20Rotation, f.org, m5ID(), f.connection, f.candidate)

	for _, purpose := range []string{"credential_rotation_test", "credential_rotation_confirm"} {
		f.mustExec(t, m20Task, f.org, m5ID(), purpose, f.connection)
	}
	f.want(t, m5Check, "an unknown purpose", m20Task, f.org, m5ID(), "credential_rotation", f.connection)

	var canSee, canSeeSealed bool
	d.AdminQueryRow(t, `SELECT has_table_privilege('pc_audit_ro', 'pc.credential_rotations', 'SELECT'),
		has_column_privilege('pc_audit_ro', 'pc.credentials', 'sealed', 'SELECT')`, nil, &canSee, &canSeeSealed)
	if !canSee || canSeeSealed {
		t.Fatalf("pc_audit_ro: rotations=%v sealed=%v, want true, false", canSee, canSeeSealed)
	}
}

// TestM20_RotationDownAppliesAgain: 00239's Down removes the rotations,
// their tasks and the candidates, restores the old checks, and its Up
// applies again.
// Covers: F424
func TestM20_RotationDownAppliesAgain(t *testing.T) {
	ctx := context.Background()
	d := dbtest.New(t)
	f := newM20Fixture(t, d.AppPool(t))
	f.mustExec(t, m20Task, f.org, m5ID(), "credential_rotation_test", f.connection)
	up, down := m20Sections(t, "00239_credential_rotations.sql")
	m := d.Pool(t, d.Migrator)
	if _, err := m.Pgx().Exec(ctx, down); err != nil {
		t.Fatalf("Down: %v", err)
	}
	f.want(t, m5Check, "a candidate after the Down", m20Candidate, f.org, m5ID(), f.connection, 5, f.brokerKey, m6Bytes(1200, 5))
	f.want(t, m5Check, "a rotation task after the Down", m20Task, f.org, m5ID(), "credential_rotation_test", f.connection)
	if _, err := m.Pgx().Exec(ctx, up); err != nil {
		t.Fatalf("Up again: %v", err)
	}
	f.mustExec(t, m20Candidate, f.org, m5ID(), f.connection, 5, f.brokerKey, m6Bytes(1200, 5))
}

// m20Sections returns the Up and Down sections of a migration file.
func m20Sections(t *testing.T, name string) (string, string) {
	t.Helper()
	b, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(b), "-- +goose Down")
	if !ok {
		t.Fatalf("%s: no Down section", name)
	}
	return up, down
}
