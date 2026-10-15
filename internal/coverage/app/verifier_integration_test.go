// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// verifier is a fake target verifier with a passing test per operation.
type verifier struct {
	passed map[string]time.Time
	asked  []string
}

func (v *verifier) LastPassed(_ context.Context, _ db.TenantTx, _ ids.UUID, operation string) (*time.Time, error) {
	v.asked = append(v.asked, operation)
	if at, ok := v.passed[operation]; ok {
		return &at, nil
	}
	return nil, nil
}

// TestHR210_AVerifierPassLiftsOnlyTheReadItTested: on target-enforced
// access, a passing target-verifier test of a read lifts that read's scope
// to ENFORCED. Another read on the same connection stays unverified, and a
// write stays PARTIAL even with a passing test of its own (founder
// decision N15).
func TestHR210_AVerifierPassLiftsOnlyTheReadItTested(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "UPDATE pc.connections SET access_mode = 'target_enforced' WHERE id = $1", f.conn)
	const tested, untested, write = "payments.refund.get", "payments.refund.list", "payments.refund.create"
	now := f.dbNow(t)
	v := &verifier{passed: map[string]time.Time{tested: now.Add(-time.Minute), write: now.Add(-time.Minute)}}
	f.svc.Verifier = v
	for _, op := range []string{tested, untested, write} {
		f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7,
			'http', 'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), op, f.conn)
	}
	var revision int32
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT revision FROM pc.connections WHERE id = $1", f.conn).Scan(&revision)
	}); err != nil {
		t.Fatal(err)
	}
	c := f.closure(probes(false), f.dbNow(t))
	c.Bound.ConnectionRevision = revision
	if _, err := f.record(t, c); err != nil {
		t.Fatal(err)
	}
	f.reassess(t)
	for op, want := range map[string]struct{ state, reason string }{
		tested:   {"ENFORCED", ""},
		untested: {"PARTIAL", domain.ReasonUnverified},
		write:    {"PARTIAL", domain.ReasonWriteCapped},
	} {
		row, s, _ := f.current(t, op)
		if row.State != want.state || (want.reason != "" && !slices.Contains(s.Reasons, want.reason)) {
			t.Errorf("%s: %s %v, want %s with %q", op, row.State, s.Reasons, want.state, want.reason)
		}
	}
	for _, op := range []string{tested, untested, write} {
		if !slices.Contains(v.asked, op) {
			t.Errorf("the verifier was not asked about %s: %v", op, v.asked)
		}
	}
}

// addTest records a finished connection test of kind on the fixture's
// connection (or conn), as the connection tests record it.
func (f *fixture) addTest(t *testing.T, conn ids.UUID, kind, operation, state, result string, finished time.Time) {
	t.Helper()
	var op, res *string
	if operation != "" {
		op = &operation
	}
	if result != "" {
		res = &result
	}
	// A read or target_verifier test is leased to the gateway as a
	// verification task.
	var task *ids.UUID
	if kind != "credential" {
		id := f.verificationTask(t, conn, operation)
		task = &id
	}
	f.exec(t, `INSERT INTO pc.connection_tests (org_id, id, connection_id, kind, operation, state, result, requested_by, finished_at,
		verification_id) VALUES ($1, $2, $3, $4, $5, $6, $7, 'test', $8, $9)`, f.org, ids.NewV7(), conn, kind, op, state, res, finished, task)
}

// verificationTask is a connection test's verification task.
func (f *fixture) verificationTask(t *testing.T, conn ids.UUID, operation string) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	f.exec(t, `INSERT INTO pc.verifications (org_id, id, purpose, connection_id, operation, request, next_at, deadline_at)
		VALUES ($1, $2, 'connection_test', $3, $4, '{}', now(), now() + interval '15 minutes')`, f.org, id, conn, operation)
	return id
}

// boundAnHourAgo dates the connections' latest revisions and the package
// pin an hour back, so tests that finished since count.
func (f *fixture) boundAnHourAgo(t *testing.T) {
	t.Helper()
	f.d.AdminExec(t, "UPDATE pc.connections SET updated_at = now() - interval '1 hour' WHERE org_id = $1", f.org)
	f.d.AdminExec(t, "UPDATE pc.package_pins SET updated_at = now() - interval '1 hour' WHERE org_id = $1", f.org)
}

// lastPassed asks app.ConnectionTests about operation on conn.
func (f *fixture) lastPassed(t *testing.T, conn ids.UUID, operation string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		at, err = app.ConnectionTests{}.LastPassed(ctx, tx, conn, operation)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return at
}

// TestHR210_ConnectionTestsVouchWhileTheLatestPasses: the server's target
// verifier reads pc.connection_tests. Only a target_verifier test of the
// operation on the connection counts, and only while the latest finished
// one is DONE and PASSED: a newer failure, or a test that could not run,
// drops the lift, and a newer pass restores it. A credential test, a read
// test, another operation's test and another connection's do not count
// (founder decision N15).
func TestHR210_ConnectionTestsVouchWhileTheLatestPasses(t *testing.T) {
	f := newFixture(t)
	const op = "payments.refund.get"
	other := ids.NewV7()
	f.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
		created_by, updated_by) VALUES ($1, $2, 'other', 'http', $3, 'pc.mock-payments', 'https://api.example.com',
		'target_enforced', 'enforce', 'test', 'test')`, f.org, other, f.gateway)
	f.boundAnHourAgo(t)
	now := f.dbNow(t).Truncate(time.Microsecond)
	if at := f.lastPassed(t, f.conn, op); at != nil {
		t.Fatalf("no test, yet %v", at)
	}
	f.addTest(t, f.conn, "credential", "", "DONE", "PASSED", now.Add(-9*time.Minute))
	f.addTest(t, f.conn, "read", op, "DONE", "PASSED", now.Add(-8*time.Minute))
	f.addTest(t, f.conn, "target_verifier", "payments.refund.list", "DONE", "PASSED", now.Add(-7*time.Minute))
	f.addTest(t, other, "target_verifier", op, "DONE", "PASSED", now.Add(-7*time.Minute))
	if at := f.lastPassed(t, f.conn, op); at != nil {
		t.Fatalf("a test of something else vouches: %v", at)
	}
	passed := now.Add(-6 * time.Minute)
	f.addTest(t, f.conn, "target_verifier", op, "DONE", "PASSED", passed)
	if at := f.lastPassed(t, f.conn, op); at == nil || !at.Equal(passed) {
		t.Fatalf("a passing test: %v, want %v", at, passed)
	}
	f.addTest(t, f.conn, "target_verifier", op, "DONE", "FAILED", now.Add(-5*time.Minute))
	if at := f.lastPassed(t, f.conn, op); at != nil {
		t.Fatalf("a newer failure still vouches: %v", at)
	}
	again := now.Add(-4 * time.Minute)
	f.addTest(t, f.conn, "target_verifier", op, "DONE", "PASSED", again)
	if at := f.lastPassed(t, f.conn, op); at == nil || !at.Equal(again) {
		t.Fatalf("a newer pass: %v, want %v", at, again)
	}
	f.addTest(t, f.conn, "target_verifier", op, "FAILED", "", now.Add(-3*time.Minute))
	if at := f.lastPassed(t, f.conn, op); at != nil {
		t.Fatalf("a test that could not run still leaves the earlier pass: %v", at)
	}
	// An open test does not change what the finished ones say.
	f.exec(t, `INSERT INTO pc.connection_tests (org_id, id, connection_id, kind, operation, requested_by, verification_id)
		VALUES ($1, $2, $3, 'target_verifier', $4, 'test', $5)`, f.org, ids.NewV7(), f.conn, op, f.verificationTask(t, f.conn, op))
	if at := f.lastPassed(t, f.conn, op); at != nil {
		t.Fatalf("an open test vouches: %v", at)
	}
}

// TestHR210_TheServersVerifierLiftsTheTestedRead: with the server's target
// verifier, a passing target_verifier test of a read in pc.connection_tests
// lifts that read's scope on target-enforced access to ENFORCED, with an
// expiry; a write with a passing test of its own stays PARTIAL.
func TestHR210_TheServersVerifierLiftsTheTestedRead(t *testing.T) {
	f := newFixture(t)
	f.exec(t, "UPDATE pc.connections SET access_mode = 'target_enforced' WHERE id = $1", f.conn)
	f.svc.Verifier = app.ConnectionTests{}
	const tested, write = "payments.refund.get", "payments.refund.create"
	f.boundAnHourAgo(t)
	now := f.dbNow(t)
	for _, op := range []string{tested, write} {
		f.addTest(t, f.conn, "target_verifier", op, "DONE", "PASSED", now.Add(-time.Minute))
		f.exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, connection_id, channel, mode, created_at) VALUES ($1, $2, $3, $4, $5, $6, 'ALLOW', 'OK', 'gw', $7,
			'http', 'enforce', now() - interval '2 minutes')`, f.org, ids.NewV7(), f.run, ids.NewV7(), make([]byte, 32), op, f.conn)
	}
	var revision int32
	if err := f.p.InTenantTx(context.Background(), f.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT revision FROM pc.connections WHERE id = $1", f.conn).Scan(&revision)
	}); err != nil {
		t.Fatal(err)
	}
	c := f.closure(probes(false), f.dbNow(t))
	c.Bound.ConnectionRevision = revision
	if _, err := f.record(t, c); err != nil {
		t.Fatal(err)
	}
	f.reassess(t)
	if row, s, _ := f.current(t, tested); row.State != "ENFORCED" || row.ExpiresAt == nil {
		t.Errorf("%s: %s %v, expires %v", tested, row.State, s.Reasons, row.ExpiresAt)
	}
	if row, s, _ := f.current(t, write); row.State != "PARTIAL" || !slices.Contains(s.Reasons, domain.ReasonWriteCapped) {
		t.Errorf("%s: %s %v", write, row.State, s.Reasons)
	}
}

// TestHR211_AChangedConnectionDropsTheVerifierLift: a passing
// target-verifier test vouches only for the connection it ran against. A
// new revision of the connection (its base URL here), a newly sealed
// credential, or a package pin that moved after the test drops the lift at
// once, not when the TTL runs out; a new passing test restores it.
func TestHR211_AChangedConnectionDropsTheVerifierLift(t *testing.T) {
	const op = "payments.refund.get"
	for name, change := range map[string]func(f *fixture){
		"a new revision": func(f *fixture) {
			f.exec(t, "UPDATE pc.connections SET base_url = 'https://api2.example.com', revision = revision + 1, updated_at = now() WHERE id = $1", f.conn)
		},
		"a new credential": func(f *fixture) {
			cert, key := ids.NewV7(), ids.NewV7()
			f.exec(t, `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, not_before, not_after)
				VALUES ($1, $2, $3, $4, $5, 'ENROLL', now(), now() + interval '24 hours')`, f.org, cert, f.gateway, cert[:16], bytes.Repeat([]byte("A"), 43))
			f.exec(t, `INSERT INTO pc.broker_keys (org_id, id, gateway_id, version, public_key, fingerprint, cert_id)
				VALUES ($1, $2, $3, 1, $4, 'sha256:' || encode(sha256($4), 'hex'), $5)`, f.org, key, f.gateway, bytes.Repeat([]byte{7}, 1216), cert)
			f.exec(t, `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, created_by)
				VALUES ($1, $2, $3, 1, $4, $5, '{api.example.com}', 'Authorization', 'test')`, f.org, ids.NewV7(), f.conn, key, bytes.Repeat([]byte{1}, 1200))
		},
		"a moved package pin": func(f *fixture) {
			f.d.AdminExec(t, "UPDATE pc.package_pins SET updated_at = now() WHERE org_id = $1", f.org)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.boundAnHourAgo(t)
			f.addTest(t, f.conn, "target_verifier", op, "DONE", "PASSED", f.dbNow(t).Add(-time.Minute))
			if at := f.lastPassed(t, f.conn, op); at == nil {
				t.Fatal("the passing test does not vouch before the change")
			}
			change(f)
			if at := f.lastPassed(t, f.conn, op); at != nil {
				t.Fatalf("a test from before %s still vouches: %v", name, at)
			}
			after := f.dbNow(t).Add(time.Second)
			f.addTest(t, f.conn, "target_verifier", op, "DONE", "PASSED", after)
			if at := f.lastPassed(t, f.conn, op); at == nil || !at.Equal(after.Truncate(time.Microsecond)) {
				t.Fatalf("a test after %s: %v, want %v", name, at, after)
			}
		})
	}
}
