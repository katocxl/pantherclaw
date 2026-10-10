// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	tdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// verifier is the server side of verification over the world's database,
// signing effect receipts with the Authority's receipt key.
func (w *world) verifier() *tapp.Service {
	return &tapp.Service{Store: &pgtransactions.Store{Pool: w.pool}, Receipts: w.auth.Receipts}
}

// recorded dispatches a refund and records outcome o (with ref for an
// accepted one), then makes its verification due now.
func (w *world) recorded(run ids.UUID, charge, amount string, o finalize.Outcome, ref string) finalize.Result {
	w.t.Helper()
	r := w.dispatched(run, charge, amount)
	if _, err := w.auth.RecordExecution(context.Background(), w.gw, finalize.Execution{
		Permit: r.PermitID, Outcome: o, TargetStatus: 200, DispatchMS: 5, TargetRef: ref,
	}); err != nil {
		w.t.Fatal(err)
	}
	w.db.AdminExec(w.t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1", r.TransactionID)
	return r
}

// lease claims the one due task of txn.
func (w *world) lease(s *tapp.Service, txn ids.UUID) tapp.Lease {
	w.t.Helper()
	leases, err := s.Claim(context.Background(), w.org, w.gwID, 16)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, l := range leases {
		if l.Correlate == "pc-"+txn.String() {
			return l
		}
	}
	w.t.Fatalf("no lease for %s among %d", txn, len(leases))
	return tapp.Lease{}
}

func refund(status, amount string) map[string]string {
	return map[string]string{"/charge": "ch_1", "/amount": amount, "/currency": "USD", "/status": status}
}

// TestHR190_LeasesAreSingleUseAndStopUnderContainment: only the gateway
// serving the connection leases a task, once; a report needs its live
// lease and only declared fields; reads stop under the kill switch and a
// quarantine.
func TestHR190_LeasesAreSingleUseAndStopUnderContainment(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})
	r := w.recorded(run, "ch_1", "30.00", finalize.Accepted, "re_1")

	other := ids.NewV7()
	exec(t, w.pool, w.org, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other', 'test')", w.org, other)
	if l, err := s.Claim(ctx, w.org, other, 16); err != nil || len(l) != 0 {
		t.Fatalf("another gateway leased %d: %v", len(l), err)
	}
	w.db.AdminExec(t, "UPDATE pc.org_containment SET kill_switch = true, engaged_by = 'test', engaged_at = now() WHERE org_id = $1", w.org)
	if l, _ := s.Claim(ctx, w.org, w.gwID, 16); len(l) != 0 {
		t.Fatal("a read was leased under the kill switch")
	}
	w.db.AdminExec(t, "UPDATE pc.org_containment SET kill_switch = false, engaged_by = NULL, engaged_at = NULL WHERE org_id = $1", w.org)
	w.db.AdminExec(t, "UPDATE pc.connections SET state = 'QUARANTINED', quarantine_reason = 'test' WHERE id = $1", w.conn)
	if l, _ := s.Claim(ctx, w.org, w.gwID, 16); len(l) != 0 {
		t.Fatal("a read was leased on a quarantined connection")
	}
	w.db.AdminExec(t, "UPDATE pc.connections SET state = 'ACTIVE', quarantine_reason = NULL WHERE id = $1", w.conn)

	l := w.lease(s, r.TransactionID)
	if l.Operation != "payments.refund.get" || l.Purpose != tdomain.PurposeFollowUp || len(l.Secret) != 32 {
		t.Fatalf("lease %+v", l)
	}
	if again, _ := s.Claim(ctx, w.org, w.gwID, 16); len(again) != 0 {
		t.Fatal("a leased task was leased again")
	}
	if n := w.count("SELECT count(*) FROM pc.verifications WHERE id = $1 AND lease_hash = sha256($2)", l.Task, l.Secret); n != 1 {
		t.Fatal("the lease secret is not stored as its SHA-256")
	}
	wrong := append([]byte{}, l.Secret...)
	wrong[0] ^= 1
	for name, c := range map[string]struct {
		gw     ids.UUID
		secret []byte
	}{"another secret": {w.gwID, wrong}, "another gateway": {other, l.Secret}} {
		if _, err := s.Report(ctx, w.org, c.gw, tapp.Report{Task: l.Task, Secret: c.secret, HTTPStatus: 200, Found: true, Fields: refund("succeeded", "30.00")}); !errors.Is(err, tapp.ErrLease) {
			t.Errorf("%s: %v, want ErrLease", name, err)
		}
	}
	undeclared := refund("succeeded", "30.00")
	undeclared["/customer/email"] = "a@example.test"
	if _, err := s.Report(ctx, w.org, w.gwID, tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: undeclared}); !errors.Is(err, tapp.ErrUndeclared) {
		t.Fatalf("an undeclared field: %v", err)
	}
	if _, err := s.Report(ctx, w.org, w.gwID, tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: refund("succeeded", "30.00")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Report(ctx, w.org, w.gwID, tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: refund("succeeded", "30.00")}); !errors.Is(err, tapp.ErrLease) {
		t.Fatalf("a used lease: %v", err)
	}
}

// TestHR191_ReportsBecomeAppendedEffectReceipts: a pending refund is
// PROPAGATION_PENDING and read again; settled, it is CONFIRMED at follow-up
// level; a refund whose amount differs is CONFLICTING and opens a task.
func TestHR191_ReportsBecomeAppendedEffectReceipts(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})

	r := w.recorded(run, "ch_1", "30.00", finalize.Accepted, "re_1")
	l := w.lease(s, r.TransactionID)
	a, err := s.Report(ctx, w.org, w.gwID, tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: refund("pending", "30.00")})
	if err != nil || a.State != tdomain.PropagationPending || a.Done {
		t.Fatalf("pending: %+v %v", a, err)
	}
	if got := w.str("SELECT state FROM pc.verifications WHERE id = $1", l.Task); got != "PENDING" {
		t.Fatalf("a pending read is not retried: %s", got)
	}
	w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE id = $1", l.Task)
	l = w.lease(s, r.TransactionID)
	if a, err = s.Report(ctx, w.org, w.gwID, tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: refund("succeeded", "30.00")}); err != nil || a.State != tdomain.Confirmed || !a.Done {
		t.Fatalf("settled: %+v %v", a, err)
	}
	if got := w.str("SELECT string_agg(state || '/' || basis, ',' ORDER BY seq) FROM pc.effect_receipts WHERE transaction_id = $1", r.TransactionID); got != "PROPAGATION_PENDING/verifier,CONFIRMED/verifier" {
		t.Fatalf("receipts %s", got)
	}
	if got := w.str("SELECT effect_state || ' ' || effect_level_achieved FROM pc.transactions WHERE id = $1", r.TransactionID); got != "CONFIRMED follow_up" {
		t.Fatalf("transaction effect %s", got)
	}
	jws := w.str("SELECT receipt_jws FROM pc.effect_receipts WHERE transaction_id = $1 AND seq = 2", r.TransactionID)
	if c := claims(t, jws); c["state"] != "CONFIRMED" || c["achieved"] != "follow_up" || c["expected_sha256"] == nil || c["limits"] == nil ||
		c["verifier"].(map[string]any)["operation"] != "payments.refund.get" {
		t.Fatalf("effect receipt claims %v", c)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'receipt.effect'"); n != 2 {
		t.Fatalf("%d effect receipts in the ledger", n)
	}

	w.refundable("ch_1")
	differs := w.recorded(run, "ch_1", "40.00", finalize.Accepted, "re_2")
	l = w.lease(s, differs.TransactionID)
	if a, err = s.Report(ctx, w.org, w.gwID, tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: refund("succeeded", "400.00")}); err != nil || a.State != tdomain.Conflicting {
		t.Fatalf("differs: %+v %v", a, err)
	}
	if n := w.count("SELECT count(*) FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'conflicting_effect' AND state = 'OPEN'", differs.TransactionID); n != 1 {
		t.Fatal("a conflicting effect opened no task")
	}
}

// TestHR192_EvidenceResolvesAnUnknownOnlyAsOccurred: a lookup that finds
// the refund resolves the reconciliation and commits the budget; one that
// shows it absent from a complete listing after the window is evidence for
// a person, and releases nothing.
func TestHR192_EvidenceResolvesAnUnknownOnlyAsOccurred(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})

	found := w.recorded(run, "ch_1", "30.00", finalize.Unknown, "")
	l := w.lease(s, found.TransactionID)
	if l.Operation != "payments.refund.list" || l.Purpose != tdomain.PurposeReconcile {
		t.Fatalf("lease %+v", l)
	}
	a, err := s.Report(ctx, w.org, w.gwID, tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Complete: true, Fields: refund("succeeded", "30.00")})
	if err != nil || !a.Resolved || a.State != tdomain.Confirmed {
		t.Fatalf("found: %+v %v", a, err)
	}
	if got := w.str("SELECT state || ' ' || resolved_via FROM pc.reconciliation_tasks WHERE transaction_id = $1", found.TransactionID); got != "OCCURRED verifier" {
		t.Fatalf("task %s", got)
	}
	if res, sp := w.budget(); res != "0" || sp != "30" {
		t.Fatalf("found: reserved %s spent %s, want committed", res, sp)
	}

	absent := w.recorded(run, "ch_2", "20.00", finalize.Unknown, "")
	l = w.lease(s, absent.TransactionID)
	if a, err = s.Report(ctx, w.org, w.gwID, tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Complete: true}); err != nil || a.State != "" || a.Done {
		t.Fatalf("absent within the window: %+v %v", a, err)
	}
	w.db.AdminExec(t, "UPDATE pc.permits SET dispatching_at = now() - interval '11 minutes' WHERE transaction_id = $1", absent.TransactionID)
	w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1", absent.TransactionID)
	l = w.lease(s, absent.TransactionID)
	if a, err = s.Report(ctx, w.org, w.gwID, tapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Complete: true}); err != nil || a.State != tdomain.NoneConfirmed || a.Resolved {
		t.Fatalf("absent after the window: %+v %v", a, err)
	}
	if got := w.str("SELECT state FROM pc.reconciliation_tasks WHERE transaction_id = $1", absent.TransactionID); got != "OPEN" {
		t.Fatalf("evidence of absence resolved the task: %s", got)
	}
	if res, sp := w.budget(); res != "20" || sp != "30" {
		t.Fatalf("absent: reserved %s spent %s, want 20 still held", res, sp)
	}
}

// TestHR191_ClosedWindowsEndInUnknown: an expired lease returns to the
// queue, and a task whose window closed without a conclusive read ends with
// an UNKNOWN effect receipt.
func TestHR191_ClosedWindowsEndInUnknown(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})

	leased := w.recorded(run, "ch_1", "30.00", finalize.Accepted, "re_1")
	l := w.lease(s, leased.TransactionID)
	w.db.AdminExec(t, "UPDATE pc.verifications SET leased_at = leased_at - interval '1 minute', lease_expires_at = lease_expires_at - interval '1 minute' WHERE id = $1", l.Task)
	closed := w.recorded(run, "ch_2", "20.00", finalize.Accepted, "re_2")
	w.db.AdminExec(t, "UPDATE pc.verifications SET created_at = now() - interval '1 hour', deadline_at = now() - interval '1 second' WHERE transaction_id = $1", closed.TransactionID)

	if n, err := s.Expire(ctx, w.org); err != nil || n != 1 {
		t.Fatalf("expire ended %d: %v", n, err)
	}
	if got := w.str("SELECT state FROM pc.verifications WHERE id = $1", l.Task); got != "PENDING" {
		t.Fatalf("an expired lease: %s", got)
	}
	if got := w.str("SELECT state || ' ' || basis FROM pc.effect_receipts WHERE transaction_id = $1", closed.TransactionID); got != "UNKNOWN deadline" {
		t.Fatalf("a closed window: %s", got)
	}
}
