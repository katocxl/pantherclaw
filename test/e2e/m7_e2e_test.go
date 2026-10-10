// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/sim/payments"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// row reads one text row of the seeded org.
func (s *stack) row(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var out string
	err := s.db.AppPool(t).InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&out)
	})
	if err != nil && !db.IsNoRows(err) {
		t.Fatal(err)
	}
	return out
}

// eventually polls sql until it returns want, for at most 45 seconds.
func (s *stack) eventually(t *testing.T, want, sql string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	got := ""
	for time.Now().Before(deadline) {
		if got = s.row(t, sql, args...); got == want {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("%s: %q, want %q", sql, got, want)
}

// TestE2E_M7_RefundConfirmedByVerifier: a refund through the gateway
// gets its execution receipt and, from the verifier's read through the same
// gateway, a CONFIRMED effect receipt at follow-up level (G0 M7 exit).
func TestE2E_M7_RefundConfirmedByVerifier(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("refund: %d %+v", code, r)
	}
	if got := s.row(t, "SELECT recorded_by || ' ' || coalesce(target_ref, '') FROM pc.execution_attempts WHERE transaction_id = $1", r.TransactionID); got[:8] != "gateway " || len(got) < 12 {
		t.Fatalf("attempt %q: no target reference", got)
	}
	s.eventually(t, "CONFIRMED follow_up verifier",
		"SELECT state || ' ' || coalesce(level_achieved, '') || ' ' || basis FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1",
		r.TransactionID)
	if got := s.row(t, "SELECT effect_state FROM pc.transactions WHERE id = $1", r.TransactionID); got != "CONFIRMED" {
		t.Fatalf("transaction effect %q", got)
	}

	// The explorer shows the execution state beside the effect state, with
	// every receipt (F479).
	txn, err := ids.ParseUUID(r.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := (&txapp.Explorer{Pool: s.pool}).TransactionEvidence(s.person(t, "reconciler", td.RoleReconciler).ctx, txn)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Transaction.Execution != txdomain.Accepted || ev.Transaction.Effect != txdomain.Confirmed || len(ev.Decisions) != 1 ||
		ev.Execution == nil || ev.Execution.TargetRef == "" || len(ev.Observations) == 0 || len(ev.Effects) == 0 {
		t.Fatalf("evidence %+v", ev)
	}
}

// TestE2E_M7_EffectWithoutReceipt: a refund made at the
// target without PantherClaw (its own console, or a leaked credential)
// shows up in the connection's target log with no receipt to match, and is
// reported as an effect without a receipt; the refund made through the
// gateway is matched (HR-112).
func TestE2E_M7_EffectWithoutReceipt(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusOK {
		t.Fatalf("refund: %d %+v", code, r)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.simURL+"/v1/refunds",
		strings.NewReader(`{"charge":"ch_9","amount":"75.00","currency":"USD","reason":"requested_by_customer"}`))
	req.Header.Set("Idempotency-Key", "console-0001")
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("out-of-band refund: %v %v", res, err)
	}
	_ = res.Body.Close()

	// The worker schedules target logs every 15 minutes; here, as often as
	// the last task ends, until a run has seen both refunds.
	logs := &txapp.Service{Store: &pgtransactions.Store{Pool: s.db.AppPool(t)}}
	deadline := time.Now().Add(45 * time.Second)
	for s.row(t, "SELECT coalesce(max(items_seen), 0)::text FROM pc.target_log_runs") != "2" {
		if time.Now().After(deadline) {
			t.Fatal("no target-log run saw both refunds")
		}
		if _, err := logs.ScheduleTargetLogs(context.Background(), s.org); err != nil {
			t.Fatal(err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if got := s.row(t, "SELECT string_agg(coalesce(correlation, ''), ',') FROM pc.unreceipted_effects"); got != "console-0001" {
		t.Fatalf("unreceipted effects %q", got)
	}
	if got := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.security.effect_without_receipt'"); got != "1" {
		t.Fatalf("%s security events", got)
	}
	if got := s.row(t, "SELECT count(*)::text FROM pc.notifications WHERE type = 'security.effect_without_receipt'"); got != "1" {
		t.Fatalf("%s notifications to admins", got)
	}
}

// TestE2E_M7_UnknownRefundFoundByVerifier: S07 with a lost answer.
// The refund happened but the gateway timed out: UNKNOWN, budget held. The
// verifier's lookup finds it by its idempotency key and resolves the
// reconciliation as occurred, committing the budget (HR-192).
func TestE2E_M7_UnknownRefundFoundByVerifier(t *testing.T) {
	s := start(t, options{budget: "1000.00", faults: payments.Faults{LoseRate: 1, HangFor: time.Minute}, timeout: 500 * time.Millisecond})
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusGatewayTimeout || r.Outcome != "UNKNOWN" {
		t.Fatalf("lost answer: %d %+v", code, r)
	}
	// Either evidence may find it first: the verifier's lookup, or the
	// connection's target log (scheduled when the server starts); both
	// resolve only towards occurred.
	s.eventually(t, "OCCURRED", "SELECT state FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID)
	if via := s.row(t, "SELECT resolved_via FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID); via != "verifier" && via != "target_log" {
		t.Fatalf("resolved via %q, want evidence", via)
	}
	s.eventually(t, "CONFIRMED", "SELECT state FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID)
	if reserved, spent, _ := s.budget(t, r.TransactionID); reserved != "0" || spent != "30" {
		t.Fatalf("after reconciling: reserved %s spent %s, want committed", reserved, spent)
	}
}

// reconciler is a Reconciler of the seeded org, and what they act through:
// the reconciliation use cases, signing effect receipts with the server's
// receipts key.
func (s *stack) reconciler(t *testing.T) (context.Context, *txapp.Reconciler) {
	t.Helper()
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(context.Background(), s.pool, kp, reg); err != nil {
		t.Fatal(err)
	}
	receipts, err := reg.Signer(keys.PurposeReceipts)
	if err != nil {
		t.Fatal(err)
	}
	p := s.person(t, "reconciler", td.RoleReconciler)
	return p.ctx, &txapp.Reconciler{
		Store: &pgtransactions.Store{Pool: s.pool}, Effects: &txapp.Service{Store: &pgtransactions.Store{Pool: s.pool}, Receipts: receipts},
	}
}

// TestE2E_M7_ConflictingObservation: the target accepts a refund but
// records it a cent short. The verifier's read through the gateway
// disagrees with what was asked: the effect is CONFLICTING, both sides are
// kept, a conflicting-effect reconciliation opens and the committed budget
// stays committed. A Reconciler then records it as occurred, naming the
// verifier's observation as authoritative; the budget still does not move
// (HR-191, HR-192).
func TestE2E_M7_ConflictingObservation(t *testing.T) {
	s := start(t, options{budget: "1000.00", faults: payments.Faults{ShortRate: 1}})
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("refund: %d %+v", code, r)
	}
	s.eventually(t, "CONFLICTING verifier",
		"SELECT state || ' ' || basis FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID)
	s.eventually(t, "OPEN", "SELECT state FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'conflicting_effect'", r.TransactionID)
	// Both sides are kept: what was asked in the decision, what the target
	// recorded in the observation.
	if got := s.row(t, "SELECT fields->>'/amount' FROM pc.observations WHERE transaction_id = $1 ORDER BY observed_at DESC LIMIT 1", r.TransactionID); got != "29.99" {
		t.Fatalf("observed amount %q", got)
	}
	if reserved, spent, _ := s.budget(t, r.TransactionID); reserved != "0" || spent != "30" {
		t.Fatalf("a conflicting effect: reserved %s spent %s, want committed", reserved, spent)
	}

	ctx, rec := s.reconciler(t)
	task, err := ids.ParseUUID(s.row(t, "SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'conflicting_effect'", r.TransactionID))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := ids.ParseUUID(s.row(t, "SELECT id::text FROM pc.observations WHERE transaction_id = $1 ORDER BY observed_at DESC LIMIT 1", r.TransactionID))
	if err != nil {
		t.Fatal(err)
	}
	k, err := rec.ResolveOccurred(ctx, txapp.Resolution{
		Reconciliation: task, Basis: "The processor's dashboard shows the refund at 29.99; the cent is a processor fee.",
		Evidence: []ids.UUID{obs}, Authoritative: &obs,
	})
	if err != nil || k.State != txdomain.TaskOccurred || k.Observation == nil || *k.Observation != obs {
		t.Fatalf("resolved %+v %v", k, err)
	}
	if got := s.row(t, "SELECT state || ' ' || basis FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID); got != "CONFIRMED person" {
		t.Fatalf("after the person: %q", got)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.effect_receipts WHERE transaction_id = $1 AND state = 'CONFLICTING'", r.TransactionID); n != "1" {
		t.Fatalf("%s conflicting receipts kept", n)
	}
	if reserved, spent, _ := s.budget(t, r.TransactionID); reserved != "0" || spent != "30" {
		t.Fatalf("after resolving: reserved %s spent %s", reserved, spent)
	}
}
