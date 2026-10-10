// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// dispatched authorizes a refund through the default connection and moves
// its permit to DISPATCHING.
func (w *world) dispatched(run ids.UUID, charge, amount string) finalize.Result {
	w.t.Helper()
	r := w.authorize(w.request(run, ids.NewV7(), charge, amount))
	if r.Permit == "" {
		w.t.Fatalf("no permit: %s %s", r.Decision, decisive(r))
	}
	if _, err := w.auth.BeginDispatch(context.Background(), w.gw, r.PermitID, r.Epoch, finalize.Outbound{}); err != nil {
		w.t.Fatal(err)
	}
	return r
}

// claims decodes an execution receipt's pap claims (the receipt was signed
// by this test's key; only its content is checked here).
func claims(t *testing.T, jws string) map[string]any {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("receipt %q", jws)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Pap map[string]any `json:"pap"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c.Pap
}

// TestHR192_UnknownOutcomesLeaveEvidenceAndATask: an unknown outcome, from
// the gateway or the sweeper, keeps its signed execution receipt, opens a
// reconciliation task, keeps the budget held and schedules the lookup that
// may find its effect.
func TestHR192_UnknownOutcomesLeaveEvidenceAndATask(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2")
	run := w.run(w.grant("500").ID, ids.UUID{})

	reported := w.dispatched(run, "ch_1", "30.00")
	receipt, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: reported.PermitID, Outcome: finalize.Unknown, DispatchMS: -1})
	if err != nil {
		t.Fatal(err)
	}
	if kept := w.str("SELECT receipt_jws FROM pc.execution_receipts WHERE permit_id = $1", reported.PermitID); kept != receipt {
		t.Fatal("the execution receipt was not kept")
	}
	if c := claims(t, receipt); c["recorded_by"] != "gateway" || c["outcome"] != "unknown" || c["effective"] == nil || c["dispatched_at"] == nil {
		t.Fatalf("receipt claims %v", c)
	}
	if n := w.count("SELECT count(*) FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND state = 'OPEN' AND kind = 'unknown_outcome'",
		reported.TransactionID); n != 1 {
		t.Fatalf("%d open tasks", n)
	}
	if got := w.str(`SELECT purpose || ' ' || operation || ' ' || (request->>'mode') || ' ' || (request->'target'->>'id')
		FROM pc.verifications WHERE transaction_id = $1`, reported.TransactionID); got != "reconcile payments.refund.list lookup ch_1" {
		t.Fatalf("verification %q", got)
	}

	swept := w.dispatched(run, "ch_2", "20.00")
	w.db.AdminExec(t, "UPDATE pc.permits SET dispatching_at = now() - interval '1 minute' WHERE id = $1", swept.PermitID)
	if _, unknown, err := w.auth.Sweep(ctx, w.org, 30*time.Second); err != nil || unknown != 1 {
		t.Fatalf("sweep: %d unknown, %v", unknown, err)
	}
	if got := w.str("SELECT recorded_by || ' ' || outcome FROM pc.execution_attempts WHERE permit_id = $1", swept.PermitID); got != "sweeper unknown" {
		t.Fatalf("swept attempt %q", got)
	}
	sweptReceipt := w.str("SELECT receipt_jws FROM pc.execution_receipts WHERE permit_id = $1", swept.PermitID)
	if c := claims(t, sweptReceipt); c["recorded_by"] != "sweeper" || c["outcome"] != "unknown" {
		t.Fatalf("swept receipt claims %v", c)
	}
	if n := w.count("SELECT count(*) FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND state = 'OPEN'", swept.TransactionID); n != 1 {
		t.Fatalf("%d open tasks for the swept permit", n)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'receipt.execution'"); n != 2 {
		t.Fatalf("%d execution receipts in the ledger", n)
	}
	if res, sp := w.budget(); res != "50" || sp != "0" {
		t.Fatalf("both unknowns hold their reservations: reserved %s spent %s", res, sp)
	}
}

// TestHR192_ALateAcceptanceResolvesAsOccurred: a gateway that reports after
// the sweeper is heard. Accepted resolves the reconciliation as occurred and
// commits the budget; any other outcome is kept as evidence and resolves
// nothing.
func TestHR192_ALateAcceptanceResolvesAsOccurred(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2")
	run := w.run(w.grant("500").ID, ids.UUID{})
	accepted, failed := w.dispatched(run, "ch_1", "30.00"), w.dispatched(run, "ch_2", "20.00")
	w.db.AdminExec(t, "UPDATE pc.permits SET dispatching_at = now() - interval '1 minute' WHERE id = ANY($1)",
		[]ids.UUID{accepted.PermitID, failed.PermitID})
	if _, unknown, err := w.auth.Sweep(ctx, w.org, 30*time.Second); err != nil || unknown != 2 {
		t.Fatalf("sweep: %d unknown, %v", unknown, err)
	}

	r, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{
		Permit: accepted.PermitID, Outcome: finalize.Accepted, TargetStatus: 200, DispatchMS: -1, TargetRef: "re_late",
	})
	if err != nil || r != w.str("SELECT receipt_jws FROM pc.execution_receipts WHERE permit_id = $1", accepted.PermitID) {
		t.Fatalf("late acceptance: %v", err)
	}
	if got := w.str("SELECT state || ' ' || resolved_via FROM pc.reconciliation_tasks WHERE transaction_id = $1", accepted.TransactionID); got != "OCCURRED late_report" {
		t.Fatalf("task %q", got)
	}
	if got := w.str(`SELECT source || ' ' || outcome FROM pc.observations o JOIN pc.reconciliation_tasks t
		ON t.org_id = o.org_id AND t.observation_id = o.id WHERE t.transaction_id = $1`, accepted.TransactionID); got != "late_report accepted" {
		t.Fatalf("observation %q", got)
	}
	if got := w.str(`SELECT purpose || ' ' || operation || ' ' || (request->'target'->>'id') FROM pc.verifications
		WHERE transaction_id = $1 AND purpose = 'follow_up'`, accepted.TransactionID); got != "follow_up payments.refund.get re_late" {
		t.Fatalf("follow-up %q", got)
	}

	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: failed.PermitID, Outcome: finalize.Failed, TargetStatus: 402, DispatchMS: -1}); err != nil {
		t.Fatal(err)
	}
	if got := w.str("SELECT state FROM pc.reconciliation_tasks WHERE transaction_id = $1", failed.TransactionID); got != "OPEN" {
		t.Fatalf("a late failure resolved the task: %s", got)
	}
	if res, sp := w.budget(); res != "20" || sp != "30" {
		t.Fatalf("after the late reports: reserved %s spent %s", res, sp)
	}
	// Reported twice, the second acceptance changes nothing.
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: accepted.PermitID, Outcome: finalize.Accepted, DispatchMS: -1}); err != nil {
		t.Fatal(err)
	}
	if res, sp := w.budget(); res != "20" || sp != "30" {
		t.Fatalf("a repeated late report settled again: reserved %s spent %s", res, sp)
	}
}

// TestHR190_AnAcceptedRefundSchedulesItsFollowUpRead: the permit records
// what its effect is verified against, and an accepted outcome schedules
// the verifier's read of the object the target named, or the lookup when
// the reference does not match the read's pattern.
func TestHR190_AnAcceptedRefundSchedulesItsFollowUpRead(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2")
	run := w.run(w.grant("500").ID, ids.UUID{})

	good := w.dispatched(run, "ch_1", "30.00")
	if got := w.str("SELECT verify_expect::text FROM pc.permits WHERE id = $1", good.PermitID); got != `{"/amount": "30.00", "/charge": "ch_1", "/currency": "USD"}` {
		t.Fatalf("the permit expects %s", got)
	}
	if w.str("SELECT definition_digest FROM pc.permits WHERE id = $1", good.PermitID) == "" {
		t.Fatal("no definition digest on the permit")
	}
	receipt, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{
		Permit: good.PermitID, Outcome: finalize.Accepted, TargetStatus: 200, DispatchMS: 12, TargetRef: "re_0192-ab",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c := claims(t, receipt); c["target_ref"] != "re_0192-ab" || c["recorded_by"] != "gateway" {
		t.Fatalf("receipt claims %v", c)
	}
	if got := w.str(`SELECT purpose || ' ' || operation || ' ' || (request->>'mode') || ' ' || (request->'target'->>'type') || ' ' ||
		(request->'target'->>'id') FROM pc.verifications WHERE transaction_id = $1`, good.TransactionID); got != "follow_up payments.refund.get reference payments.refund re_0192-ab" {
		t.Fatalf("verification %q", got)
	}
	if n := w.count(`SELECT count(*) FROM pc.verifications v JOIN pc.permits p ON p.org_id = v.org_id AND p.transaction_id = v.transaction_id
		WHERE v.transaction_id = $1 AND v.deadline_at BETWEEN p.dispatching_at + interval '599 seconds' AND p.dispatching_at + interval '601 seconds'`,
		good.TransactionID); n != 1 {
		t.Fatal("the deadline is not the verifier's window from dispatch")
	}
	if got := w.str("SELECT effect_level_required FROM pc.transactions WHERE id = $1", good.TransactionID); got != "acceptance" {
		t.Fatalf("required level %q", got)
	}

	bad := w.dispatched(run, "ch_2", "20.00")
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{
		Permit: bad.PermitID, Outcome: finalize.Accepted, TargetStatus: 200, DispatchMS: 12, TargetRef: "ch_2/../re_x",
	}); err != nil {
		t.Fatal(err)
	}
	if n := w.count("SELECT count(*) FROM pc.execution_attempts WHERE permit_id = $1 AND target_ref IS NULL", bad.PermitID); n != 1 {
		t.Fatal("a reference outside the read's pattern was kept")
	}
	if got := w.str("SELECT operation || ' ' || (request->>'mode') FROM pc.verifications WHERE transaction_id = $1", bad.TransactionID); got != "payments.refund.list lookup" {
		t.Fatalf("verification %q", got)
	}
}
