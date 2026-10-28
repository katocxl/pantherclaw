// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// TestHR206_AnUnknownConsequenceIsAuditedAsNotVerified (G0 M8 W1c): a
// confirmed action whose decision could not rule a consequence out
// (UNKNOWN, as the deployment of an approved merge whose facts were
// missing) opens nothing for it, since it names no environment to look it
// up by, and the consequence is audited as not verified
// (CONSEQUENCE_UNKNOWN) rather than left without a word. A consequence
// ruled out (NOT_TRIGGERED) is neither opened nor audited. A person's
// "occurred" audits it too, even when the verifier captures nothing.
func TestHR206_AnUnknownConsequenceIsAuditedAsNotVerified(t *testing.T) {
	w := newWorldWith(t, verifiedPayouts)
	w.refundable("ch_1", "ch_2")
	g := w.heldRefunds([]string{"payments.refund.create", "payments.refund.get", "payments.payout.trigger"})
	run := w.run(g.ID, ids.UUID{})
	s := w.verifier()
	ctx := context.Background()

	confirmed := func(charge, ref, state string) ids.UUID {
		t.Helper()
		w.payouts(charge, `{"state": "scheduled", "environments": ["payroll"]}`)
		r := w.recorded(run, charge, "30.00", finalize.Accepted, ref)
		// What the latest evaluation said of the payout, as the decision
		// would have recorded it had the payout fact been missing (UNKNOWN)
		// or ruled it out (NOT_TRIGGERED).
		unknown := `[]`
		if state == "UNKNOWN" {
			unknown = `[{"fact": "payments.charge.payouts", "reason": "MISSING"}]`
		}
		w.db.AdminExec(t, `UPDATE pc.decision_consequences SET state = $1, environments = '{}', unknown = $2::jsonb
			WHERE org_id = $3 AND transaction_id = $4`, state, unknown, w.org, r.TransactionID)
		l := w.lease(s, r.TransactionID)
		fields := refundOf(charge, "succeeded", "30.00")
		fields["/id"] = ref
		if a, err := s.Report(ctx, w.org, w.gwID, txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: fields}); err != nil ||
			a.State != txdomain.Confirmed {
			t.Fatalf("%s: confirm %+v %v", charge, a, err)
		}
		if n := w.count("SELECT count(*) FROM pc.transaction_links WHERE from_transaction_id = $1", r.TransactionID); n != 0 {
			t.Fatalf("%s: %d consequences opened for a %s payout", charge, n, state)
		}
		return r.TransactionID
	}
	audited := func(txn ids.UUID) (all, unknown int) {
		const q = `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.transaction.consequence_not_verified'
			AND convert_from(body, 'UTF8')::jsonb #>> '{object,id}' = $2`
		return w.count(q, w.org, txn.String()),
			w.count(q+` AND convert_from(body, 'UTF8')::jsonb ->> 'reason_code' = 'CONSEQUENCE_UNKNOWN'`, w.org, txn.String())
	}

	txn := confirmed("ch_1", "re_1", "UNKNOWN")
	if all, unknown := audited(txn); all != 1 || unknown != 1 {
		t.Fatalf("an unknown payout: %d not-verified events, %d CONSEQUENCE_UNKNOWN, want 1 and 1", all, unknown)
	}
	txn = confirmed("ch_2", "re_2", "NOT_TRIGGERED")
	if all, _ := audited(txn); all != 0 {
		t.Fatalf("a payout ruled out: %d not-verified events", all)
	}

	// A person's "occurred" confirms an action whose verifier captures
	// nothing (so no consequence is ever opened by it): its UNKNOWN payout
	// is audited all the same.
	p := newWorldWith(t, pipelinetest.PayoutConsequence)
	p.refundable("ch_3")
	pg := p.heldRefunds([]string{"payments.refund.create", "payments.refund.get", "payments.payout.trigger"})
	ps := p.verifier()
	p.payouts("ch_3", `{"state": "scheduled", "environments": ["payroll"]}`)
	r := p.recorded(p.run(pg.ID, ids.UUID{}), "ch_3", "30.00", finalize.Unknown, "")
	p.db.AdminExec(t, `UPDATE pc.decision_consequences SET state = 'UNKNOWN', environments = '{}',
		unknown = '[{"fact": "payments.charge.payouts", "reason": "MISSING"}]'::jsonb WHERE org_id = $1 AND transaction_id = $2`, p.org, r.TransactionID)
	task, err := ids.ParseUUID(p.str(`SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'unknown_outcome'`, r.TransactionID))
	if err != nil {
		t.Fatal(err)
	}
	person, _ := p.reconciler("rita")
	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: p.pool}, Effects: ps}
	if _, err := rec.ResolveOccurred(person, txapp.Resolution{Reconciliation: task, Basis: "the bank shows the refund"}); err != nil {
		t.Fatal(err)
	}
	const q = `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.transaction.consequence_not_verified'
		AND convert_from(body, 'UTF8')::jsonb #>> '{object,id}' = $2 AND convert_from(body, 'UTF8')::jsonb ->> 'reason_code' = 'CONSEQUENCE_UNKNOWN'`
	if n := p.count(q, p.org, r.TransactionID.String()); n != 1 {
		t.Fatalf("a person's occurred without a capturing verifier: %d CONSEQUENCE_UNKNOWN events, want 1", n)
	}
	if n := p.count("SELECT count(*) FROM pc.transaction_links WHERE from_transaction_id = $1", r.TransactionID); n != 0 {
		t.Fatalf("%d consequences opened for an unknown payout", n)
	}
}
