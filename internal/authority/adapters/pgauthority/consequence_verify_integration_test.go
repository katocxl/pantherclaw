// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// verifiedPayouts is the payout consequence (pipelinetest) shaped as
// pc.github's deployment (G0 M8 W1c): the refund's verifier captures the
// refund's id, and the payout's own verifier finds the payout of that
// refund to that environment by a matched lookup, then reads its
// statuses, newest first.
func verifiedPayouts(pkg string) string {
	pkg = pipelinetest.PayoutConsequence(pkg)
	pkg = strings.Replace(pkg, "      limits: >-\n        Shows that the simulated refund object exists",
		"      capture:\n        refund: /id\n      limits: >-\n        Shows that the simulated refund object exists", 1)
	pkg = strings.Replace(pkg, "    params: {}\n    effects:\n      - kind: funds.transfer\n", `    params:
      refund:
        type: identifier
        pattern: '^re_[A-Za-z0-9-]{1,64}$'
      environment:
        type: identifier
        pattern: '^[a-z]{1,32}$'
    effects:
      - kind: funds.transfer
`, 1)
	pkg = strings.Replace(pkg, "      on_unknown: reconcile\n    approval:\n      title: Release a payout", `      on_unknown: reconcile
    verifier:
      operation: payments.payout.statuses
      establishes: payout.paid
      within_seconds: 3600
      lookup:
        operation: payments.payout.list
        list:
          items: /data
          id: /id
        match:
          - field: /refund
            equals: params.refund
          - field: /environment
            equals: params.environment
        id_param: payout_id
      states:
        field: /0/state
        confirmed: [paid, superseded]
        pending: [in_transit]
        reconcile: [failed, canceled]
    approval:
      title: Release a payout`, 1)
	const reads = `  - operation: payments.payout.list
    summary: List the payouts of a refund to an environment
    access: read
    target:
      type: payments.charge
      id_pattern: '^ch_[A-Za-z0-9]{1,64}$'
      account: none
    params:
      refund:
        type: identifier
        required: true
        pattern: '^re_[A-Za-z0-9-]{1,64}$'
      environment:
        type: identifier
        required: true
        pattern: '^[a-z]{1,32}$'
    effects:
      - kind: none
        description: Reads only
    reversibility: reversible
    retry:
      safe: true
      on_unknown: fail
    assurance:
      basis: declared
      reviewed_by: [pantherclaw-maintainers]
      valid_until: 2027-10-08
    dispatch:
      http:
        method: GET
        path: /v1/payouts
        query:
          refund: params.refund
          environment: params.environment

  - operation: payments.payout.statuses
    summary: Read a payout's statuses, newest first
    access: read
    target:
      type: payments.charge
      id_pattern: '^ch_[A-Za-z0-9]{1,64}$'
      account: none
    params:
      payout_id:
        type: identifier
        required: true
        pattern: '^po_[A-Za-z0-9]{1,64}$'
    effects:
      - kind: none
        description: Reads only
    reversibility: reversible
    retry:
      safe: true
      on_unknown: fail
    assurance:
      basis: declared
      reviewed_by: [pantherclaw-maintainers]
      valid_until: 2027-10-08
    dispatch:
      http:
        method: GET
        path: /v1/payouts/{params.payout_id}/statuses

`
	const anchor = "# What the simulated API created"
	return strings.Replace(pkg, anchor, reads+anchor, 1)
}

// TestHR206_AConfirmedActionsConsequenceIsVerifiedOnItsOwn (G0 M8 W1c,
// coordinator decision 2026-10-13): once the refund's verifier confirms it,
// the server opens a transaction for the payout it predicted, never
// dispatched, linked as its consequence and verified by a matched lookup of
// the captured refund and the environment. Each status row is tested:
// paid and superseded confirm it; in transit is pending; failed and
// canceled are a person's question, never NONE_CONFIRMED by evidence; so is
// nothing found by the deadline, whether a report or the expiry job finds
// it; a failed read changes nothing and is read again.
func TestHR206_AConfirmedActionsConsequenceIsVerifiedOnItsOwn(t *testing.T) {
	w := newWorldWith(t, verifiedPayouts)
	charges := []string{"ch_1", "ch_2", "ch_3", "ch_4", "ch_5", "ch_6", "ch_7", "ch_8"}
	w.refundable(charges...)
	g := w.heldRefunds([]string{"payments.refund.create", "payments.refund.get", "payments.payout.trigger"})
	run := w.run(g.ID, ids.UUID{})
	s := w.verifier()
	ctx := context.Background()

	// opened refunds charge, confirms it, and returns the consequence the
	// server opened, due now.
	opened := func(charge string) (parent, cons ids.UUID) {
		t.Helper()
		w.payouts(charge, `{"state": "scheduled", "environments": ["payroll"]}`)
		ref := "re_" + strings.TrimPrefix(charge, "ch_")
		r := w.recorded(run, charge, "30.00", finalize.Accepted, ref)
		l := w.lease(s, r.TransactionID)
		fields := refundOf(charge, "succeeded", "30.00")
		fields["/id"] = ref
		if a, err := s.Report(ctx, w.org, w.gwID, txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: fields}); err != nil ||
			a.State != txdomain.Confirmed {
			t.Fatalf("%s: confirm %+v %v", charge, a, err)
		}
		id, err := ids.ParseUUID(w.str(`SELECT to_transaction_id::text FROM pc.transaction_links WHERE from_transaction_id = $1 AND kind = 'consequence'`,
			r.TransactionID))
		if err != nil {
			t.Fatalf("%s: no consequence: %v", charge, err)
		}
		if got := w.str(`SELECT t.operation || ' ' || t.decision || ' ' || t.reason_code || ' ' || t.target_id || ' ' ||
			(v.request -> 'params' ->> 'refund') || ' ' || (v.request -> 'params' ->> 'environment') || ' ' || v.operation
			FROM pc.transactions t JOIN pc.verifications v ON v.transaction_id = t.id AND v.purpose = 'consequence' WHERE t.id = $1`, id); got !=
			"payments.payout.trigger ALLOW CONSEQUENCE "+charge+" "+ref+" payroll payments.payout.list" {
			t.Fatalf("%s: the consequence %q", charge, got)
		}
		w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1", id)
		return r.TransactionID, id
	}
	report := func(cons ids.UUID, status int, found bool, state string) txapp.Applied {
		t.Helper()
		w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", cons)
		l := w.lease(s, cons)
		r := txapp.Report{Task: l.Task, Secret: l.Secret, HTTPStatus: status, Found: found, Complete: true}
		if state != "" {
			r.Fields = map[string]string{"/0/state": state}
		}
		a, err := s.Report(ctx, w.org, w.gwID, r)
		if err != nil {
			t.Fatalf("report %s: %v", state, err)
		}
		return a
	}
	effect := func(id ids.UUID) string {
		return w.str("SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1", id)
	}
	open := func(id ids.UUID) int {
		return w.count(`SELECT count(*) FROM pc.reconciliation_tasks WHERE transaction_id = $1 AND kind = 'consequence_unconfirmed' AND state = 'OPEN'`, id)
	}

	// Paid, after in transit: pending, then confirmed.
	parent, cons := opened("ch_1")
	if a := report(cons, 200, true, "in_transit"); a.State != txdomain.PropagationPending || effect(cons) != "PROPAGATION_PENDING" {
		t.Fatalf("in transit: %+v %s", a, effect(cons))
	}
	if a := report(cons, 200, true, "paid"); a.State != txdomain.Confirmed || effect(cons) != "CONFIRMED" || open(cons) != 0 {
		t.Fatalf("paid: %+v %s", a, effect(cons))
	}
	if effect(parent) != "CONFIRMED" || w.count("SELECT count(*) FROM pc.effect_receipts WHERE transaction_id = $1", cons) != 2 {
		t.Fatalf("the refund %s, %d receipts of the payout", effect(parent), w.count("SELECT count(*) FROM pc.effect_receipts WHERE transaction_id = $1", cons))
	}
	if n := w.count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.transaction.consequence_opened'
		AND convert_from(body, 'UTF8')::jsonb #>> '{object,id}' = $2`, w.org, cons.String()); n != 1 {
		t.Fatalf("%d audit events", n)
	}

	// Superseded: it was paid.
	_, cons = opened("ch_2")
	if a := report(cons, 200, true, "superseded"); a.State != txdomain.Confirmed {
		t.Fatalf("superseded: %+v", a)
	}

	// Failed and canceled: a person decides; evidence never says it did not
	// happen.
	for _, ch := range []string{"ch_3", "ch_4"} {
		_, cons = opened(ch)
		status := map[string]string{"ch_3": "failed", "ch_4": "canceled"}[ch]
		if a := report(cons, 200, true, status); a.State != "" || !a.Done || open(cons) != 1 || effect(cons) == "NONE_CONFIRMED" {
			t.Fatalf("%s: %+v %s, %d open", status, a, effect(cons), open(cons))
		}
	}
	// A person who checked records the canceled payout as occurred after all.
	rctx, _ := w.reconciler("rita")
	task, err := ids.ParseUUID(w.str(`SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1`, cons))
	if err != nil {
		t.Fatal(err)
	}
	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: s}
	if _, err := rec.ResolveOccurred(rctx, txapp.Resolution{Reconciliation: task, Basis: "the bank shows it paid"}); err != nil ||
		effect(cons) != "CONFIRMED" {
		t.Fatalf("a person's occurred: %v %s", err, effect(cons))
	}

	// Nothing found: pending within the window, a person's question after it.
	_, cons = opened("ch_5")
	if a := report(cons, 200, false, ""); a.State != txdomain.PropagationPending || open(cons) != 0 {
		t.Fatalf("not found yet: %+v", a)
	}
	w.db.AdminExec(t, "UPDATE pc.verifications SET basis_at = now() - interval '2 hours' WHERE transaction_id = $1", cons)
	if a := report(cons, 200, false, ""); !a.Done || open(cons) != 1 {
		t.Fatalf("not found after the window: %+v, %d open", a, open(cons))
	}

	// Nothing reported by the deadline: the expiry job asks a person.
	_, cons = opened("ch_6")
	w.db.AdminExec(t, `UPDATE pc.verifications SET created_at = now() - interval '2 hours', basis_at = now() - interval '2 hours',
		deadline_at = now() - interval '1 second' WHERE transaction_id = $1`, cons)
	if _, err := s.Expire(ctx, w.org); err != nil {
		t.Fatal(err)
	}
	if open(cons) != 1 || effect(cons) != "UNKNOWN" {
		t.Fatalf("at the deadline: %d open, %s", open(cons), effect(cons))
	}

	// A failed read changes nothing and is read again.
	_, cons = opened("ch_7")
	if a := report(cons, 502, false, ""); a.State != "" || a.Done || effect(cons) != "" || open(cons) != 0 ||
		w.str("SELECT state FROM pc.verifications WHERE transaction_id = $1", cons) != "PENDING" {
		t.Fatalf("a failed read: %+v %s", a, effect(cons))
	}
}
