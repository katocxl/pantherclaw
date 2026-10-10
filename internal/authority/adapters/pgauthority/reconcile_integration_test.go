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
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// reconciler is a person of the org, bound as Reconciler at the org.
func (w *world) reconciler(name string) (context.Context, ids.UUID) {
	id := ids.NewV7()
	exec(w.t, w.pool, w.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", w.org, id, name)
	return tapp.WithCaller(context.Background(), tapp.Caller{
		Subject: tdomain.Subject{
			Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindUser, ID: id},
			Bindings: []tdomain.Binding{{Role: tdomain.RoleReconciler, Scope: tdomain.Scope{Type: tdomain.ScopeOrg, ID: w.org.UUID()}}},
		},
		Credential: tapp.CredAccessToken,
	}), id
}

// refundOf is what the verifier reads for a refund of charge.
func refundOf(charge, status, amount string) map[string]string {
	return map[string]string{"/charge": charge, "/amount": amount, "/currency": "USD", "/status": status}
}

// confirm reports the verifier's read that confirms txn's refund.
func (w *world) confirm(s *txapp.Service, txn ids.UUID, charge, amount string) {
	w.t.Helper()
	l := w.lease(s, txn)
	a, err := s.Report(context.Background(), w.org, w.gwID, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Fields: refundOf(charge, "succeeded", amount),
	})
	if err != nil || a.State != txdomain.Confirmed {
		w.t.Fatalf("confirm %s: %+v %v", txn, a, err)
	}
}

// TestHR192_APersonRecordsAnUnknownOutcomeAsOccurred: a person holding
// transaction.reconcile records "occurred" with a basis: the held budget is
// committed, the dedupe claim succeeds, a person-based CONFIRMED receipt is
// appended and the resolution is in the ledger. A service, a person without
// the permission, and evidence the transaction does not have are refused;
// a resolved task stays resolved.
func TestHR192_APersonRecordsAnUnknownOutcomeAsOccurred(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	r := w.recorded(w.run(w.grant("500").ID, ids.UUID{}), "ch_1", "30.00", finalize.Unknown, "")
	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: s}
	task, err := ids.ParseUUID(w.str("SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1", r.TransactionID))
	if err != nil {
		t.Fatal(err)
	}
	if got := w.str("SELECT state FROM pc.dedupe_claims WHERE transaction_id = $1", r.TransactionID); got != "HELD" {
		t.Fatalf("claim %q before", got)
	}
	basis := "The refund is in the processor's dashboard as re_7731."

	service := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{
		Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing},
	}})
	if _, err := rec.ResolveOccurred(service, txapp.Resolution{Reconciliation: task, Basis: basis}); !errors.Is(err, txapp.ErrHumanOnly) {
		t.Fatalf("a service account: %v", err)
	}
	elsewhere := w.reader(tdomain.RoleReconciler, tdomain.Scope{Type: tdomain.ScopeTeam, ID: ids.NewV7()})
	if _, err := rec.ResolveOccurred(elsewhere, txapp.Resolution{Reconciliation: task, Basis: basis}); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("another team's reconciler: %v", err)
	}
	person, id := w.reconciler("rita")
	if _, err := rec.ResolveOccurred(person, txapp.Resolution{Reconciliation: task}); !errors.Is(err, txapp.ErrBasis) {
		t.Fatalf("no basis: %v", err)
	}
	if _, err := rec.ResolveOccurred(person, txapp.Resolution{Reconciliation: task, Basis: basis, Evidence: []ids.UUID{ids.NewV7()}}); !errors.Is(err, txapp.ErrEvidence) {
		t.Fatalf("evidence of nothing: %v", err)
	}
	if n := w.count("SELECT count(*) FROM pc.reconciliation_tasks WHERE id = $1 AND state = 'OPEN'", task); n != 1 {
		t.Fatal("a refused resolution changed the task")
	}

	k, err := rec.ResolveOccurred(person, txapp.Resolution{Reconciliation: task, Basis: basis})
	if err != nil {
		t.Fatal(err)
	}
	if k.State != txdomain.TaskOccurred || k.Via != txdomain.ViaPerson || k.User == nil || *k.User != id || k.Basis != basis {
		t.Fatalf("resolved %+v", k)
	}
	if res, sp := w.budget(); res != "0" || sp != "30" {
		t.Fatalf("reserved %s spent %s, want committed", res, sp)
	}
	if got := w.str("SELECT state FROM pc.dedupe_claims WHERE transaction_id = $1", r.TransactionID); got != "SUCCEEDED" {
		t.Fatalf("claim %q", got)
	}
	jws := w.str("SELECT receipt_jws FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", r.TransactionID)
	pap := claims(t, jws)
	if b, _ := pap["basis"].(map[string]any); pap["state"] != "CONFIRMED" || b["kind"] != "person" || b["person"] != id.String() {
		t.Fatalf("effect receipt %v", pap)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.transaction.reconciliation_resolved' AND actor_id = $1", id.String()); n != 1 {
		t.Fatalf("%d resolution entries", n)
	}
	if _, err := rec.ResolveOccurred(person, txapp.Resolution{Reconciliation: task, Basis: basis}); !errors.Is(err, txapp.ErrNotOpen) {
		t.Fatalf("resolved twice: %v", err)
	}
	if res, sp := w.budget(); res != "0" || sp != "30" {
		t.Fatalf("after a second try: reserved %s spent %s", res, sp)
	}

	e := &txapp.Explorer{Pool: w.pool}
	p, err := e.ListReconciliations(person, page.Request{Size: 50}, txapp.ReconciliationFilter{States: []txdomain.TaskState{txdomain.TaskOccurred}})
	if err != nil || len(p.Items) != 1 || p.Items[0].ID != task {
		t.Fatalf("occurred reconciliations %+v %v", p.Items, err)
	}
	if p, _ := e.ListReconciliations(person, page.Request{Size: 50}, txapp.ReconciliationFilter{States: []txdomain.TaskState{txdomain.TaskOpen}}); len(p.Items) != 0 {
		t.Fatalf("open reconciliations %+v", p.Items)
	}
	if p, _ := e.ListReconciliations(elsewhere, page.Request{Size: 50}, txapp.ReconciliationFilter{}); len(p.Items) != 0 {
		t.Fatalf("another team's reconciler lists %d", len(p.Items))
	}
	got, txn, err := e.Reconciliation(person, task)
	if err != nil || got.Basis != basis || txn.ID != r.TransactionID || txn.Effect != txdomain.Confirmed {
		t.Fatalf("reconciliation %+v %+v %v", got, txn, err)
	}
}

// TestRequestVerification_ReadsAgainNow: a person's request makes the open
// verification due now; once it is done, a request opens a new one like
// it.
func TestRequestVerification_ReadsAgainNow(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	s := w.verifier()
	r := w.recorded(w.run(w.grant("500").ID, ids.UUID{}), "ch_1", "30.00", finalize.Accepted, "re_1")
	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: s}
	person, _ := w.reconciler("rita")
	w.db.AdminExec(t, "UPDATE pc.verifications SET next_at = now() + interval '1 hour'")

	v, err := rec.RequestVerification(person, r.TransactionID)
	if err != nil {
		t.Fatal(err)
	}
	if n := w.count("SELECT count(*) FROM pc.verifications WHERE id = $1 AND next_at <= now()", v); n != 1 {
		t.Fatal("the open verification is not due now")
	}
	w.confirm(s, r.TransactionID, "ch_1", "30.00")
	again, err := rec.RequestVerification(person, r.TransactionID)
	if err != nil || again == v {
		t.Fatalf("after it was done: %s %v", again, err)
	}
	if got := w.str("SELECT purpose || ' ' || state || ' ' || operation FROM pc.verifications WHERE id = $1", again); got != "follow_up PENDING payments.refund.get" {
		t.Fatalf("new verification %q", got)
	}
	if n := w.count("SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.transaction.verification_requested'"); n != 2 {
		t.Fatalf("%d requests audited", n)
	}
	if _, err := rec.RequestVerification(person, ids.NewV7()); !errors.Is(err, txapp.ErrTransactionNotFound) {
		t.Fatalf("an unknown transaction: %v", err)
	}
}

// TestHR193_ACompensationChangesNothingOfTheOriginal: a person links a
// later transaction as the compensation of an earlier one. The earlier
// one's receipts, reservations and effect stay as they are until the
// compensating effect is confirmed; then it gains one COMPENSATED receipt
// naming the compensation and the definition's reversibility. A link the
// wrong way round, to itself, twice or by a service is refused.
func TestHR193_ACompensationChangesNothingOfTheOriginal(t *testing.T) {
	w := newWorld(t)
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2")
	s := w.verifier()
	run := w.run(w.grant("500").ID, ids.UUID{})
	original := w.recorded(run, "ch_1", "30.00", finalize.Accepted, "re_1")
	w.confirm(s, original.TransactionID, "ch_1", "30.00")
	comp := w.recorded(run, "ch_2", "10.00", finalize.Accepted, "re_2")
	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: w.pool}, Effects: s}
	person, id := w.reconciler("rita")

	snapshot := func() string {
		return w.str(`SELECT (SELECT string_agg(receipt_jws, ',' ORDER BY evaluation) FROM pc.decision_receipts WHERE transaction_id = $1)
			|| (SELECT receipt_jws FROM pc.execution_receipts WHERE transaction_id = $1)
			|| (SELECT string_agg(state || amount::text, ',' ORDER BY id) FROM pc.reservations WHERE transaction_id = $1)`, original.TransactionID)
	}
	before := snapshot()
	receipts := func() int {
		return w.count("SELECT count(*) FROM pc.effect_receipts WHERE transaction_id = $1", original.TransactionID)
	}
	n0 := receipts()

	link := txapp.LinkRequest{From: comp.TransactionID, To: original.TransactionID, Kind: txdomain.LinkCompensates}
	if _, err := rec.Link(person, txapp.LinkRequest{From: original.TransactionID, To: comp.TransactionID, Kind: txdomain.LinkCompensates}); !errors.Is(err, txapp.ErrLinkOrder) {
		t.Fatalf("decided before the other was sent: %v", err)
	}
	if _, err := rec.Link(person, txapp.LinkRequest{From: comp.TransactionID, To: comp.TransactionID, Kind: txdomain.LinkCompensates}); !errors.Is(err, txapp.ErrLinkSelf) {
		t.Fatalf("to itself: %v", err)
	}
	if _, err := rec.Link(person, txapp.LinkRequest{From: comp.TransactionID, To: ids.NewV7(), Kind: txdomain.LinkCompensates}); !errors.Is(err, txapp.ErrTransactionNotFound) {
		t.Fatalf("to another org's: %v", err)
	}
	service := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{
		Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing},
	}})
	if _, err := rec.Link(service, link); !errors.Is(err, txapp.ErrHumanOnly) {
		t.Fatalf("a service account: %v", err)
	}

	l, err := rec.Link(person, link)
	if err != nil || l.CreatedBy != "user:"+id.String() {
		t.Fatalf("link %+v %v", l, err)
	}
	if _, err := rec.Link(person, link); !errors.Is(err, txapp.ErrLinkExists) {
		t.Fatalf("linked twice: %v", err)
	}
	if receipts() != n0 || w.str("SELECT effect_state FROM pc.transactions WHERE id = $1", original.TransactionID) != "CONFIRMED" {
		t.Fatal("the original changed before its compensation was confirmed")
	}

	w.confirm(s, comp.TransactionID, "ch_2", "10.00")
	if receipts() != n0+1 {
		t.Fatalf("%d receipts, want one more", receipts())
	}
	jws := w.str("SELECT receipt_jws FROM pc.effect_receipts WHERE transaction_id = $1 ORDER BY seq DESC LIMIT 1", original.TransactionID)
	pap := claims(t, jws)
	b, _ := pap["basis"].(map[string]any)
	if pap["state"] != "COMPENSATED" || b["kind"] != "compensation" || b["transaction"] != comp.TransactionID.String() || pap["reversibility"] == nil {
		t.Fatalf("compensated receipt %v", pap)
	}
	if snapshot() != before {
		t.Fatal("the original's receipts or reservations changed")
	}
	ev, err := (&txapp.Explorer{Pool: w.pool}).TransactionEvidence(person, original.TransactionID)
	if err != nil || ev.Transaction.Effect != txdomain.Compensated || len(ev.Links) != 1 || ev.Links[0].From != comp.TransactionID {
		t.Fatalf("explorer %+v %v", ev.Links, err)
	}
}
