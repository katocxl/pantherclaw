// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/transactions/adapters/pgtransactions"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
	txdomain "github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// downstream is a world whose refunds predict a payout (verifiedPayouts):
// confirm refunds a charge in run and confirms it with its verifier, after
// edit (if any) changed what its decision predicted; report answers the
// payout consequence's lookup.
type downstream struct {
	*world
	s     *txapp.Service
	runID ids.UUID
	// bare: the refund's verifier captures nothing, so its read reports
	// no /id.
	bare bool
}

func newDownstream(t *testing.T, edit func(string) string) *downstream {
	w := newWorldWith(t, edit)
	w.refundable("ch_1", "ch_2", "ch_3", "ch_4", "ch_5")
	g := w.heldRefunds([]string{"payments.refund.create", "payments.refund.get", "payments.payout.trigger"})
	return &downstream{world: w, s: w.verifier(), runID: w.run(g.ID, ids.UUID{})}
}

func (d *downstream) confirm(charge string, edit func(txn ids.UUID)) ids.UUID {
	d.t.Helper()
	d.payouts(charge, `{"state": "scheduled", "environments": ["payroll"]}`)
	ref := "re_" + strings.TrimPrefix(charge, "ch_")
	r := d.recorded(d.runID, charge, "30.00", finalize.Accepted, ref)
	if edit != nil {
		edit(r.TransactionID)
	}
	l := d.lease(d.s, r.TransactionID)
	fields := refundOf(charge, "succeeded", "30.00")
	if !d.bare {
		fields["/id"] = ref
	}
	if a, err := d.s.Report(context.Background(), d.org, d.gwID, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true,
		Fields: fields,
	}); err != nil || a.State != txdomain.Confirmed {
		d.t.Fatalf("%s: confirm %+v %v", charge, a, err)
	}
	return r.TransactionID
}

// consequences are the transactions opened as consequences of txn.
func (d *downstream) consequences(txn ids.UUID) []ids.UUID {
	d.t.Helper()
	var out []ids.UUID
	for _, s := range strings.Fields(d.str(`SELECT coalesce(string_agg(to_transaction_id::text, ' ' ORDER BY created_at), '')
		FROM pc.transaction_links WHERE from_transaction_id = $1 AND kind = 'consequence'`, txn)) {
		id, err := ids.ParseUUID(s)
		if err != nil {
			d.t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

// report answers cons's lookup with the payout's state and, in pairs,
// more fields it read.
func (d *downstream) report(cons ids.UUID, state string, more ...string) {
	d.t.Helper()
	d.db.AdminExec(d.t, "UPDATE pc.verifications SET next_at = now() WHERE transaction_id = $1 AND state = 'PENDING'", cons)
	l := d.lease(d.s, cons)
	fields := map[string]string{"/0/state": state}
	for i := 0; i+1 < len(more); i += 2 {
		fields[more[i]] = more[i+1]
	}
	if _, err := d.s.Report(context.Background(), d.org, d.gwID, txapp.Report{
		Task: l.Task, Secret: l.Secret, HTTPStatus: 200, Found: true, Complete: true, Fields: fields,
	}); err != nil {
		d.t.Fatalf("report %s: %v", state, err)
	}
}

// chainedPayouts is verifiedPayouts whose payout verifier also captures
// the refund a payout was made for, so a payout that follows from a payout
// can be looked up (G0 M17 D104).
func chainedPayouts(pkg string) string {
	return strings.Replace(verifiedPayouts(pkg), "      establishes: payout.paid\n      within_seconds: 3600\n",
		"      establishes: payout.paid\n      within_seconds: 3600\n      capture:\n        refund: /refund\n", 1)
}

func (d *downstream) state(txn ids.UUID) string {
	return d.str("SELECT coalesce(downstream_state, '') FROM pc.transactions WHERE id = $1", txn)
}

// receipts are txn's effect receipts in order: seq, state, basis, level
// and the signed receipt.
func (d *downstream) receipts(txn ids.UUID) []string {
	return strings.Split(d.str(`SELECT string_agg(seq || ' ' || state || ' ' || basis || ' ' || coalesce(level_achieved, '') || ' ' || receipt_jws,
		E'\n' ORDER BY seq) FROM pc.effect_receipts WHERE transaction_id = $1`, txn), "\n")
}

// counts are the run's downstream counts, for operation (all when ""),
// and the run's confirmed actions of operation, as wait_effect and policy
// read them (G0 M17 D103).
func (d *downstream) counts(operation string) (dbq.RunDownstreamCountsRow, []ids.UUID) {
	d.t.Helper()
	var c dbq.RunDownstreamCountsRow
	var confirmed []ids.UUID
	if err := d.pool.InTenantTx(context.Background(), d.org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var op *string
		if operation != "" {
			op = &operation
		}
		var err error
		if c, err = q.RunDownstreamCounts(ctx, d.org, d.runID, op); err != nil || operation == "" {
			return err
		}
		confirmed, err = q.RunDownstreamConfirmed(ctx, d.org, d.runID, operation)
		return err
	}); err != nil {
		d.t.Fatal(err)
	}
	return c, confirmed
}

// predictAlso adds a predicted consequence to the latest evaluation of
// txn: a copy of its payout, at depth 1 (parent < 0) or following from the
// consequence at position parent, with environments.
func (d *downstream) predictAlso(txn ids.UUID, parent int, environments string) {
	d.t.Helper()
	depth, from := "1", "NULL"
	if parent >= 0 {
		depth, from = "2", "$3::int"
	}
	args := []any{d.org, txn}
	if parent >= 0 {
		args = append(args, parent)
	}
	d.db.AdminExec(d.t, `INSERT INTO pc.decision_consequences (org_id, transaction_id, evaluation, position, rule_id, operation,
		target_type, target_id, environments, state, unknown, facts_digest, depth, parent_position, source)
		SELECT org_id, transaction_id, evaluation, position + 1, rule_id, operation, target_type, target_id, '`+environments+`'::text[],
			state, unknown, facts_digest, `+depth+`, `+from+`, source
		FROM pc.decision_consequences WHERE org_id = $1 AND transaction_id = $2 AND state = 'PREDICTED'
		ORDER BY position DESC LIMIT 1`, args...)
}

// TestHR450_APredictedConsequenceThatCannotBeOpenedIsAuditedAsNotVerifiable
// (G0 M17 D101, D104): a refund whose verifier captures nothing a payout
// could be found by audits its predicted payout as not verifiable and is
// NOT_VERIFIABLE downstream, never left without a word or counted
// confirmed. In a chain, a consequence of a confirmed payout that cannot
// be opened makes the payout NOT_VERIFIABLE, and with it the refund at
// the root, though the payout itself was confirmed.
//
// Covers: F414
func TestHR450_APredictedConsequenceThatCannotBeOpenedIsAuditedAsNotVerifiable(t *testing.T) {
	const notVerifiable = `SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.transaction.consequence_not_verifiable'
		AND convert_from(body, 'UTF8')::jsonb #>> '{object,id}' = $2 AND convert_from(body, 'UTF8')::jsonb ->> 'reason_code' = 'NOT_VERIFIABLE'`
	d := newDownstream(t, pipelinetest.PayoutConsequence)
	d.bare = true
	txn := d.confirm("ch_1", nil)
	if n := d.count(notVerifiable, d.org, txn.String()); n != 1 || len(d.consequences(txn)) != 0 || d.state(txn) != "NOT_VERIFIABLE" {
		t.Fatalf("a verifier that captures nothing: %d events, %d opened, downstream %q", n, len(d.consequences(txn)), d.state(txn))
	}

	// A chain: the payout's own consequence (a second payout following from
	// it) cannot be opened once the payout is confirmed, since the payout's
	// verifier captures nothing to find it by.
	c := newDownstream(t, verifiedPayouts)
	root := c.confirm("ch_1", func(txn ids.UUID) {
		c.predictAlso(txn, c.count("SELECT max(position) FROM pc.decision_consequences WHERE transaction_id = $1", txn), "{payroll}")
	})
	cons := c.consequences(root)
	if len(cons) != 1 || c.state(root) != "PENDING" {
		t.Fatalf("depth 1: %d opened, downstream %q", len(cons), c.state(root))
	}
	c.report(cons[0], "paid")
	if len(c.consequences(cons[0])) != 0 || c.state(cons[0]) != "NOT_VERIFIABLE" || c.state(root) != "NOT_VERIFIABLE" {
		t.Fatalf("depth 2: %d opened, the payout %q, the refund %q", len(c.consequences(cons[0])), c.state(cons[0]), c.state(root))
	}
	if n := c.count(notVerifiable, c.org, cons[0].String()); n != 1 {
		t.Fatalf("%d audit events for the payout's consequence", n)
	}
	if n := c.count("SELECT count(*) FROM pc.effect_receipts WHERE transaction_id = $1 AND basis = 'consequence'", root); n != 0 {
		t.Fatalf("%d downstream receipts for a refund not verifiable downstream", n)
	}
}

// TestHR451_ADownstreamStateComesFromTheConsequencesOwnEvidence (G0 M17
// D102, D104, D131): a refund confirmed by its own verifier is only
// PENDING downstream; it becomes CONFIRMED when its payout's own lookup
// confirms the payout, and only then is a downstream receipt appended,
// the earlier receipts left as they were. A payout that failed makes it
// UNCONFIRMED until a person records it as occurred. A refund with one
// payout opened and another that could not be is NOT_VERIFIABLE whatever
// the opened one shows (the mixed case). A chain's root waits for the
// consequences of its consequences.
//
// Covers: F414
func TestHR451_ADownstreamStateComesFromTheConsequencesOwnEvidence(t *testing.T) {
	d := newDownstream(t, verifiedPayouts)
	downstreamReceipts := func(txn ids.UUID) int {
		return d.count("SELECT count(*) FROM pc.effect_receipts WHERE transaction_id = $1 AND basis = 'consequence'", txn)
	}

	// Confirmed by its payout's evidence; the receipt is appended.
	txn := d.confirm("ch_1", nil)
	before := d.receipts(txn)
	cons := d.consequences(txn)
	if len(cons) != 1 || d.state(txn) != "PENDING" || downstreamReceipts(txn) != 0 {
		t.Fatalf("after the refund's own confirmation: %d opened, downstream %q", len(cons), d.state(txn))
	}
	d.report(cons[0], "in_transit")
	if d.state(txn) != "PENDING" {
		t.Fatalf("a payout in transit: %q", d.state(txn))
	}
	d.report(cons[0], "paid")
	after := d.receipts(txn)
	if d.state(txn) != "CONFIRMED" || len(after) != len(before)+1 || !slices.Equal(after[:len(before)], before) ||
		!strings.Contains(after[len(before)], " CONFIRMED consequence downstream ") {
		t.Fatalf("a paid payout: downstream %q, receipts %q then %q", d.state(txn), before, after)
	}

	// A failed payout: UNCONFIRMED, no receipt, until a person says it
	// occurred.
	txn = d.confirm("ch_2", nil)
	cons = d.consequences(txn)
	d.report(cons[0], "failed")
	if d.state(txn) != "UNCONFIRMED" || downstreamReceipts(txn) != 0 {
		t.Fatalf("a failed payout: %q, %d receipts", d.state(txn), downstreamReceipts(txn))
	}
	rctx, _ := d.reconciler("rita")
	task, err := ids.ParseUUID(d.str(`SELECT id::text FROM pc.reconciliation_tasks WHERE transaction_id = $1`, cons[0]))
	if err != nil {
		t.Fatal(err)
	}
	rec := &txapp.Reconciler{Store: &pgtransactions.Store{Pool: d.pool}, Effects: d.s}
	if _, err := rec.ResolveOccurred(rctx, txapp.Resolution{Reconciliation: task, Basis: "the bank shows it paid"}); err != nil {
		t.Fatal(err)
	}
	if d.state(txn) != "CONFIRMED" || downstreamReceipts(txn) != 1 {
		t.Fatalf("a person's occurred: %q, %d receipts", d.state(txn), downstreamReceipts(txn))
	}

	// Mixed: a second payout with no environment could not be opened.
	txn = d.confirm("ch_3", func(txn ids.UUID) { d.predictAlso(txn, -1, "{}") })
	cons = d.consequences(txn)
	if len(cons) != 1 || d.state(txn) != "NOT_VERIFIABLE" {
		t.Fatalf("mixed: %d opened, %q", len(cons), d.state(txn))
	}
	d.report(cons[0], "paid")
	if d.state(txn) != "NOT_VERIFIABLE" || downstreamReceipts(txn) != 0 {
		t.Fatalf("mixed, the opened one paid: %q, %d receipts", d.state(txn), downstreamReceipts(txn))
	}
	// Mixed, and a negative outcome: UNCONFIRMED wins.
	txn = d.confirm("ch_4", func(txn ids.UUID) { d.predictAlso(txn, -1, "{}") })
	d.report(d.consequences(txn)[0], "failed")
	if d.state(txn) != "UNCONFIRMED" {
		t.Fatalf("mixed, the opened one failed: %q", d.state(txn))
	}

	// A chain whose second payout follows from the first and is opened,
	// from the refund the first one's read captured, once the first is
	// paid: the root waits for both.
	c := newDownstream(t, chainedPayouts)
	chainReceipts := func(txn ids.UUID) int {
		return c.count("SELECT count(*) FROM pc.effect_receipts WHERE transaction_id = $1 AND basis = 'consequence'", txn)
	}
	txn = c.confirm("ch_1", func(txn ids.UUID) {
		c.predictAlso(txn, c.count("SELECT max(position) FROM pc.decision_consequences WHERE transaction_id = $1", txn), "{payroll}")
	})
	cons = c.consequences(txn)
	if len(cons) != 1 {
		t.Fatalf("depth 1 of the chain: %d opened", len(cons))
	}
	c.report(cons[0], "paid", "/refund", "re_1")
	kids := c.consequences(cons[0])
	if len(kids) != 1 || c.state(cons[0]) != "PENDING" || c.state(txn) != "PENDING" {
		t.Fatalf("depth 2 opened: %d, the payout %q, the refund %q", len(kids), c.state(cons[0]), c.state(txn))
	}
	if got := c.str(`SELECT consequence_root::text || ' ' || consequence_position FROM pc.transactions WHERE id = $1`, kids[0]); !strings.HasPrefix(got,
		txn.String()+" ") {
		t.Fatalf("depth 2 origin %q", got)
	}
	// Only the run's own action counts, not the consequences opened for
	// it in the same run (D141 L1).
	const refund, payout = "payments.refund.create", "payments.payout.trigger"
	if all, _ := c.counts(""); all != (dbq.RunDownstreamCountsRow{Pending: 1}) {
		t.Fatalf("the run's counts with the chain pending: %+v", all)
	}
	c.report(kids[0], "paid", "/refund", "re_1")
	if c.state(cons[0]) != "CONFIRMED" || c.state(txn) != "CONFIRMED" || chainReceipts(txn) != 1 {
		t.Fatalf("the chain paid: the payout %q, the refund %q, %d receipts", c.state(cons[0]), c.state(txn), chainReceipts(txn))
	}
	if all, _ := c.counts(""); all != (dbq.RunDownstreamCountsRow{Confirmed: 1}) {
		t.Fatalf("the run's counts with the chain paid: %+v", all)
	}
	if got, confirmed := c.counts(refund); got.Confirmed != 1 || !slices.Equal(confirmed, []ids.UUID{txn}) {
		t.Fatalf("the refunds confirmed downstream: %+v %v", got, confirmed)
	}
	if got, confirmed := c.counts(payout); got != (dbq.RunDownstreamCountsRow{}) || len(confirmed) != 0 {
		t.Fatalf("the payouts counted as the run's actions: %+v %v", got, confirmed)
	}
}

// TestT198_AnUnverifiedDownstreamConsequenceHoldsFollowOnWork is T-198 (an
// unverified downstream consequence lets follow-on work proceed): a policy
// holds the run's next refund while one of its earlier refunds has a
// payout that failed (run.consequences_unconfirmed), as the
// coding-to-production template holds a merge; before that, and in another
// run, refunds go through.
//
// Covers: F414
func TestT198_AnUnverifiedDownstreamConsequenceHoldsFollowOnWork(t *testing.T) {
	d := newDownstream(t, verifiedPayouts)
	d.publishPolicy(1, false, pdomain.Rule{
		ID: "hold-after-unconfirmed", Kind: pdomain.RequireApproval, Summary: "no follow-on refund while a payout is unconfirmed",
		Operations: []string{"payments.refund.create"}, When: `run.consequences_unconfirmed > 0`, Reason: "CONSEQUENCES_UNCONFIRMED",
		Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	})
	txn := d.confirm("ch_1", nil)
	next := func(run ids.UUID, charge string) finalize.Result {
		d.payouts(charge, `{"state": "scheduled", "environments": ["payroll"]}`)
		return d.authorize(d.request(run, ids.NewV7(), charge, "10.00"))
	}
	if r := next(d.runID, "ch_2"); !r.Decision.Permits() {
		t.Fatalf("with the payout pending: %s %s", r.Decision, decisive(r))
	}
	d.report(d.consequences(txn)[0], "failed")
	r := next(d.runID, "ch_3")
	if r.Decision != adomain.RequireApproval || !hasReason(r, "CONSEQUENCES_UNCONFIRMED") {
		t.Fatalf("with the payout failed: %s %s", r.Decision, decisive(r))
	}
	g := d.heldRefunds([]string{"payments.refund.create", "payments.refund.get", "payments.payout.trigger"})
	if r := next(d.run(g.ID, ids.UUID{}), "ch_4"); !r.Decision.Permits() {
		t.Fatalf("another run: %s %s", r.Decision, decisive(r))
	}
}
