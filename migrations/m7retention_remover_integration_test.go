// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// m7rItems inserts, for transaction txn, one item of every kind retention
// removes: a decision, an execution and an effect receipt with their
// ledger entries, an observation, replay inputs, an approval note, and an
// approval and a security audit entry. Ledger entries get chain links from
// seq on and are covered by a checkpoint. It returns the next seq.
func m7rItems(t *testing.T, f m7Fixture, txn, attempt, permit, request string, seq int) int {
	t.Helper()
	entry := func(kind, body string) string {
		id := m5ID()
		f.mustExec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body) VALUES ($1, $2, $3, 'test', 'test', $4)`,
			f.org, id, kind, []byte(body))
		f.mustExec(t, `INSERT INTO pc.ledger_chain (org_id, seq, entry_id, prev_hash, entry_hash) VALUES ($1, $2, $3, $4, $5)`,
			f.org, seq, id, m6Bytes(32, byte(seq-1)), m6Bytes(32, byte(seq)))
		seq++
		return id
	}
	f.mustExec(t, `INSERT INTO pc.decision_receipts (org_id, transaction_id, receipt_jws, ledger_entry_id) VALUES ($1, $2, $3, $4)`,
		f.org, txn, m7rJWS, entry("receipt.decision", `{"receipt_sha256":"aa"}`))
	f.mustExec(t, `INSERT INTO pc.execution_receipts (org_id, attempt_id, transaction_id, permit_id, receipt_jws, ledger_entry_id)
		VALUES ($1, $2, $3, $4, $5, $6)`, f.org, attempt, txn, permit, m7rJWS, entry("receipt.execution", `{"receipt_sha256":"bb"}`))
	f.mustExec(t, `INSERT INTO pc.effect_receipts (org_id, transaction_id, seq, state, level_required, basis, receipt_jws,
		ledger_entry_id) VALUES ($1, $2, 1, 'UNKNOWN', 'acceptance', 'deadline', $3, $4)`, f.org, txn, m7rJWS,
		entry("receipt.effect", `{"receipt_sha256":"cc"}`))
	v := m5ID()
	f.mustExec(t, m7Verification, f.org, v, "follow_up", txn, f.connection, nil, nil)
	f.mustExec(t, `INSERT INTO pc.observations (org_id, id, source, transaction_id, verification_id, gateway_id, found, fields)
		VALUES ($1, $2, 'verifier', $3, $4, $5, true, '{"status":"succeeded"}')`, f.org, m5ID(), txn, v, f.gateway)
	f.mustExec(t, `INSERT INTO pc.evaluation_inputs (org_id, transaction_id, evaluation, format_version, pipeline_version, inputs,
		inputs_sha256, truncated) VALUES ($1, $2, 1, 1, 1, $3, $4, false)`, f.org, txn, m6Bytes(64, 7), m6Bytes(32, 8))
	f.mustExec(t, `INSERT INTO pc.approval_evidence (org_id, id, request_id, author_kind, author_user_id, note)
		VALUES ($1, $2, $3, 'user', $4, 'the customer called')`, f.org, m5ID(), request, f.user)
	entry("audit.approval.requested", `{"name":"approval.requested","object":{"id":"`+request+`","type":"approval_request"}}`)
	entry("audit.agent.suspended", `{"name":"agent.suspended","object":{"id":"`+txn+`","type":"transaction"}}`)
	f.mustExec(t, m7bPoint, f.org, seq-1, m6Bytes(32, 3), m7bNote(), nil)
	return seq
}

// TestHR198_RemoverRemovesEveryCategoryOutsideHolds: once every period has
// passed, the job removes the body of each kind of item and leaves its
// hashes, links and checkpoint; items of a held transaction, run or agent
// are never touched until the hold is released; every batch is audited;
// the tombstone names the policy revision; a second run removes nothing.
func TestHR198_RemoverRemovesEveryCategoryOutsideHolds(t *testing.T) {
	d := dbtest.New(t)
	app := d.AppPool(t)
	f := newM7Fixture(t, app)
	// A second transaction of the same run, with its own permit and
	// attempt, and an approval request of each.
	txn2, permit2, attempt2 := m5ID(), m5ID(), m5ID()
	f.mustExec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id) VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'ALLOW', 'ALLOWED', 'gw')`, f.org, txn2, f.run, m5ID(), m5Secret(21))
	f.mustExec(t, `INSERT INTO pc.permits (org_id, id, transaction_id, gateway_id, epoch, state, expires_at, dispatching_at,
		finished_at) VALUES ($1, $2, $3, $4, 1, 'DISPATCHED', now() + interval '5 seconds', now(), now())`, f.org, permit2, txn2, f.gateway)
	f.mustExec(t, `INSERT INTO pc.execution_attempts (org_id, id, permit_id, transaction_id, outcome, target_status)
		VALUES ($1, $2, $3, $4, 'accepted', 200)`, f.org, attempt2, permit2, txn2)
	request1 := f.request(t, 1)
	request2 := m5ID()
	f.mustExec(t, m5p2Request, f.org, request2, f.agent, txn2, f.run, f.grant, m5Secret(2), m5Secret(2), "1 hour")
	seq := m7rItems(t, f, f.txn, f.attempt, f.permit, request1, 1)
	m7rItems(t, f, txn2, attempt2, permit2, request2, seq)
	// A recent, unsealed entry and an uncategorized one are kept anyway.
	f.mustExec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body) VALUES ($1, $2, 'test.kept', 't', 't', '\x7b7d')`,
		f.org, m5ID())

	hold := m5ID()
	f.mustExec(t, m7rHold, f.org, hold, "transaction", f.txn, nil, nil, f.user)
	r := &retention.Remover{Pool: d.Pool(t, d.Retention), App: app, Log: pclog.Discard(), Batch: 2, Shift: 800 * 24 * time.Hour}
	ctx := context.Background()
	res, err := r.Run(ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		d.AdminQueryRow(t, sql, args, &n)
		return n
	}
	// Everything of the second transaction went; nothing of the held one.
	want := map[string]int{
		"decision_receipts": 1, "execution_receipts": 1, "effect_receipts": 1, "observations": 1, "evaluation_inputs": 1,
		"approval_evidence": 1,
	}
	for _, x := range res.Removed {
		if x.Items == "ledger_entries" {
			continue
		}
		if x.Count != want[x.Items] {
			t.Errorf("%s %s: removed %d, want %d", x.Category, x.Items, x.Count, want[x.Items])
		}
	}
	if n := res.Total(); n != 6+5 {
		t.Errorf("removed %d items in all, want 11 (six rows and five ledger bodies of the second transaction)", n)
	}
	if n := count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND body IS NULL`, f.org); n != 5 {
		t.Errorf("%d ledger bodies removed, want 5", n)
	}
	for _, table := range []string{"decision_receipts", "execution_receipts", "effect_receipts", "observations"} {
		if n := count(`SELECT count(*) FROM pc.`+table+` WHERE org_id = $1 AND transaction_id = $2 AND body_removed_at IS NOT NULL`,
			f.org, f.txn); n != 0 {
			t.Errorf("%s of the held transaction: %d removed", table, n)
		}
		if n := count(`SELECT count(*) FROM pc.`+table+` WHERE org_id = $1 AND transaction_id = $2 AND body_removed_at IS NOT NULL
			AND removed_by_policy IS NOT NULL`, f.org, txn2); n != 1 {
			t.Errorf("%s of the free transaction: %d removed, want 1", table, n)
		}
	}
	if n := count(`SELECT count(*) FROM pc.evaluation_inputs WHERE org_id = $1`, f.org); n != 1 {
		t.Errorf("%d replay inputs left, want only the held one", n)
	}
	if n := count(`SELECT count(*) FROM pc.approval_evidence WHERE org_id = $1 AND note IS NULL`, f.org); n != 1 {
		t.Errorf("%d approval notes removed, want 1", n)
	}
	// Links, hashes and the checkpoints are untouched; kept kinds are kept.
	if n := count(`SELECT count(*) FROM pc.ledger_chain WHERE org_id = $1`, f.org); n != 10 {
		t.Errorf("%d chain links, want 10", n)
	}
	if n := count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'test.kept' AND body IS NOT NULL`, f.org); n != 1 {
		t.Error("an uncategorized entry lost its body")
	}
	// Each removal names the revision in effect; each batch is audited.
	if n := count(`SELECT count(*) FROM pc.decision_receipts r JOIN pc.retention_policies p
		ON p.org_id = r.org_id AND p.id = r.removed_by_policy AND p.category = 'receipts' WHERE r.org_id = $1`, f.org); n != 1 {
		t.Errorf("the removed decision receipt names %d receipts revisions", n)
	}
	audits := count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.evidence.retention_removed'`, f.org)
	if audits < 7 {
		t.Errorf("%d audit entries for the removals, want one per batch", audits)
	}
	if n := count(`SELECT count(*) FROM pc.retention_status WHERE org_id = $1 AND last_run_at IS NOT NULL AND last_error IS NULL`, f.org); n != 1 {
		t.Error("the run is not recorded")
	}

	// Again: nothing more, and no new audit entry.
	res, err = r.Run(ctx, f.org)
	if err != nil || res.Total() != 0 {
		t.Fatalf("second run removed %d (%v)", res.Total(), err)
	}
	if n := count(`SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.evidence.retention_removed'`, f.org); n != audits {
		t.Errorf("a run that removed nothing wrote %d audit entries", n-audits)
	}

	// A run hold also covers the first transaction; released, only the
	// run hold keeps it; with both released, it goes too.
	runHold := m5ID()
	f.mustExec(t, m7rHold, f.org, runHold, "run", f.run, nil, nil, f.user)
	f.mustExec(t, `UPDATE pc.legal_holds SET state = 'RELEASED', released_by = $2, released_at = now(), release_reason = 'settled'
		WHERE id = $1`, hold, f.user)
	if res, err := r.Run(ctx, f.org); err != nil || res.Total() != 0 {
		t.Fatalf("a run hold did not keep the transaction: removed %d (%v)", res.Total(), err)
	}
	f.mustExec(t, `UPDATE pc.legal_holds SET state = 'RELEASED', released_by = $2, released_at = now(), release_reason = 'settled'
		WHERE id = $1`, runHold, f.user)
	if res, err := r.Run(ctx, f.org); err != nil || res.Total() < 6 {
		t.Fatalf("after the holds were released: removed %d (%v)", res.Total(), err)
	}
	if n := count(`SELECT count(*) FROM pc.evaluation_inputs WHERE org_id = $1`, f.org); n != 0 {
		t.Errorf("%d replay inputs left after the release", n)
	}
}

// TestHR198_NothingIsRemovedBeforeItsPeriodOrWithoutTheRole: with the
// periods in effect nothing recent goes, and without the retention role
// nothing goes at all and the run reports it.
func TestHR198_NothingIsRemovedBeforeItsPeriodOrWithoutTheRole(t *testing.T) {
	d := dbtest.New(t)
	app := d.AppPool(t)
	f := newM7Fixture(t, app)
	request := f.request(t, 1)
	m7rItems(t, f, f.txn, f.attempt, f.permit, request, 1)
	ctx := context.Background()
	r := &retention.Remover{Pool: d.Pool(t, d.Retention), App: app, Log: pclog.Discard(), Shift: 89 * 24 * time.Hour}
	if res, err := r.Run(ctx, f.org); err != nil || res.Total() != 0 {
		t.Fatalf("removed %d items younger than their period (%v)", res.Total(), err)
	}
	// 91 days: only normalized facts (90 days by default) are due.
	r.Shift = 91 * 24 * time.Hour
	res, err := r.Run(ctx, f.org)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range res.Removed {
		if (x.Category == retention.NormalizedFacts) != (x.Count == 1) {
			t.Errorf("%s %s: removed %d after 91 days", x.Category, x.Items, x.Count)
		}
	}
	none := &retention.Remover{App: app, Log: pclog.Discard(), Shift: 800 * 24 * time.Hour}
	if _, err := none.Run(ctx, f.org); err == nil {
		t.Fatal("a run without the retention role succeeded")
	}
	var code string
	var removed int
	d.AdminQueryRow(t, `SELECT coalesce(last_error, ''), (SELECT count(*) FROM pc.decision_receipts WHERE org_id = $1 AND receipt_jws IS NULL)
		FROM pc.retention_status WHERE org_id = $1`, []any{f.org}, &code, &removed)
	if code != retention.CodeRoleUnavailable || removed != 0 {
		t.Fatalf("without the role: last_error %q, %d receipts removed", code, removed)
	}
}
