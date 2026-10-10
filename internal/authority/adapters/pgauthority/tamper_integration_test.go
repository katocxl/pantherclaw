// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR006_TamperingAnOpenTransactionIsRecorded: on PostgreSQL, a changed
// action under the ids of an OPEN transaction closes it at the next
// evaluation with DENY ACTION_TAMPERED, its receipt and a security event,
// and leaves the transaction's mode, grant and hashes as they were.
func TestHR006_TamperingAnOpenTransactionIsRecorded(t *testing.T) {
	w := newWorld(t)
	g := w.grant("500")
	run := w.run(g.ID, ids.UUID{})
	act := ids.NewV7()
	missing := w.authorize(w.request(run, act, "ch_1", "10.00"))
	if missing.Decision != adomain.CannotAuthorize || decisive(missing) != fdomain.ReasonFactMissing || missing.Evaluation != 1 {
		t.Fatalf("missing fact: %+v", missing)
	}
	txn := missing.TransactionID
	const kept = `SELECT (mode, grant_id, grant_revision, basis_digest, effective_hash, action_hash, connection_id)::text
		FROM pc.transactions WHERE id = $1`
	before := w.str(kept, txn)

	tampered := w.authorize(w.request(run, act, "ch_1", "11.00"))
	if tampered.Decision != adomain.Deny || decisive(tampered) != adomain.ReasonActionTampered || tampered.Evaluation != 2 ||
		tampered.TransactionID != txn || tampered.Receipt == "" {
		t.Fatalf("tampered: %+v", tampered)
	}
	if s := w.str("SELECT concat_ws(' ', decision, reason_code, state, evaluations) FROM pc.transactions WHERE id = $1", txn); s != "DENY ACTION_TAMPERED FINAL 2" {
		t.Fatalf("transaction: %s", s)
	}
	if after := w.str(kept, txn); after != before {
		t.Fatalf("mode, grant and hashes changed:\n%s\n%s", before, after)
	}
	if s := w.str(`SELECT r.receipt_jws FROM pc.decision_receipts r JOIN pc.ledger_entries l ON l.org_id = r.org_id AND l.id = r.ledger_entry_id
		WHERE r.transaction_id = $1 AND r.evaluation = 2 AND l.kind = 'receipt.decision'`, txn); s != tampered.Receipt {
		t.Fatalf("the receipt of evaluation 2 is not recorded: %q", s)
	}
	if n := w.count(`SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.security.action_tampered'
		AND convert_from(body, 'UTF8')::jsonb #>> '{object,id}' = $1`, txn.String()); n != 1 {
		t.Fatalf("%d security.action_tampered events", n)
	}

	// The closed transaction is terminal: the original action, even with
	// its fact now present, gets the stored denial.
	w.refundable("ch_1")
	if r := w.authorize(w.request(run, act, "ch_1", "10.00")); r.Decision != adomain.Deny || !r.Repeat || r.Receipt != tampered.Receipt {
		t.Fatalf("the original action after tampering: %+v", r)
	}
}
