// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgranges_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/ranges/app"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// decisionReceipt is an unsigned stand-in for a stored receipt: the range
// reads the payload only.
func decisionReceipt(decision string, codes ...string) string {
	items := ""
	for i, c := range codes {
		if i > 0 {
			items += ","
		}
		items += `{"code":"` + c + `","decisive":` + map[bool]string{true: "true", false: "false"}[i == 0] + `}`
	}
	payload := `{"pap":{"decision":"` + decision + `","checklist":[` + items + `],"simulated":true}}`
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

// TestHR224_AReEvaluatedTransactionDerivesFromItsLatestEvaluation: a hold
// that was approved has two decision receipts (evaluations 1 and 2). A step
// citing it derives from the latest one, with one row, however the rows are
// stored.
func TestHR224_AReEvaluatedTransactionDerivesFromItsLatestEvaluation(t *testing.T) {
	w := newWorld(t, dbtest.New(t))
	ctx := w.as(td.RoleAgentOwner)
	r := w.start(t, "RT-008")
	id := w.txn(t, w.run, true, "ALLOW", "GRANT_ALLOWS")
	// Two receipts, each with a ledger entry of its own (an audit entry
	// stands in: the range reads the receipt, not the entry).
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		for _, row := range []struct {
			eval    int
			receipt string
		}{
			{1, decisionReceipt("REQUIRE_APPROVAL", "REQUIRE_APPROVAL_REASON")},
			{2, decisionReceipt("ALLOW", "GRANT_ALLOWS", "APPROVED_BY_PERSON")},
		} {
			entry, err := audit.Record(ctx, tx, audit.Event{Name: "redteam.test_entry", Actor: evdomain.Actor{Type: "system", ID: "test"}, Outcome: audit.Success})
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO pc.decision_receipts (org_id, transaction_id, evaluation, receipt_jws, ledger_entry_id)
				VALUES ($1, $2, $3, $4, $5)`, w.org, id, row.eval, row.receipt, entry.ID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The step expects the second reason of the latest evaluation. Derived
	// from the first (held) evaluation instead, it would not match.
	want := domain.Expect{Outcome: domain.OutcomeAllow, Reason: "APPROVED_BY_PERSON"}
	res, err := w.svc.RecordResult(ctx, app.RecordInput{
		Range: r.ID, Scenario: "RT-008", Digest: hexA, Verdict: domain.Pass,
		Steps: []domain.StepInput{{ID: "approved", Kind: "agent.call", Expect: want, Observed: want, Transaction: &id}},
	})
	if err != nil {
		t.Fatal(err)
	}
	st := res.Steps[0]
	if res.Verdict != domain.Pass || st.ObservedBy != domain.Server || st.Mismatch || st.Observed.Reason != "APPROVED_BY_PERSON" {
		t.Fatalf("result = %+v", res)
	}
}
