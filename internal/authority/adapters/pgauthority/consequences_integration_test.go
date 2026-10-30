// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// payouts pushes the charge's payout schedule, as the provider.
func (w *world) payouts(charge, object string) {
	w.t.Helper()
	ctx := tapp.WithCaller(context.Background(), tapp.Caller{Subject: tdomain.Subject{Org: w.org, Principal: tdomain.PrincipalRef{Kind: tdomain.KindServiceAccount, ID: w.billing}}})
	res, err := w.facts.PutFacts(ctx, []fdomain.Observation{{
		Name: "payments.charge.payouts", SubjectType: "payments.charge", SubjectID: charge,
		Value: jsontext.Value(`{"object": ` + object + `}`), ObservedAt: time.Now().Add(-time.Second),
	}})
	if err != nil || len(res) != 1 || res[0].Err != nil {
		w.t.Fatalf("payouts: %v %+v", err, res)
	}
}

// receiptConsequences reads the consequences a decision receipt states.
func receiptConsequences(t *testing.T, receipt string) []finalize.ReceiptConsequence {
	t.Helper()
	parts := strings.Split(receipt, ".")
	if len(parts) != 3 {
		t.Fatalf("receipt %q", receipt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var r finalize.DecisionReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r.Pap.Consequences
}

// TestHR206_ConsequencesAreRecordedWithTheDecision: each evaluation keeps,
// next to its decision receipt, what the action's consequence rules said,
// and the receipt and the answer state it too: a predicted payout the grant
// does not cover (DENY), and a payout ruled out (ALLOW).
func TestHR206_ConsequencesAreRecordedWithTheDecision(t *testing.T) {
	w := newWorldWith(t, pipelinetest.PayoutConsequence)
	w.refundable("ch_1", "ch_2")
	run := w.run(w.grant("100.00").ID, ids.UUID{})
	stored := func(r finalize.Result) []dbq.ListDecisionConsequencesRow {
		t.Helper()
		var rows []dbq.ListDecisionConsequencesRow
		if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			rows, err = dbq.New(tx).ListDecisionConsequences(ctx, w.org, r.TransactionID, int32(r.Evaluation)) //nolint:gosec // 1
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return rows
	}

	w.payouts("ch_1", `{"state": "scheduled", "environments": ["payroll"]}`)
	r := w.authorize(w.request(run, ids.NewV7(), "ch_1", "30.00"))
	rows := stored(r)
	if r.Decision != adomain.Deny || len(r.Consequences) != 1 || r.Consequences[0].State != consequences.Predicted ||
		len(rows) != 1 || rows[0].State != "PREDICTED" || rows[0].RuleID != "refund-triggers-payout" || rows[0].TargetID != "ch_1" ||
		!slices.Equal(rows[0].Environments, []string{"payroll"}) || rows[0].FactsDigest != r.Consequences[0].FactsDigest ||
		rows[0].Depth != 1 || rows[0].ParentPosition.Valid || rows[0].Source != "package" {
		t.Fatalf("predicted: %s %+v %+v", r.Decision, r.Consequences, rows)
	}
	if rc := receiptConsequences(t, r.Receipt); len(rc) != 1 || rc[0].State != "PREDICTED" || rc[0].Target != "payments.charge:ch_1" ||
		rc[0].Operation != "payments.payout.trigger" {
		t.Fatalf("receipt: %+v", rc)
	}

	w.payouts("ch_2", `{"state": "none", "environments": []}`)
	r = w.authorize(w.request(run, ids.NewV7(), "ch_2", "30.00"))
	if rows := stored(r); r.Decision != adomain.Allow || len(rows) != 1 || rows[0].State != "NOT_TRIGGERED" || len(rows[0].Environments) != 0 {
		t.Fatalf("not triggered: %s %+v", r.Decision, rows)
	}
}
