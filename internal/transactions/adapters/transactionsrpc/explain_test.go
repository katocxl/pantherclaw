// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package transactionsrpc

import (
	"testing"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// TestF066_ExplanationProto: every explanation field reaches the API, and
// the recovery action links the console only when there is one.
//
// Covers: F066, F069
func TestF066_ExplanationProto(t *testing.T) {
	x := &app.Explanation{
		Decision: "REQUIRE_APPROVAL", Presentation: adomain.PresentHold, Category: "requirements",
		Decisive:  &app.ChecklistLine{Step: 8, Check: "requirements", Status: "REQUIRED", Code: "REFUND_OVER_50", Decisive: true},
		Operation: "payments.refund.create", Target: "stripe.charge:ch_1", Material: map[string]string{"amount": "60.00 USD"},
		Principal: "user:u", Environment: "e", Policy: "p", Execution: domain.Waiting, Gaps: []string{app.GapCoveragePartial},
		Grant:   &app.ExplainedGrant{ID: "g", Revision: 2, Constraints: []string{"operations"}, Expires: time.Now()},
		Budgets: []app.ExplainedBudget{{Account: "a", Owner: "g", Rule: "task", Currency: "USD", Limit: "100", Reserved: "30", Spent: "50"}},
	}
	p := explanationProto(x, "t-1", "https://pc.example")
	if p.GetDecision() != pantherclawv1.Decision_DECISION_REQUIRE_APPROVAL ||
		p.GetPresentation() != pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_HOLD || p.GetFailingCategory() != "requirements" ||
		p.GetDecisive().GetStatus() != pantherclawv1.ChecklistStatus_CHECKLIST_STATUS_REQUIRED || p.GetDecisive().GetCode() != "REFUND_OVER_50" ||
		p.GetTransactionId() != "t-1" || p.GetAction().GetMaterialValues()["amount"] != "60.00 USD" || p.GetAction().GetTarget() != "stripe.charge:ch_1" ||
		p.GetPrincipal() != "user:u" || p.GetEnvironment() != "e" || p.GetGrant().GetRevision() != 2 || p.GetGrant().GetExpireTime() == nil ||
		p.GetPolicyVersionId() != "p" || len(p.GetBudgets()) != 1 || p.GetBudgets()[0].GetLimit() != "100" ||
		p.GetBudgets()[0].GetAccountId() != "a" || p.GetBudgets()[0].GetOwnerId() != "g" || len(p.GetGaps()) != 1 ||
		p.GetExecutionState() != "WAITING" || len(p.GetNextActions()) != 1 ||
		p.GetNextActions()[0].GetUrl() != "https://pc.example/app/evidence/transactions/t-1" {
		t.Fatalf("explanation = %v", p)
	}
	if p := explanationProto(x, "t-1", ""); p.GetNextActions()[0].GetUrl() != "" || p.GetNextActions()[0].GetLabel() != "pclaw txn show t-1" {
		t.Fatalf("without a console: %v", p.GetNextActions())
	}
	if explanationProto(nil, "t-1", "") != nil {
		t.Fatal("an explanation from nothing")
	}
}
