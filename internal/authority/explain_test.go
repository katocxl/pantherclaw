// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

func fieldNames(d protoreflect.MessageDescriptor) []string {
	var out []string
	for i := range d.Fields().Len() {
		out = append(out, string(d.Fields().Get(i).Name()))
	}
	slices.Sort(out)
	return out
}

// TestHR400_TheAuthorizeResponseExplainsOnlyWhatIsAgentSafe: the
// AgentExplanation on an AuthorizeResponse has exactly the presentation,
// failing category, decisive code, transaction id and recovery actions,
// and none of the decision's grant level, detail, obligations or budgets
// reaches it.
//
// Covers: F330
func TestHR400_TheAuthorizeResponseExplainsOnlyWhatIsAgentSafe(t *testing.T) {
	if got, want := fieldNames((&pantherclawv1.AgentExplanation{}).ProtoReflect().Descriptor()),
		[]string{"decisive_code", "failing_category", "next_actions", "presentation", "transaction_id"}; !slices.Equal(got, want) {
		t.Fatalf("AgentExplanation fields %v, want exactly %v", got, want)
	}
	if got, want := fieldNames((&pantherclawv1.NextAction{}).ProtoReflect().Descriptor()), []string{"code", "label", "url"}; !slices.Equal(got, want) {
		t.Fatalf("NextAction fields %v, want exactly %v", got, want)
	}

	const txn = "0190f3b4-7c2e-7aaa-8bbb-0000000000aa"
	res := Result{
		Decision: domain.Deny,
		Checklist: []pipeline.Item{
			{
				Step: pipeline.StepAuthority, Check: "authority", Status: pipeline.StatusFailed, Code: "GRANT_AMOUNT_EXCEEDED",
				Detail: "amount 30.00 exceeds the grant's 10.00", Level: "grant g-secret@3", Decisive: true,
			},
			{Step: pipeline.StepScope, Check: "scope", Status: pipeline.StatusPassed, Code: "IN_SCOPE"},
		},
		Obligations: []pdomain.Obligation{{Rule: "policy-rule-secret", Param: "amount", Max: "10.00"}},
	}
	x := agentExplanation("https://pc.example/", res, txn)
	if x.GetPresentation() != pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_DENY || x.GetFailingCategory() != "authority" ||
		x.GetDecisiveCode() != "GRANT_AMOUNT_EXCEEDED" || x.GetTransactionId() != txn || len(x.GetNextActions()) != 1 ||
		x.GetNextActions()[0].GetUrl() != "https://pc.example/app/evidence/transactions/"+txn ||
		x.GetNextActions()[0].GetLabel() != "pclaw txn show "+txn || x.GetNextActions()[0].GetCode() != domain.NextActionInspect {
		t.Fatalf("explanation = %v", x)
	}
	b, _ := protojson.Marshal(x)
	for _, leak := range []string{"10.00", "30.00", "g-secret", "policy-rule-secret"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("the explanation carries %q: %s", leak, b)
		}
	}
}

// TestF330_ExplanationByDecision: the failing category is named only for
// Hold, Deny and Cannot authorize; without a console the action has no
// URL; without a transaction there is no recovery action; an answer with
// no checklist is explained by its decisive reason.
//
// Covers: F330, F069
func TestF330_ExplanationByDecision(t *testing.T) {
	item := func(d domain.Decision, check, code string) Result {
		return Result{Decision: d, Checklist: []pipeline.Item{{Check: check, Code: code, Decisive: true}}}
	}
	for _, tc := range []struct {
		res      Result
		pres     pantherclawv1.DecisionPresentation
		category string
	}{
		{item(domain.Allow, "authority", "GRANT_COVERS"), pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_ALLOW, ""},
		{item(domain.AllowWithObligations, "requirements", "CLAMPED"), pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_CONSTRAIN, ""},
		{item(domain.RequireApproval, "requirements", "APPROVAL_REQUIRED"), pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_HOLD, "requirements"},
		{item(domain.RequireStepUp, "requirements", "STEP_UP_REQUIRED"), pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_HOLD, "requirements"},
		{item(domain.Deny, "boundaries", "GUARDRAIL"), pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_DENY, "boundaries"},
		{item(domain.CannotAuthorize, "facts", "FACT_STALE"), pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_CANNOT_AUTHORIZE, "facts"},
	} {
		x := agentExplanation("", tc.res, "t-1")
		if x.GetPresentation() != tc.pres || x.GetFailingCategory() != tc.category || x.GetDecisiveCode() != tc.res.Checklist[0].Code ||
			x.GetNextActions()[0].GetUrl() != "" {
			t.Errorf("%s: %v", tc.res.Decision, x)
		}
	}
	x := agentExplanation("https://pc.example", Result{Decision: domain.CannotAuthorize, Reasons: []domain.Reason{
		{Code: domain.ReasonIdentityUnverified, Check: "identity", Decisive: true},
	}}, "")
	if x.GetFailingCategory() != "identity" || x.GetDecisiveCode() != domain.ReasonIdentityUnverified || len(x.GetNextActions()) != 0 {
		t.Fatalf("identity answer = %v", x)
	}
}
