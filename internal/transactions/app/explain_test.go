// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
)

// receipt is an unsigned decision receipt with payload claims: explain
// reads, never verifies.
func receipt(claims string) string {
	return "e30." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".sig"
}

const grantID = "0192aaaa-bbbb-7ccc-8ddd-0000000000g1"

func sample(decision, check, code string, execution domain.ExecutionState, coverage string) (*Evidence, explainInputs) {
	ev := &Evidence{
		Transaction: Summary{ID: ids.NewV7(), Decision: decision, Operation: "payments.refund.create", Execution: execution},
		Decisions: []DecisionRecord{{Evaluation: 1, JWS: receipt(`{"pap": {"decision": "` + decision + `",
			"checklist": [{"step": 4, "check": "` + check + `", "status": "FAILED", "code": "` + code + `", "detail": "over 10.00",
			  "level": "grant ` + grantID + `@2", "decisive": true}, {"step": 1, "check": "scope", "status": "PASSED", "code": "IN_SCOPE"}],
			"identity": {"principal": "user:0192aaaa-bbbb-7ccc-8ddd-0000000000u1"},
			"budgets": [{"level": "` + grantID + `", "rule": "task", "currency": "USD", "available": "20.00", "reserved": "30.00", "spent": "50.00"}],
			"consequences": [{"state": "UNKNOWN"}], "coverage": {"state": "` + coverage + `"}}}`)}},
		Basis: &DecisionBasis{Policy: "0192aaaa-bbbb-7ccc-8ddd-0000000000p1", Levels: []Level{{Kind: "grant", ID: grantID, Revision: 2}}},
	}
	in := explainInputs{
		facts:   dbq.ExplanationFactsRow{TargetType: "stripe.charge", TargetID: "ch_1", EnvironmentID: ids.NewV7()},
		grant:   &dbq.ExplanationGrantRevisionRow{ExpiresAt: time.Now().Add(time.Hour), Bounds: []byte(`{"operations": ["payments.refund.create"], "params": {"x": 1}}`)},
		unknown: map[string]money.Decimal{grantID + "/task": money.MustParse("30.00")}, budgetsShown: true, grantID: grantID, grantRevision: 2,
		material: map[string]string{"amount": "60.00 USD", "charge": "ch_1"}, materialOK: true,
	}
	return ev, in
}

// TestF066_EveryFieldOfAHeldAndADeniedDecisionIsFilled: the explanation
// of a held and of a denied transaction fills every field: the decision,
// its presentation, the failing check and decisive item, the action, the
// principal, environment, grant, policy, budgets, gaps, execution state.
// No grant revision carries a structured task id, so task_id stays empty
// (rows26 D12a). Material values come from the sealed inputs (D12b).
//
// Covers: F066, F647
func TestF066_EveryFieldOfAHeldAndADeniedDecisionIsFilled(t *testing.T) {
	held, heldIn := sample("REQUIRE_APPROVAL", "requirements", "REFUND_OVER_50", domain.Waiting, "PARTIAL")
	denied, deniedIn := sample("DENY", "authority", "BUDGET_EXHAUSTED", domain.Blocked, "OBSERVE_ONLY")
	for _, tc := range []struct {
		name     string
		ev       *Evidence
		in       explainInputs
		pres     adomain.Presentation
		material map[string]string
		gap      string
	}{
		{"held", held, heldIn, adomain.PresentHold, map[string]string{"amount": "60.00 USD", "charge": "ch_1"}, GapCoveragePartial},
		{"denied", denied, deniedIn, adomain.PresentDeny, map[string]string{"amount": "60.00 USD", "charge": "ch_1"}, GapCoverageObserveOnly},
	} {
		x := explain(tc.ev, tc.in)
		if x == nil {
			t.Fatalf("%s: no explanation", tc.name)
		}
		if x.Decision != tc.ev.Transaction.Decision || x.Presentation != tc.pres || x.Category == "" || x.Decisive == nil ||
			x.Decisive.Code == "" || x.Decisive.Check != x.Category || x.Operation == "" || x.Target != "stripe.charge:ch_1" ||
			x.Principal != "user:0192aaaa-bbbb-7ccc-8ddd-0000000000u1" || x.Environment == "" || x.Policy == "" ||
			x.Execution != tc.ev.Transaction.Execution {
			t.Errorf("%s: %+v", tc.name, x)
		}
		if !maps.Equal(x.Material, tc.material) {
			t.Errorf("%s: material %v, want %v", tc.name, x.Material, tc.material)
		}
		if g := x.Grant; g == nil || g.ID != grantID || g.Revision != 2 || g.Expires.IsZero() ||
			!slices.Equal(g.Constraints, []string{"operations", "params"}) {
			t.Errorf("%s: grant %+v", tc.name, x.Grant)
		}
		if len(x.Budgets) != 1 || x.Budgets[0] != (ExplainedBudget{
			Owner: grantID, Rule: "task", Currency: "USD", Limit: "100", Reserved: "30.00", Spent: "50.00", Unknown: "30",
		}) {
			t.Errorf("%s: budgets %+v", tc.name, x.Budgets)
		}
		if !slices.Equal(x.Gaps, []string{GapUnknownConsequence, tc.gap}) {
			t.Errorf("%s: gaps %v", tc.name, x.Gaps)
		}
	}
}

// TestF066_GrantValuesAndBudgetsFollowPermissions: with grant.read the
// constraints carry their values; without budget.read no budget is shown.
//
// Covers: F066
func TestF066_GrantValuesAndBudgetsFollowPermissions(t *testing.T) {
	ev, in := sample("DENY", "authority", "GRANT_AMOUNT_EXCEEDED", domain.Blocked, "ENFORCED")
	in.grantValues, in.budgetsShown = true, false
	x := explain(ev, in)
	if want := []string{`operations=["payments.refund.create"]`, `params={"x":1}`}; !slices.Equal(x.Grant.Constraints, want) {
		t.Fatalf("constraints with grant.read %v, want %v", x.Grant.Constraints, want)
	}
	if x.Budgets != nil {
		t.Fatalf("budgets without budget.read: %+v", x.Budgets)
	}
	if !slices.Equal(x.Gaps, []string{GapUnknownConsequence}) {
		t.Fatalf("an enforced claim is no gap: %v", x.Gaps)
	}
}

// TestF647_GapsAndPresentation: an allow names no failing category; an
// unknown outcome, an executed action with no confirmed effect and a
// missing coverage claim are gaps.
//
// Covers: F647, F069
func TestF647_GapsAndPresentation(t *testing.T) {
	ev, in := sample("ALLOW", "authority", "GRANT_COVERS", domain.Dispatched, "ENFORCED")
	ev.Decisions[0].JWS = receipt(`{"pap": {"decision": "ALLOW", "checklist": [{"check": "authority", "code": "GRANT_COVERS", "decisive": true}]}}`)
	ev.Execution = &ExecutionRecord{Outcome: "unknown"}
	x := explain(ev, in)
	if x.Presentation != adomain.PresentAllow || x.Category != "" || x.Decisive.Code != "GRANT_COVERS" {
		t.Fatalf("allow %+v", x)
	}
	if want := []string{GapOutcomeUnknown, GapNoEffectConfirmed, GapCoverageUnknown}; !slices.Equal(x.Gaps, want) {
		t.Fatalf("gaps %v, want %v", x.Gaps, want)
	}
	if explain(&Evidence{}, in) != nil {
		t.Fatal("an explanation without a decision receipt")
	}
}

type failingRecordings struct{ err error }

func (f failingRecordings) RecordedInputs(context.Context, ids.OrgID, ids.UUID, int) (*recording.Recording, error) {
	return nil, f.err
}

func (failingRecordings) Definition(context.Context, ids.OrgID, actionir.Definition) (pipeline.Pinned, error) {
	return pipeline.Pinned{}, nil
}

// TestF066_MissingInputsAreAGap: when the sealed inputs are missing or
// truncated (or no opener is configured) the material values stay empty
// and the gaps say so (rows26 D12b).
//
// Covers: F066, F647
func TestF066_MissingInputsAreAGap(t *testing.T) {
	for _, r := range []Recordings{nil, failingRecordings{recording.ErrTruncated}, failingRecordings{errors.New("no row")}} {
		if m, ok := recordedMaterial(context.Background(), r, ids.OrgID{}, ids.NewV7(), 1); ok || m != nil {
			t.Fatalf("%T: material %v ok %v", r, m, ok)
		}
	}
	ev, in := sample("DENY", "authority", "GRANT_AMOUNT_EXCEEDED", domain.Blocked, "ENFORCED")
	in.material, in.materialOK = nil, false
	x := explain(ev, in)
	if len(x.Material) != 0 || !slices.Contains(x.Gaps, GapMaterialUnavailable) {
		t.Fatalf("missing inputs: material %v, gaps %v", x.Material, x.Gaps)
	}
}
