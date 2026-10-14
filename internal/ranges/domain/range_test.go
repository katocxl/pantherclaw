// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/ranges/domain"
)

func TestSetDigestIgnoresOrderAndCoversEveryDigest(t *testing.T) {
	a := domain.Scenario{ID: "RT-001", Digest: "aa"}
	b := domain.Scenario{ID: "RT-002", Digest: "bb"}
	if domain.SetDigest([]domain.Scenario{a, b}) != domain.SetDigest([]domain.Scenario{b, a}) {
		t.Fatal("order changes the set digest")
	}
	b.Digest = "cc"
	if domain.SetDigest([]domain.Scenario{a, b}) == domain.SetDigest([]domain.Scenario{a, {ID: "RT-002", Digest: "bb"}}) {
		t.Fatal("a changed scenario keeps the set digest")
	}
}

func TestObserveDerivesFromDecisionAndEffect(t *testing.T) {
	for _, tc := range []struct {
		decision, effect string
		expect, want     string
	}{
		{"ALLOW_WITH_OBLIGATIONS", "", domain.OutcomeAllow, domain.OutcomeAllow},
		{"REQUIRE_STEP_UP", "", domain.OutcomeHold, domain.OutcomeHold},
		{"DENY", "", domain.OutcomeDeny, domain.OutcomeDeny},
		{"CANNOT_AUTHORIZE", "", domain.OutcomeDeny, domain.OutcomeCannotAuthorize},
		{"ALLOW", "CONFIRMED", domain.OutcomeConfirmed, domain.OutcomeConfirmed},
		{"ALLOW", "UNKNOWN", domain.OutcomeConfirmed, domain.OutcomeUnknown},
		// An effect that is neither falls back to the decision.
		{"ALLOW", "PARTIAL", domain.OutcomeConfirmed, domain.OutcomeAllow},
	} {
		got := domain.TransactionRecord{Decision: tc.decision, EffectState: tc.effect}.Observe(domain.Expect{Outcome: tc.expect})
		if got.Outcome != tc.want || got.Code != "" {
			t.Errorf("%s/%s expecting %s: %+v, want %s", tc.decision, tc.effect, tc.expect, got, tc.want)
		}
	}
}

func TestResolveFlagsClaimsTheServerDoesNotShare(t *testing.T) {
	server := domain.Expect{Outcome: domain.OutcomeDeny, Reason: "R"}
	tx := ids.NewV7()
	for name, tc := range map[string]struct {
		claim    domain.Expect
		mismatch bool
	}{
		"same":          {domain.Expect{Outcome: domain.OutcomeDeny, Reason: "R"}, false},
		"no reason":     {domain.Expect{Outcome: domain.OutcomeDeny}, false},
		"other outcome": {domain.Expect{Outcome: domain.OutcomeAllow, Reason: "R"}, true},
		"other reason":  {domain.Expect{Outcome: domain.OutcomeDeny, Reason: "X"}, true},
		"invented code": {domain.Expect{Outcome: domain.OutcomeDeny, Reason: "R", Code: "c"}, true},
	} {
		st := domain.Resolve(domain.StepInput{ID: "s", Expect: server, Observed: tc.claim, Transaction: &tx}, &server)
		if st.Mismatch != tc.mismatch || st.Observed != server || st.ObservedBy != domain.Server || !st.Matched {
			t.Errorf("%s: %+v", name, st)
		}
	}
}

func TestFinalizeAddsMissingInDeclaredOrder(t *testing.T) {
	d := []domain.Scenario{{ID: "RT-001"}, {ID: "RT-002"}, {ID: "RT-003"}}
	got := domain.Finalize(d, []domain.Result{{Scenario: d[1], Verdict: domain.Pass}}, time.Now())
	if len(got) != 3 || got[0].Verdict != domain.Missing || got[1].Verdict != domain.Pass || got[2].Verdict != domain.Missing {
		t.Fatalf("%+v", got)
	}
	if c := domain.Count(got); c != (domain.Counts{Pass: 1, Missing: 2}) {
		t.Fatalf("%+v", c)
	}
}

func TestDeriveKeepsErrorAndSkippedAndRefusesEmptyVerdicts(t *testing.T) {
	if v, ok := domain.Derive(domain.Errored, nil); !ok || v != domain.Errored {
		t.Fatal("ERROR must be kept")
	}
	if _, ok := domain.Derive(domain.Pass, nil); ok {
		t.Fatal("a PASS without steps")
	}
	if _, ok := domain.Derive(domain.Missing, nil); ok {
		t.Fatal("MISSING is the server's alone")
	}
}
