// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/jsontext"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// TestCase is one scenario test of a bundle (M11.1 D7, F193): an action,
// what is given around it, and the decision the real pipeline must reach.
// internal/policy/scenario runs them.
type TestCase struct {
	ID      string     `json:"id"`
	Summary string     `json:"summary"`
	Action  TestAction `json:"action"`
	Given   *TestGiven `json:"given,omitzero"`
	Expect  TestExpect `json:"expect"`
}

// TestAction is the action a case evaluates.
type TestAction struct {
	Operation   string           `json:"operation"`
	Environment string           `json:"environment,omitzero"`
	Params      jsontext.Value   `json:"params"`
	Target      *actionir.Target `json:"target,omitzero"`
}

// TestGiven is the state around the action. Absent parts take the fixture's
// defaults (internal/policy/scenario); an absent fact is missing.
type TestGiven struct {
	// Agent is the agent (a canonical UUID) the action's run belongs to, so
	// a rule on run.agent_id can be tested (M11.1 D20); unset, the runner's
	// fixed default agent.
	Agent            string              `json:"agent,omitzero"`
	Grant            *TestGrant          `json:"grant,omitzero"`
	Budget           *TestBudget         `json:"budget,omitzero"`
	Facts            map[string]TestFact `json:"facts,omitzero"`
	Approval         string              `json:"approval,omitzero"`
	StepUp           string              `json:"step_up,omitzero"`
	DestinationClass string              `json:"destination_class,omitzero"`
	// RunConsequences are the run's consequence counts (G0 M17 D103), so a
	// rule on run.consequences_pending or run.consequences_unconfirmed can be
	// tested; unset, both are 0.
	RunConsequences *TestRunConsequences `json:"run_consequences,omitzero"`
}

// Approval states a case may give.
const (
	ApprovalNone                = "none"
	ApprovalApproved            = "approved"
	ApprovalApprovedOtherAction = "approved_other_action"
	ApprovalExpired             = "expired"
)

// Step-up states a case may give.
const (
	StepUpNone = "none"
	StepUpDone = "done"
)

// TestGrant is the root grant's constraints, as in rules.
type TestGrant struct {
	Constraints []Constraint `json:"constraints,omitzero"`
}

// TestBudget is the usage of one budgeted param: Limit and Used are decimal
// strings, with Currency for money.
type TestBudget struct {
	Param    string `json:"param"`
	Currency string `json:"currency,omitzero"`
	Limit    string `json:"limit"`
	Used     string `json:"used"`
}

// TestFact is a fact's value and age when the action is evaluated.
type TestFact struct {
	Value      jsontext.Value `json:"value"`
	AgeSeconds int            `json:"age_seconds"`
}

// TestExpect is the outcome a case requires: the decision and the decisive
// reason, and the deciding rule when Rule is set.
type TestExpect struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Rule     string `json:"rule,omitzero"`
}

// MaxTests bounds a bundle's scenario tests (HR-238).
const MaxTests = 200

func validateTests(tests []TestCase) error {
	if len(tests) > MaxTests {
		return invalid("a bundle has at most %d tests", MaxTests)
	}
	seen := map[string]bool{}
	for _, tc := range tests {
		if !idRe.MatchString(tc.ID) {
			return invalid("test id %q", tc.ID)
		}
		if seen[tc.ID] {
			return invalid("duplicate test id %s", tc.ID)
		}
		seen[tc.ID] = true
	}
	return nil
}

// TestRunConsequences are the counts of the run's actions whose
// consequences are pending, or unconfirmed or not verifiable.
type TestRunConsequences struct {
	Pending     int `json:"pending,omitzero"`
	Unconfirmed int `json:"unconfirmed,omitzero"`
}
