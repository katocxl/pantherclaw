// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"strings"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// Explanation is the agent-safe explanation in a refusal body (F330,
// HR-400): the presentation, the failing category, the decisive code, the
// transaction and the recovery actions. Nothing else from the decision is
// added: never the grant, policy, limits, budgets or request.
type Explanation struct {
	// Presentation is "allow", "constrain", "hold", "deny" or
	// "cannot_authorize".
	Presentation    string       `json:"presentation"`
	FailingCategory string       `json:"failing_category"`
	DecisiveCode    string       `json:"decisive_code"`
	TransactionID   string       `json:"transaction_id"`
	NextActions     []NextAction `json:"next_actions"`
}

// NextAction is one recovery action.
type NextAction struct {
	Code  string `json:"code"`
	Label string `json:"label"`
	URL   string `json:"url"`
}

// ExplanationOf is the body form of the Authority's explanation; nil when
// there was none (the gateway refused before asking).
func ExplanationOf(e *pb.AgentExplanation) *Explanation {
	if e == nil {
		return nil
	}
	out := &Explanation{
		Presentation:    strings.ToLower(strings.TrimPrefix(e.GetPresentation().String(), "DECISION_PRESENTATION_")),
		FailingCategory: e.GetFailingCategory(), DecisiveCode: e.GetDecisiveCode(), TransactionID: e.GetTransactionId(),
		NextActions: []NextAction{},
	}
	for _, a := range e.GetNextActions() {
		out.NextActions = append(out.NextActions, NextAction{Code: a.GetCode(), Label: a.GetLabel(), URL: a.GetUrl()})
	}
	return out
}
