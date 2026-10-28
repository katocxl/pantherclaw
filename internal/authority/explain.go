// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// PresentationToProto maps a presentation (F069).
var PresentationToProto = map[domain.Presentation]pantherclawv1.DecisionPresentation{
	domain.PresentAllow:           pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_ALLOW,
	domain.PresentConstrain:       pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_CONSTRAIN,
	domain.PresentHold:            pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_HOLD,
	domain.PresentDeny:            pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_DENY,
	domain.PresentCannotAuthorize: pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_CANNOT_AUTHORIZE,
}

// NextActions are a transaction's recovery actions (domain.NextActions).
func NextActions(consoleURL, txn string) []*pantherclawv1.NextAction {
	var out []*pantherclawv1.NextAction
	for _, a := range domain.NextActions(consoleURL, txn) {
		out = append(out, &pantherclawv1.NextAction{Code: a.Code, Label: a.Label, Url: a.URL})
	}
	return out
}

// agentExplanation is all the decision tells the agent (HR-400): the
// presentation, the decisive check and code, the transaction and recovery
// links, never the grant, policy, limits, budgets or request.
func agentExplanation(consoleURL string, res Result, txn string) *pantherclawv1.AgentExplanation {
	p := res.Decision.Presentation()
	check, code := decisive(res.Checklist, res.Reasons)
	out := &pantherclawv1.AgentExplanation{
		Presentation: PresentationToProto[p], DecisiveCode: code, TransactionId: txn, NextActions: NextActions(consoleURL, txn),
	}
	if p.Explains() {
		out.FailingCategory = check
	}
	return out
}

// decisive is the decisive checklist item's check and code, or, for an
// answer without a checklist (identity, binding), the decisive reason's.
func decisive(items []pipeline.Item, reasons []domain.Reason) (check, code string) {
	for _, it := range items {
		if it.Decisive {
			return it.Check, it.Code
		}
	}
	for _, r := range reasons {
		if r.Decisive {
			return r.Check, r.Code
		}
	}
	if len(reasons) > 0 {
		return reasons[0].Check, reasons[0].Code
	}
	return "", ""
}
