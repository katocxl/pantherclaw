// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package transactionsrpc

import (
	"strings"

	"google.golang.org/protobuf/types/known/timestamppb"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/transactions/app"
)

var presentations = map[adomain.Presentation]pantherclawv1.DecisionPresentation{
	adomain.PresentAllow:           pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_ALLOW,
	adomain.PresentConstrain:       pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_CONSTRAIN,
	adomain.PresentHold:            pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_HOLD,
	adomain.PresentDeny:            pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_DENY,
	adomain.PresentCannotAuthorize: pantherclawv1.DecisionPresentation_DECISION_PRESENTATION_CANNOT_AUTHORIZE,
}

// explanationProto converts a decision explanation (F066, F647); nil for
// none.
func explanationProto(x *app.Explanation, txn, consoleURL string) *pantherclawv1.DecisionExplanation {
	if x == nil {
		return nil
	}
	out := &pantherclawv1.DecisionExplanation{
		Decision:     pantherclawv1.Decision(pantherclawv1.Decision_value["DECISION_"+x.Decision]),
		Presentation: presentations[x.Presentation], FailingCategory: x.Category, TransactionId: txn,
		Action:    &pantherclawv1.ExplainedAction{Operation: x.Operation, Target: x.Target, MaterialValues: x.Material},
		Principal: x.Principal, Environment: x.Environment, PolicyVersionId: x.Policy, Gaps: x.Gaps,
		ExecutionState: string(x.Execution),
	}
	if d := x.Decisive; d != nil {
		out.Decisive = &pantherclawv1.ChecklistItem{
			Step: int32(d.Step), Check: d.Check, Code: d.Code, Detail: d.Detail, Level: d.Level, Decisive: true, //nolint:gosec // G115: 1..10
			Status: pantherclawv1.ChecklistStatus(pantherclawv1.ChecklistStatus_value["CHECKLIST_STATUS_"+strings.ToUpper(d.Status)]),
		}
	}
	if g := x.Grant; g != nil {
		out.Grant = &pantherclawv1.ExplainedGrant{Id: g.ID, Revision: int64(g.Revision), Constraints: g.Constraints}
		if !g.Expires.IsZero() {
			out.Grant.ExpireTime = timestamppb.New(g.Expires)
		}
	}
	for _, b := range x.Budgets {
		out.Budgets = append(out.Budgets, &pantherclawv1.ExplainedBudget{
			AccountId: b.Account, OwnerId: b.Owner, Rule: b.Rule, Currency: b.Currency, Limit: b.Limit, Reserved: b.Reserved, Spent: b.Spent, Unknown: b.Unknown,
		})
	}
	for _, c := range x.Consequences {
		out.Consequences = append(out.Consequences, &pantherclawv1.ExplainedConsequence{
			RuleId: c.Rule, Source: c.Source, Chain: c.Chain, Operation: c.Operation, Target: c.Target, Environments: c.Environments,
			Description: c.Description, Evidence: c.Evidence, ValidUntil: c.ValidUntil, UnknownLinks: c.UnknownLinks,
			Label: pantherclawv1.ConsequenceLabel(pantherclawv1.ConsequenceLabel_value["CONSEQUENCE_LABEL_"+string(c.Label)]),
		})
	}
	for _, a := range adomain.NextActions(consoleURL, txn) {
		out.NextActions = append(out.NextActions, &pantherclawv1.NextAction{Code: a.Code, Label: a.Label, Url: a.URL})
	}
	return out
}
