// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"maps"
	"slices"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// Verdict is the policy's contribution to a decision. PASS means no rule
// restricts the action; it is not ALLOW, which only a grant can give.
type Verdict string

// Verdicts, from most to least restrictive.
const (
	VerdictDeny            Verdict = "DENY"
	VerdictCannotAuthorize Verdict = "CANNOT_AUTHORIZE"
	VerdictRequireApproval Verdict = "REQUIRE_APPROVAL"
	VerdictRequireStepUp   Verdict = "REQUIRE_STEP_UP"
	VerdictConstrain       Verdict = "CONSTRAIN"
	VerdictPass            Verdict = "PASS"
)

var order = []Verdict{VerdictDeny, VerdictCannotAuthorize, VerdictRequireApproval, VerdictRequireStepUp, VerdictConstrain, VerdictPass}

func stricter(a, b Verdict) bool { return slices.Index(order, a) < slices.Index(order, b) }

// Status is a checklist status (F078).
type Status string

// Checklist statuses.
const (
	StatusPassed        Status = "PASSED"         // condition false: the rule does not restrict
	StatusFailed        Status = "FAILED"         // a prohibition or limit decides against the action
	StatusRequired      Status = "REQUIRED"       // a requirement must be satisfied first
	StatusConstrained   Status = "CONSTRAINED"    // an obligation applies
	StatusAnnotated     Status = "ANNOTATED"      // labels were added
	StatusError         Status = "ERROR"          // the rule could not be evaluated
	StatusNotApplicable Status = "NOT_APPLICABLE" // out of the rule's scope
	StatusNotEvaluated  Status = "NOT_EVALUATED"  // its facts are missing or stale
)

// Effect is how one rule evaluated.
type Effect int

// Rule effects.
const (
	OutOfScope Effect = iota
	NotMatched
	Matched
	// Violated: a CONSTRAIN rule whose limit the action exceeds and which
	// cannot be safely transformed (F105) — the limit decides: DENY.
	Violated
	// Unsupported: a CONSTRAIN rule the definition cannot enforce (F100).
	Unsupported
	// EvalError: the condition errored, returned a non-boolean or could
	// not be compiled.
	EvalError
	// CostExceeded: the per-expression or per-evaluation budget ran out.
	CostExceeded
	// FactsMissing: a fact the rule reads is missing or stale, so it was
	// not evaluated. Missing evidence is CANNOT_AUTHORIZE, never a
	// business denial (F096), even for FORBID.
	FactsMissing
)

// Obligation is a constraint the gateway or connector must enforce, with its
// timing (F071), or, for verify, one the Authority applies after dispatch.
type Obligation struct {
	Rule   string         `json:"rule"`
	Kind   ConstraintKind `json:"kind"`
	Param  string         `json:"param,omitzero"`
	Max    string         `json:"max,omitzero"`
	Values []string       `json:"values,omitzero"`
	Clamp  bool           `json:"clamp,omitzero"`
	// Level is the verification level a verify obligation requires.
	Level  defs.Level `json:"level,omitzero"`
	Timing string     `json:"timing"`
}

// Obligation timings (F071).
const (
	TimingBeforeExecution = "before_execution"
	TimingAfterDispatch   = "after_dispatch"
)

// ByAuthority reports whether the Authority itself applies the obligation:
// verify raises the level the effect is verified at (G0 M7 design decision
// 2). The gateway never applies, and is never sent, such an obligation.
func (o Obligation) ByAuthority() bool { return o.Kind == Verify }

// Result is the evaluation of one rule, produced by the policy engine.
type Result struct {
	Rule       *Rule
	Effect     Effect
	Detail     string
	Obligation *Obligation
}

// Item is one checklist line.
type Item struct {
	Rule     string `json:"rule"`
	Kind     Kind   `json:"kind"`
	Status   Status `json:"status"`
	Reason   string `json:"reason"`
	Detail   string `json:"detail,omitzero"`
	Decisive bool   `json:"decisive"`
	// Verdict is what this rule alone does to the action.
	Verdict Verdict `json:"verdict"`
}

// Outcome is the policy verdict with its explanation.
type Outcome struct {
	Verdict   Verdict
	Checklist []Item
	Approvals []ApprovalRequirement
	StepUps   []StepUpRequirement
	// Required lists the same requirements with the rule that asks for each
	// (G0 M5 part 2: a hold keeps every requirement's source).
	Required    []Required
	Obligations []Obligation
	Labels      map[string]string
}

// Required is one requirement of a REQUIRE_APPROVAL or REQUIRE_STEP_UP rule.
type Required struct {
	Rule     string
	Reason   string
	Approval *ApprovalRequirement
	StepUp   *StepUpRequirement
}

// Decisive returns the decisive checklist item, if any.
func (o Outcome) Decisive() (Item, bool) {
	if len(o.Checklist) > 0 && o.Checklist[0].Decisive {
		return o.Checklist[0], true
	}
	return Item{}, false
}

// Reason codes for outcomes not named by a rule.
const (
	ReasonEvalError             = "POLICY_EVALUATION_ERROR"
	ReasonCostExceeded          = "POLICY_COST_EXCEEDED"
	ReasonUnsupportedObligation = "UNSUPPORTED_OBLIGATION"
	ReasonFactMissing           = "FACT_MISSING"
)

// classify maps one result to its checklist status and the verdict it
// forces (fail-closed, HR-040/HR-043):
//   - an error in FORBID ⇒ DENY; in REQUIRE or CONSTRAIN ⇒ CANNOT_AUTHORIZE;
//     in ANNOTATE ⇒ nothing (shown, never decisive);
//   - a cost overrun ⇒ CANNOT_AUTHORIZE whatever the kind;
//   - an unsupported constraint ⇒ CANNOT_AUTHORIZE (F100).
func classify(r Result) (Status, Verdict, string) {
	k := r.Rule.Kind
	switch r.Effect {
	case OutOfScope:
		return StatusNotApplicable, VerdictPass, r.Rule.Reason
	case NotMatched:
		return StatusPassed, VerdictPass, r.Rule.Reason
	case CostExceeded:
		return StatusError, VerdictCannotAuthorize, ReasonCostExceeded
	case FactsMissing:
		if k == Annotate {
			return StatusNotEvaluated, VerdictPass, ReasonFactMissing
		}
		return StatusNotEvaluated, VerdictCannotAuthorize, ReasonFactMissing
	case Unsupported:
		return StatusError, VerdictCannotAuthorize, ReasonUnsupportedObligation
	case Violated:
		return StatusFailed, VerdictDeny, r.Rule.Reason
	case EvalError:
		switch k {
		case Forbid:
			return StatusError, VerdictDeny, ReasonEvalError
		case Annotate:
			return StatusError, VerdictPass, ReasonEvalError
		case RequireApproval, RequireStepUp, Constrain:
		}
		return StatusError, VerdictCannotAuthorize, ReasonEvalError
	case Matched:
	}
	switch k {
	case Forbid:
		return StatusFailed, VerdictDeny, r.Rule.Reason
	case RequireApproval:
		return StatusRequired, VerdictRequireApproval, r.Rule.Reason
	case RequireStepUp:
		return StatusRequired, VerdictRequireStepUp, r.Rule.Reason
	case Constrain:
		if r.Obligation == nil { // the action is already within the limit
			return StatusPassed, VerdictPass, r.Rule.Reason
		}
		return StatusConstrained, VerdictConstrain, r.Rule.Reason
	case Annotate:
		return StatusAnnotated, VerdictPass, r.Rule.Reason
	}
	// An unknown kind never passes.
	return StatusError, VerdictCannotAuthorize, ReasonEvalError
}

// Compose combines rule results deterministically (F092): the strictest
// verdict wins; prohibitions cannot be overridden; compatible requirements
// and obligations accumulate; the decisive item comes first, then the rest
// of the checklist in rule order (failed, errors, requirements, others).
func Compose(results []Result) Outcome {
	out := Outcome{Verdict: VerdictPass, Labels: map[string]string{}}
	decisive := -1
	items := make([]Item, 0, len(results))
	for _, r := range results {
		status, v, reason := classify(r)
		items = append(items, Item{Rule: r.Rule.ID, Kind: r.Rule.Kind, Status: status, Reason: reason, Detail: r.Detail, Verdict: v})
		if stricter(v, out.Verdict) {
			out.Verdict, decisive = v, len(items)-1
		}
		switch status { //nolint:exhaustive // only these statuses carry requirements or labels
		case StatusRequired:
			if r.Rule.Approval != nil {
				out.Approvals = append(out.Approvals, *r.Rule.Approval)
			}
			if r.Rule.StepUp != nil {
				out.StepUps = append(out.StepUps, *r.Rule.StepUp)
			}
			out.Required = append(out.Required, Required{Rule: r.Rule.ID, Reason: reason, Approval: r.Rule.Approval, StepUp: r.Rule.StepUp})
		case StatusConstrained:
			out.Obligations = append(out.Obligations, *r.Obligation)
		case StatusAnnotated:
			for _, k := range slices.Sorted(maps.Keys(r.Rule.Labels)) {
				if _, taken := out.Labels[k]; !taken { // first rule wins: deterministic
					out.Labels[k] = r.Rule.Labels[k]
				}
			}
		}
	}
	if decisive >= 0 {
		items[decisive].Decisive = true
		d := items[decisive]
		items = append([]Item{d}, slices.Delete(items, decisive, decisive+1)...)
	}
	rank := map[Status]int{StatusFailed: 0, StatusError: 1, StatusNotEvaluated: 2, StatusRequired: 3, StatusConstrained: 4, StatusAnnotated: 5, StatusPassed: 6, StatusNotApplicable: 7}
	start := 0
	if decisive >= 0 {
		start = 1
	}
	slices.SortStableFunc(items[start:], func(a, b Item) int { return rank[a.Status] - rank[b.Status] })
	out.Checklist = items
	return out
}
