// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"slices"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
)

// Steps of the decision pipeline (ARCHITECTURE §6.1).
const (
	StepScope        = 1
	StepIdentity     = 2
	StepContainment  = 3
	StepAuthority    = 4
	StepMeaning      = 5
	StepFacts        = 6
	StepBoundaries   = 7
	StepRequirements = 8
	StepFinalBinding = 9
	StepObserve      = 10
)

var stepChecks = map[int]string{
	StepScope: "scope", StepIdentity: "identity", StepContainment: "containment", StepAuthority: "authority",
	StepMeaning: "exact_meaning", StepFacts: "facts", StepBoundaries: "boundaries", StepRequirements: "requirements",
	StepFinalBinding: "final_binding", StepObserve: "observe",
}

// Status is a checklist status (F078).
type Status string

// Statuses. MISSING marks missing evidence (CANNOT_AUTHORIZE), REQUIRED a
// requirement still to satisfy, NOT_EVALUATED a check that could not run
// because an earlier one failed.
const (
	StatusPassed        Status = "PASSED"
	StatusFailed        Status = "FAILED"
	StatusMissing       Status = "MISSING"
	StatusRequired      Status = "REQUIRED"
	StatusConstrained   Status = "CONSTRAINED"
	StatusAnnotated     Status = "ANNOTATED"
	StatusNotEvaluated  Status = "NOT_EVALUATED"
	StatusNotApplicable Status = "NOT_APPLICABLE"
	// StatusWaived: an active policy exception waived a matched exceptable
	// rule (G0 M11.1 D14, HR-235); the item's code is EXCEPTION_APPLIED and
	// its detail the exception id.
	StatusWaived Status = "WAIVED"
)

// Item is one checklist line. Detail names the offending value and what is
// permitted (F079); it is built from canonical fields and stored records,
// never from agent-supplied text (HR-023).
type Item struct {
	Step     int    `json:"step"`
	Check    string `json:"check"`
	Status   Status `json:"status"`
	Code     string `json:"code"`
	Detail   string `json:"detail,omitzero"`
	Level    string `json:"level,omitzero"`
	Decisive bool   `json:"decisive"`

	// effect is what the item does to the decision.
	effect adomain.Decision
}

// strictness orders decisions: the strictest present wins (F092, F096).
var strictness = []adomain.Decision{
	adomain.Deny, adomain.CannotAuthorize, adomain.RequireApproval, adomain.RequireStepUp,
	adomain.AllowWithObligations, adomain.Allow,
}

func rank(d adomain.Decision) int {
	if i := slices.Index(strictness, d); i >= 0 {
		return i
	}
	return 0 // unknown is the strictest
}

// statusOf maps an effect to its checklist status.
func statusOf(d adomain.Decision) Status {
	switch d {
	case adomain.Deny:
		return StatusFailed
	case adomain.CannotAuthorize:
		return StatusMissing
	case adomain.RequireApproval, adomain.RequireStepUp:
		return StatusRequired
	case adomain.AllowWithObligations:
		return StatusConstrained
	case adomain.Allow:
	}
	return StatusPassed
}

// checklist collects items in step order.
type checklist struct{ items []Item }

func (c *checklist) add(step int, effect adomain.Decision, code, detail, level string) {
	c.items = append(c.items, Item{Step: step, Check: stepChecks[step], Status: statusOf(effect), Code: code, Detail: detail, Level: level, effect: effect})
}

func (c *checklist) pass(step int, code string) {
	c.add(step, adomain.Allow, code, "", "")
}

func (c *checklist) note(step int, s Status, code, detail string) {
	c.items = append(c.items, Item{Step: step, Check: stepChecks[step], Status: s, Code: code, Detail: detail, effect: adomain.Allow})
}

func (c *checklist) skip(step int, why string) {
	c.note(step, StatusNotEvaluated, "NOT_EVALUATED", why)
}

// compose returns the decision and the checklist with the decisive item
// first (F078). The strictest effect wins; among items with that effect the
// first in step order decides. Only an action a grant covers can be
// allowed (F095): every path that leaves it uncovered adds its own reason,
// and as a last line of defense an uncovered action that nothing blocked is
// CANNOT_AUTHORIZE, never ALLOW.
func (c *checklist) compose(covered bool) (adomain.Decision, []Item) {
	decision := c.strictest()
	if !covered && decision.Permits() {
		c.add(StepAuthority, adomain.CannotAuthorize, "AUTHORITY_NOT_ESTABLISHED", "no grant could be shown to cover the action", "")
		decision = c.strictest()
	}
	items := slices.Clone(c.items)
	slices.SortStableFunc(items, func(a, b Item) int { return a.Step - b.Step })
	// The first item, in step order, with the winning effect decides; an
	// ALLOW is explained by the grant that covers the action.
	for i := range items {
		if items[i].effect == decision && (decision != adomain.Allow || items[i].Step == StepAuthority) {
			items[i].Decisive = true
			d := items[i]
			items = append([]Item{d}, slices.Delete(items, i, i+1)...)
			break
		}
	}
	return decision, items
}

func (c *checklist) strictest() adomain.Decision {
	decision := adomain.Allow
	for _, it := range c.items {
		if rank(it.effect) < rank(decision) {
			decision = it.effect
		}
	}
	return decision
}
