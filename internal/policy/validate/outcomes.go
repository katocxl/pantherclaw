// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package validate

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"math"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// OutcomeChange is one sample whose policy outcome differs between two
// versions (F198). Decisions are the policy engine's alone: grants,
// budgets, facts and holds are not part of it.
type OutcomeChange struct {
	Operation      string           `json:"operation"`
	Example        jsontext.Value   `json:"example"`
	BeforeDecision adomain.Decision `json:"before_decision"`
	BeforeReason   string           `json:"before_reason,omitzero"`
	AfterDecision  adomain.Decision `json:"after_decision"`
	AfterReason    string           `json:"after_reason,omitzero"`
	Category       replay.Category  `json:"category"`
}

// OutcomeDiff evaluates base and next on the same samples (those of both
// bundles' literals and limits) and returns every sample whose decision or
// decisive reason changes, categorized as D5 does (a newly allowed sample
// is expanded exposure). A nil base is no policy. It is sample-based
// (R-25): an empty result does not prove the versions decide alike.
func (v *Validator) OutcomeDiff(ctx context.Context, org ids.OrgID, base, next *pdomain.Bundle) ([]OutcomeChange, error) {
	in, err := v.read(ctx, org)
	if err != nil {
		return nil, err
	}
	engine := &papp.Engine{Limits: v.limits, Facts: in.catalog, Subjects: in.subjects}
	compile := func(b *pdomain.Bundle) (*papp.Compiled, error) {
		if b == nil || len(b.Rules) == 0 {
			return nil, nil //nolint:nilnil // no policy
		}
		c, err := engine.Compile(b, in.defs)
		if err != nil {
			return nil, fmt.Errorf("validate: compile %s@%d: %w", b.ID, b.Version, err)
		}
		return c, nil
	}
	before, err := compile(base)
	if err != nil {
		return nil, err
	}
	after, err := compile(next)
	if err != nil {
		return nil, err
	}
	var rules []pdomain.Rule
	for _, b := range []*pdomain.Bundle{base, next} {
		if b != nil {
			rules = append(rules, b.Rules...)
		}
	}
	ds, facts := operations(rules, in)
	g := &generator{lit: collect(rules), catalog: in.catalog, now: v.now(), budget: math.MaxUint64}
	var out []OutcomeChange
	for _, d := range ds {
		for _, s := range g.samples(d, facts[d.Digest]) {
			bd, br, okB := decide(ctx, before, s)
			ad, ar, okA := decide(ctx, after, s)
			if !okB || !okA {
				continue
			}
			if cat := replay.Classify(bd, ad, br, ar); cat != replay.Unchanged {
				out = append(out, OutcomeChange{
					Operation: d.Operation, Example: s.example(), BeforeDecision: bd, BeforeReason: br, AfterDecision: ad, AfterReason: ar, Category: cat,
				})
			}
		}
	}
	return out, nil
}

// decide is the policy's decision and decisive reason on a sample: ALLOW
// with no reason when nothing restricts it (or there is no policy).
func decide(ctx context.Context, c *papp.Compiled, s sample) (adomain.Decision, string, bool) {
	if c == nil {
		return adomain.Allow, "", true
	}
	out, err := c.Evaluate(ctx, s.def, s.action, s.in)
	if err != nil {
		return "", "", false
	}
	reason := ""
	if it, ok := out.Decisive(); ok {
		reason = it.Reason
	}
	switch out.Verdict {
	case pdomain.VerdictPass:
		return adomain.Allow, reason, true
	case pdomain.VerdictConstrain:
		return adomain.AllowWithObligations, reason, true
	case pdomain.VerdictRequireStepUp:
		return adomain.RequireStepUp, reason, true
	case pdomain.VerdictRequireApproval:
		return adomain.RequireApproval, reason, true
	case pdomain.VerdictDeny:
		return adomain.Deny, reason, true
	case pdomain.VerdictCannotAuthorize:
	}
	return adomain.CannotAuthorize, reason, true
}
