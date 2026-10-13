// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"encoding/json/jsontext"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/consequences"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// Consequences (G0 M8 P1, HR-206, design decision 6): step 6 evaluates the
// consequence rules the action's package version has for its operation.
// A predicted or unknown consequence is decided with the action, under the
// same run, grant and policy: step 4 must cover it, step 7's limits and
// FORBID rules apply to it, and step 8 adds its requirements to the
// action's. An unknown consequence is at least a hold, "Consequence
// unknown", released only by the approvals its requirements need; when no
// requirement applies to it, nothing can release it and it is
// CANNOT_AUTHORIZE until the facts can be read. A DENY anywhere still wins.

// consequenceEvaluator keeps the rule programs it compiled.
var consequenceEvaluator = consequences.NewEvaluator(celenv.DefaultLimits)

// pendingConsequence is a predicted or unknown consequence that steps 4, 7
// and 8 decide with the action.
type pendingConsequence struct {
	c      *consequences.Consequence
	action gdomain.Action
	ir     actionir.ActionIR
	// unknown is the index of its CONSEQUENCE_UNKNOWN item, or -1.
	unknown int
	// requirements counts the requirements it added.
	requirements int
}

// label names the consequence in the items and sources it adds.
func (k *pendingConsequence) label() string {
	return " (consequence " + k.c.Operation + " on " + k.c.Target.ID + ")"
}

// factNames are the facts step 6 reads: those the definition and the
// policy require, then those the consequence rules need.
func factNames(reqs []fdomain.Requirement, rules []consequences.Rule) []string {
	var names []string
	for _, r := range fdomain.Merge(reqs) {
		names = append(names, r.Name)
	}
	for _, r := range rules {
		for _, n := range r.RequiresFacts {
			if !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	return names
}

// consequences evaluates the rules from the facts step 6 read.
func (s *state) consequences(ctx context.Context, recorded map[string]fdomain.Fact, reqs []fdomain.Requirement) {
	if s.pinned == nil || len(s.pinned.Consequences) == 0 {
		return
	}
	ages := map[string]time.Duration{}
	for _, r := range fdomain.Merge(reqs) {
		ages[r.Name] = r.MaxAge
	}
	s.ev.Consequences = consequenceEvaluator.Evaluate(ctx, s.pinned.Consequences, consequences.Input{
		On: s.def, TargetID: s.a.Target.ID, Facts: recorded, Ages: ages, Now: s.cont.Now,
	})
	for i := range s.ev.Consequences {
		c := &s.ev.Consequences[i]
		for _, f := range c.Used {
			if !slices.ContainsFunc(s.used, func(u fdomain.Fact) bool { return u.Name == f.Name }) {
				s.used = append(s.used, f)
			}
		}
		k := pendingConsequence{c: c, unknown: -1}
		switch {
		case c.Err != nil:
			s.cl.add(StepFacts, adomain.CannotAuthorize, consequences.ReasonEvaluation,
				"consequence rule "+c.Rule+" cannot be evaluated: "+c.Err.Error(), "")
			continue
		case c.State == consequences.Unknown:
			k.unknown = len(s.cl.items)
			s.cl.add(StepRequirements, adomain.RequireApproval, consequences.ReasonUnknown,
				"Consequence unknown: "+c.Operation+" on "+c.Target.ID+" ("+c.Rule+"): "+strings.Join(c.Unknown, "; "), "")
		case c.State == consequences.Predicted:
			s.cl.note(StepFacts, StatusAnnotated, consequences.ReasonPredicted, predicted(c))
		default:
			continue
		}
		k.action, k.ir = s.consequenceAction(c)
		s.pending = append(s.pending, k)
	}
}

// predicted describes a predicted consequence.
func predicted(c *consequences.Consequence) string {
	out := c.Operation + " on " + c.Target.ID
	if len(c.Environments) > 0 {
		out += " to " + strings.Join(c.Environments, ", ")
	}
	return out + " (" + c.Rule + ")"
}

// consequenceAction is the consequence as an action of the same run: its
// operation, target and no params, pinned to its definition in the
// action's package version.
func (s *state) consequenceAction(c *consequences.Consequence) (gdomain.Action, actionir.ActionIR) {
	d := c.Definition
	ga := gdomain.Action{
		Operation: c.Operation, Access: d.Access, TargetType: c.Target.Type, TargetID: c.Target.ID,
		AccountDeclared: d.Target.Account != defs.PresenceNone, Params: defs.Values{}, Time: s.cont.Now,
	}
	ir := s.a
	ir.Operation, ir.Definition.Digest, ir.Target, ir.Params = c.Operation, d.Digest, c.Target, jsontext.Value(`{}`)
	ir.Route, ir.Destinations, ir.DedupeKey = "", nil, ""
	return ga, ir
}

// consequenceBoundaries runs steps 4 and 7 for each pending consequence:
// the grant must cover it, and its limits and policy rules apply.
func (p *Pipeline) consequenceBoundaries(ctx context.Context, s *state) {
	for i := range s.pending {
		k := &s.pending[i]
		if s.covered {
			for _, f := range s.chain.Coverage(k.action) {
				s.cl.add(StepAuthority, effectOf(f), f.Reason(), f.Finding.Detail+k.label(), f.Level.String())
			}
		}
		for _, f := range s.chain.Limits(k.action) {
			s.cl.add(StepBoundaries, effectOf(f), f.Reason(), f.Finding.Detail+k.label(), f.Level.String())
		}
		if s.policy == nil {
			continue
		}
		in := s.policyInput()
		in.Consequence = &papp.Consequence{Rule: k.c.Rule, State: string(k.c.State), Environments: k.c.Environments}
		out, err := s.policy.Compiled.Evaluate(ctx, k.c.Definition, k.ir, in)
		if err != nil {
			s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonPolicyEvaluation, "the policy could not be evaluated"+k.label(), "")
			continue
		}
		k.requirements += s.filePolicy(out, k.label())
	}
}

// consequenceRequirements runs step 8's grant requirements for each pending
// consequence. An unknown consequence that no requirement applies to
// cannot be released by any approval: it is CANNOT_AUTHORIZE.
func (s *state) consequenceRequirements() {
	for i := range s.pending {
		k := &s.pending[i]
		for _, r := range s.chain.Requirements(k.action) {
			level := r.Level.String() + k.label()
			if a := r.Requirement.Approval; a != nil {
				s.ev.Approvals = append(s.ev.Approvals, *a)
				s.cl.add(StepRequirements, adomain.RequireApproval, r.Requirement.Reason, "approval by "+a.Role+" is required", level)
			} else {
				s.ev.StepUps = append(s.ev.StepUps, *r.Requirement.StepUp)
				s.cl.add(StepRequirements, adomain.RequireStepUp, r.Requirement.Reason, "step-up by the "+r.Requirement.StepUp.Subject+" is required", level)
			}
			s.ev.Requirements = append(s.ev.Requirements, input(r.Requirement.Approval, r.Requirement.StepUp,
				apdomain.Source{Level: level, Reason: r.Requirement.Reason}))
			k.requirements++
		}
		if k.unknown >= 0 && k.requirements == 0 {
			it := &s.cl.items[k.unknown]
			it.effect, it.Status = adomain.CannotAuthorize, StatusMissing
			it.Detail += "; no requirement applies to it, so no approval can release it"
		}
	}
}

// displayed are the predicted and unknown consequences an approver sees
// (G0 M8, F158).
func (s *state) displayed() []apdomain.ConsequenceInput {
	var out []apdomain.ConsequenceInput
	for _, k := range s.pending {
		c := k.c
		out = append(out, apdomain.ConsequenceInput{
			Rule: c.Rule, Operation: c.Operation, State: string(c.State), Target: c.Target, Environments: c.Environments,
			Unknown: c.Unknown, Facts: c.Used,
		})
	}
	return out
}

// WouldUnknown is the first unknown consequence of a monitor-mode permit
// and what an enforce-mode route would have decided about the action
// (G0 M8, HR-206 with HR-184, founder decision 2026-10-13): monitor mode
// stays observe-only, so the action is still dispatched, but its decision
// and receipt say "HOLD: consequence unknown" (or the stricter decision
// the same reasons give), and a security notification goes out. ok is
// false for an enforce-mode evaluation, one whose identity or containment
// failed, and one without an unknown consequence.
func (e *Evaluation) WouldUnknown() (would string, c *consequences.Consequence, ok bool) {
	if !e.MonitorPermit() {
		return "", nil, false
	}
	i := slices.IndexFunc(e.Consequences, func(c consequences.Consequence) bool { return c.State == consequences.Unknown && c.Err == nil })
	if i < 0 {
		return "", nil, false
	}
	would = "HOLD"
	if e.Decision == adomain.Deny || e.Decision == adomain.CannotAuthorize {
		would = string(e.Decision)
	}
	return would + ": consequence unknown", &e.Consequences[i], true
}
