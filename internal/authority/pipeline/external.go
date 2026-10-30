// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// External policy checks (G0 M16 D81, founder decision F7; HR-436..440).
// After the policy rules, every ACTIVE check whose operations match the
// action is asked about it. A check can only restrict:
//
//   - "deny" is DENY EXTERNAL_POLICY_DENY;
//   - "hold" is REQUIRE_APPROVAL EXTERNAL_POLICY_HOLD, approved by an
//     approver;
//   - "allow" is a passed checklist item and nothing more: it never lifts a
//     DENY, a hold or a missing fact that any other step found (HR-436);
//   - no answer in time, a non-2xx status, bad JSON, a missing result or
//     too many calls in flight is CANNOT_AUTHORIZE
//     EXTERNAL_CHECK_UNAVAILABLE (HR-437).
//
// A check's reasons are UNTRUSTED: they are kept in the item's detail,
// which people see and agents never do (HR-400, HR-440).

// External policy check reason codes.
const (
	ReasonExternalDeny        = "EXTERNAL_POLICY_DENY"
	ReasonExternalHold        = "EXTERNAL_POLICY_HOLD"
	ReasonExternalAllow       = "EXTERNAL_POLICY_ALLOW"
	ReasonExternalUnavailable = "EXTERNAL_CHECK_UNAVAILABLE"
	// ReasonExternalNotEvaluated is what replay and simulation report for
	// a decision an external check took part in: they never call one.
	ReasonExternalNotEvaluated = "EXTERNAL_CHECK_NOT_EVALUATED"
)

// external files the matching external checks (step 7, after the policy
// rules): pass 1 lists them with their input for the caller to ask, and
// adds CANNOT_AUTHORIZE until they answer; pass 2 files their answers.
func (p *Pipeline) external(ctx context.Context, s *state) {
	if p.External == nil || s.def == nil || s.gAction == nil {
		return
	}
	targets, err := p.External.Matching(ctx, s.req.Org, s.a.Operation)
	if err != nil {
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonExternalUnavailable, "the external policy checks could not be read", "")
		return
	}
	round, answered := ctx.Value(externalRoundKey{}).(externalRound)
	answered = answered && round.org == s.req.Org
	if len(targets) == 0 {
		if answered && len(round.calls) > 0 {
			s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonExternalUnavailable, "the external checks changed between the two passes", "")
		}
		return
	}
	in := s.externalInput()
	digest := InputDigest(in)
	if p.SimulateExternal {
		for _, t := range targets {
			s.cl.items = append(s.cl.items, Item{
				Step: StepBoundaries, Check: stepChecks[StepBoundaries], Status: StatusNotEvaluated, Code: ReasonExternalNotEvaluated,
				Detail: "external check not evaluated in a simulation", Level: "external check " + t.Name, effect: adomain.Allow,
			})
		}
		return
	}
	if !answered {
		for _, t := range targets {
			s.ev.ExternalCalls = append(s.ev.ExternalCalls, ExternalCall{Check: t, Input: in, Digest: digest})
		}
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonExternalUnavailable, "the external checks have not answered", "")
		return
	}
	if !round.covers(targets, digest) {
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonExternalUnavailable,
			"the matching external checks or the action changed between the two passes", "")
		return
	}
	for _, v := range round.verdicts {
		level := "external check " + v.Check
		switch v.Decision {
		case "deny":
			s.cl.add(StepBoundaries, adomain.Deny, ReasonExternalDeny, "the external check denied the action"+untrusted(v.Reasons), level)
		case "hold":
			a := pdomain.ApprovalRequirement{Role: string(td.RoleApprover), Count: 1}
			s.ev.Approvals = append(s.ev.Approvals, a)
			s.cl.add(StepRequirements, adomain.RequireApproval, ReasonExternalHold,
				"approval by "+a.Role+" is required: the external check held the action"+untrusted(v.Reasons), level)
			s.ev.Requirements = append(s.ev.Requirements, input(&a, nil, apdomain.Source{Level: level, Reason: ReasonExternalHold}))
		case "allow":
			s.cl.items = append(s.cl.items, Item{
				Step: StepBoundaries, Check: stepChecks[StepBoundaries], Status: StatusPassed, Code: ReasonExternalAllow,
				Detail: "the external check allowed the action" + untrusted(v.Reasons), Level: level, effect: adomain.Allow,
			})
		default:
			why := v.Unavailable
			if why == "" {
				why = "NO_ANSWER"
			}
			s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonExternalUnavailable, "the external check did not answer ("+why+")", level)
		}
	}
}

// untrusted renders a check's reasons for people, marked as the endpoint's
// own words, as a JSON list: each reason is quoted, so one cannot pose as
// another or as the detail around it (HR-440).
func untrusted(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	b, err := json.Marshal(reasons)
	if err != nil {
		return ""
	}
	return "; its reasons (UNTRUSTED): " + string(b)
}

// externalInput is what the checks are asked. Every value comes from the
// Authority's own records or the parsed action; a disclosure-capable
// parameter is sent as its length only (HR-439).
func (s *state) externalInput() ExternalInput {
	in := ExternalInput{
		Operation: s.a.Operation, Access: string(s.def.Access), Target: s.a.Target, Destinations: s.a.Destinations,
		Agent: s.req.Identity.AgentID.String(), Instance: s.req.Identity.InstanceID.String(), Run: s.ev.RunID.String(),
		Mode: s.ev.Mode, Params: map[string]any{},
	}
	if s.conn != nil {
		in.DestinationClass = s.conn.DestinationClass
	}
	if s.run != nil && s.run.Principal.Kind == gdomain.PrincipalUser {
		in.RepresentedUser = s.run.Principal.String()
	}
	var raw map[string]jsontext.Value
	if err := json.Unmarshal(s.a.Params, &raw); err != nil {
		return in
	}
	for name, spec := range s.def.Params {
		v, present := raw[name]
		switch {
		case !present || !spec.Material:
			continue
		case spec.Disclosure || spec.Type == defs.TypeContent || spec.Type == defs.TypeCommand:
			// What the action sends or runs: its length only.
			in.Params[name] = map[string]any{"bytes": len(s.vals[name].Disclosed())}
		default:
			in.Params[name] = v
		}
	}
	return in
}

// externalRound is pass 1's calls and their answers, carried to pass 2.
type externalRound struct {
	org      ids.OrgID
	calls    []ExternalCall
	verdicts []ExternalVerdict
}

type externalRoundKey struct{}

// covers reports whether the round asked exactly targets, about the input
// with digest.
func (r externalRound) covers(targets []ExternalTarget, digest string) bool {
	if len(r.calls) != len(targets) || len(r.verdicts) != len(r.calls) {
		return false
	}
	for i, c := range r.calls {
		if c.Check.ID != targets[i].ID || c.Digest != digest || r.verdicts[i].CheckID != c.Check.ID {
			return false
		}
	}
	return true
}

// InputDigest is the SHA-256 of an external check's input, which pass 2
// compares with pass 1's.
func InputDigest(in ExternalInput) string {
	b, err := json.Marshal(in, json.Deterministic(true))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// AskExternal is the round between the passes (D96): it asks the checks
// pass 1 listed, with no snapshot open, and returns a context carrying
// their answers for pass 2, and whether pass 2 is needed. Call it outside
// every database transaction, once per decision.
func (p *Pipeline) AskExternal(ctx context.Context, org ids.OrgID, ev *Evaluation) (context.Context, bool) {
	if p.External == nil || ev == nil || len(ev.ExternalCalls) == 0 {
		return ctx, false
	}
	if _, done := ctx.Value(externalRoundKey{}).(externalRound); done {
		return ctx, false // one round per decision
	}
	verdicts := p.External.Call(ctx, org, ev.ExternalCalls)
	return context.WithValue(ctx, externalRoundKey{}, externalRound{org: org, calls: ev.ExternalCalls, verdicts: verdicts}), true
}
