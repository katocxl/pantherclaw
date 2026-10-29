// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
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

// external asks the matching external checks (step 7, after the policy
// rules).
func (p *Pipeline) external(ctx context.Context, s *state) {
	if p.External == nil || s.def == nil || s.gAction == nil {
		return
	}
	verdicts, err := p.External.Ask(ctx, s.req.Org, s.externalInput())
	if err != nil {
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonExternalUnavailable, "the external policy checks could not be read", "")
		return
	}
	for _, v := range verdicts {
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
// own words.
func untrusted(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return "; its reasons (UNTRUSTED): " + strings.Join(reasons, " | ")
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
