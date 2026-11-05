// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"slices"
	"strings"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	csdomain "github.com/katocxl/pantherclaw/internal/contentsignals/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The shared intel step (G0 M38 D1104; FQ38-2; HR-819, HR-822). When the
// org consumes the intel feed, an action matches when:
//
//   - its connection's upstream server matches an mcp_server indicator, by
//     the server's reported name and version or its pinned package;
//   - the tool it calls is listed with a description matching a
//     tool_description indicator;
//   - its outbound payload carries a shared injection_text match from the
//     gateway's content scan;
//   - or, for an action that is not a read, the run tree carries one from
//     an earlier result.
//
// In HOLD a match adds a person's approval (INTEL_MATCH_HOLD); in
// ALERT_ONLY it is a note. The step never refuses, lowers a decision or
// removes a requirement: it only ever adds a hold. A Reader without the
// port reads nothing, so nothing matches (consuming is off by default).

// Reason codes and level of an intel hold.
const (
	// ReasonIntelMatchHold: a shared indicator matched, held for a person.
	ReasonIntelMatchHold = "INTEL_MATCH_HOLD"
	// ReasonIntelMatchAlert notes a match in ALERT_ONLY.
	ReasonIntelMatchAlert = "INTEL_MATCH_ALERT_ONLY"
	// IntelLevel is the source of the hold's requirement.
	IntelLevel = "intel"
	// IntelModeHold and IntelModeAlertOnly are the consuming modes.
	IntelModeHold      = "HOLD"
	IntelModeAlertOnly = "ALERT_ONLY"
)

// IntelHit is one indicator an action's server or tool matched.
type IntelHit struct {
	ID   string
	Kind string
}

// IntelState is the org's consume mode and the indicators the action's
// connection and tool match.
type IntelState struct {
	Mode string
	Hits []IntelHit
}

// IntelMatches is the port the intel step reads through.
type IntelMatches interface {
	// IntelMatches returns the org's consume mode and, when it consumes,
	// the indicators the connection's upstream server and its tool match;
	// a zero connection or an empty tool matches nothing of its own.
	IntelMatches(ctx context.Context, org ids.OrgID, conn ids.UUID, tool string) (IntelState, error)
}

// intelTool is the upstream MCP tool the action's definition calls, or "".
func (s *state) intelTool() string {
	if s.def == nil || s.def.Dispatch == nil || s.def.Dispatch.MCP == nil {
		return ""
	}
	return s.def.Dispatch.MCP.Tool
}

// intel holds or notes an action that matches a shared indicator (D1104).
func (p *Pipeline) intel(ctx context.Context, s *state) {
	port, ok := p.Reader.(IntelMatches)
	if !ok {
		return
	}
	st, err := port.IntelMatches(ctx, s.req.Org, s.connID(), s.intelTool())
	if err != nil {
		s.missing(StepFacts, err, "the shared intel matches")
		return
	}
	if st.Mode != IntelModeHold && st.Mode != IntelModeAlertOnly {
		return
	}
	var why []string
	for _, h := range st.Hits {
		why = append(why, h.Kind+" indicator "+h.ID)
	}
	for _, f := range s.ev.ContentFindings {
		if id := csdomain.IntelIndicator(csdomain.Finding{Kind: f.Kind, Location: f.Location}); id != "" {
			why = append(why, "injection_text indicator "+id+" in the outbound payload")
		}
	}
	// Reads pass, as for content flags (G0 M27 D512).
	if slices.Contains(s.content.Kinds, csdomain.KindIntelInjectionText) && (s.def == nil || s.def.Access != defs.AccessRead) {
		why = append(why, "an injection_text indicator on the run tree")
	}
	if len(why) == 0 {
		return
	}
	slices.Sort(why)
	detail := "a shared indicator matched (" + strings.Join(slices.Compact(why), ", ") + "); a match is a known hash, not proof"
	if st.Mode == IntelModeAlertOnly {
		s.cl.note(StepRequirements, StatusNotApplicable, ReasonIntelMatchAlert, "an alert only: "+detail)
		return
	}
	a := pdomain.ApprovalRequirement{Role: string(td.RoleApprover), Count: 1}
	s.ev.Approvals = append(s.ev.Approvals, a)
	s.cl.add(StepRequirements, adomain.RequireApproval, ReasonIntelMatchHold, "approval by "+a.Role+" is required: "+detail, IntelLevel)
	s.ev.Requirements = append(s.ev.Requirements, input(&a, nil, apdomain.Source{Level: IntelLevel, Reason: ReasonIntelMatchHold}))
}

// withoutIntel drops the intel findings' kind: the intel step alone decides
// what they mean, by the org's intel mode, never the content signal mode.
func withoutIntel(kinds []string) []string {
	return slices.DeleteFunc(slices.Clone(kinds), func(k string) bool { return k == csdomain.KindIntelInjectionText })
}
