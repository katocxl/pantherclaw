// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"slices"
	"strings"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// maxPayloadFindings caps the findings one decision records.
const maxPayloadFindings = 16

// payloadFindings returns the request's findings sorted, unique and capped.
func payloadFindings(in []PayloadFinding) []PayloadFinding {
	out := slices.Clone(in)
	slices.SortFunc(out, func(a, b PayloadFinding) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return strings.Compare(a.Location, b.Location)
	})
	out = slices.Compact(out)
	if len(out) > maxPayloadFindings {
		out = out[:maxPayloadFindings]
	}
	return out
}

// payloadRequirement adds the approval a payload finding calls for (HR-225,
// G0 M12 D8): a person with the approver role must approve an action whose
// payload holds a credential-shaped value. No policy or grant can lift it,
// and findings only ever add it: nothing here lowers a decision or removes
// another requirement.
func (s *state) payloadRequirement() {
	if len(s.ev.PayloadFindings) == 0 {
		return
	}
	a := pdomain.ApprovalRequirement{Role: string(td.RoleApprover), Count: 1}
	f := s.ev.PayloadFindings[0]
	s.ev.Approvals = append(s.ev.Approvals, a)
	s.cl.add(StepRequirements, adomain.RequireApproval, ReasonSecretInPayload,
		"approval by "+a.Role+" is required: the payload holds what looks like a credential ("+f.Kind+" at "+f.Location+")", "payload")
	s.ev.Requirements = append(s.ev.Requirements, input(&a, nil, apdomain.Source{Level: "payload", Reason: ReasonSecretInPayload}))
}

func (s *state) payloadDisplayed() []apdomain.PayloadFindingInput {
	var out []apdomain.PayloadFindingInput
	for _, f := range s.ev.PayloadFindings {
		out = append(out, apdomain.PayloadFindingInput{Kind: f.Kind, Location: f.Location})
	}
	return out
}
