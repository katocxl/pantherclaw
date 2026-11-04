// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"slices"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Reason code and level of a vectorstore writer hold (G0 M30 D924, HR-705).
const (
	// ReasonVectorWriteNotWriter: an upsert or delete by an agent the
	// connection does not name as a writer waits for a person.
	ReasonVectorWriteNotWriter = "VECTOR_WRITE_NOT_WRITER"
	// VectorstoreLevel is the source of the hold's requirement.
	VectorstoreLevel = "vectorstore"
)

// vectorWriterHold files the hold of a vectorstore write by a non-writer
// (step 7). It only adds a requirement; an unknown run or agent holds too
// (fail closed).
func (s *state) vectorWriterHold() {
	if s.conn == nil || s.conn.Kind != "vectorstore" || s.def == nil || s.def.Dispatch == nil || s.def.Dispatch.SQL == nil {
		return
	}
	if op := s.def.Dispatch.SQL.Operation; op != defs.VectorUpsert && op != defs.VectorDelete {
		return
	}
	if s.run != nil && slices.Contains(s.conn.Writers, s.run.AgentID) {
		return
	}
	a := pdomain.ApprovalRequirement{Role: string(td.RoleApprover), Count: 1}
	s.ev.Approvals = append(s.ev.Approvals, a)
	s.cl.add(StepRequirements, adomain.RequireApproval, ReasonVectorWriteNotWriter,
		"approval by "+a.Role+" is required: the agent is not one of this retrieval index's writers", VectorstoreLevel)
	s.ev.Requirements = append(s.ev.Requirements, input(&a, nil, apdomain.Source{Level: VectorstoreLevel, Reason: ReasonVectorWriteNotWriter}))
}
