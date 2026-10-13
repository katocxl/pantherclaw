// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package evidencerpc

import (
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// decisionProto maps a decision by its name (DECISION_<decision>); an
// empty or unknown one is unspecified.
func decisionProto(d adomain.Decision) pantherclawv1.Decision {
	if d == "" {
		return pantherclawv1.Decision_DECISION_UNSPECIFIED
	}
	return pantherclawv1.Decision(pantherclawv1.Decision_value["DECISION_"+string(d)])
}

func checklistProto(items []pipeline.Item) []*pantherclawv1.ChecklistItem {
	out := make([]*pantherclawv1.ChecklistItem, 0, len(items))
	for _, it := range items {
		out = append(out, &pantherclawv1.ChecklistItem{
			Step: int32(it.Step), Check: it.Check, //nolint:gosec // G115: steps 1..10
			Status: pantherclawv1.ChecklistStatus(pantherclawv1.ChecklistStatus_value["CHECKLIST_STATUS_"+string(it.Status)]),
			Code:   it.Code, Detail: it.Detail, Level: it.Level, Decisive: it.Decisive,
		})
	}
	return out
}

// replayProto translates a replay. Input values reach the response only
// when the use case returned them (evidence.read_restricted).
func replayProto(r evapp.ReplayResult) *pantherclawv1.ReplayDecisionResponse {
	o := r.Outcome
	out := &pantherclawv1.ReplayDecisionResponse{
		TransactionId: o.Transaction.String(), Evaluation: int32(o.Evaluation), //nolint:gosec // G115: ≤ 64
		Policy: o.Policy, Proposed: o.Proposed, Complete: o.Complete,
		Decision: decisionProto(o.Decision), Reason: o.Reason, BasisDigest: o.BasisDigest, Checklist: checklistProto(o.Checklist),
		OriginalDecision: decisionProto(o.Original.Decision), OriginalReason: o.Original.Reason,
		OriginalBasisDigest: o.Original.BasisDigest, OriginalChecklist: checklistProto(o.Original.Checklist),
		OriginalOmitted: int32(o.Original.Omitted), //nolint:gosec // G115: a checklist's length
		SameDecision:    o.SameDecision, Reproduced: o.Reproduced, Notes: o.Notes,
		Inputs: r.Inputs, InputsWithheld: r.InputsWithheld,
	}
	for _, l := range o.Incomplete {
		out.Incomplete = append(out.Incomplete, &pantherclawv1.ReplayLimitation{
			Code: l.Code, Step: int32(l.Step), Detail: l.Detail, //nolint:gosec // G115: steps 1..10
		})
	}
	for _, d := range o.Differences {
		out.Differences = append(out.Differences, &pantherclawv1.ReplayDifference{
			Step: int32(d.Step), Check: d.Check, Original: checklistProto(d.Original), Replayed: checklistProto(d.Replayed), //nolint:gosec // G115
			Rules: d.Rules, Inputs: d.Inputs,
		})
	}
	return out
}
