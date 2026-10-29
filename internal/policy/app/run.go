// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Policy rules see the run an action belongs to as `run` (G0 M8 C4, the
// coordinator's decision of 2026-10-13): its id and its agent's id. Both
// come from the server's own run record, found by the run the action names
// and checked against the agent's verified identity, never from the
// request or the ActionIR, so an agent cannot claim another agent's run.
// Without a run both are "".
//
// `run.consequences_pending` and `run.consequences_unconfirmed` (G0 M17
// D103) count the run's actions whose predicted consequences are still
// being verified, and those with a consequence UNCONFIRMED or
// NOT_VERIFIABLE; both are 0 without a run.
const runType = "pc.Run"

// Run is the server's record of the action's run.
type Run struct {
	ID, AgentID                                  string
	ConsequencesPending, ConsequencesUnconfirmed int
}

// RunSchema is the typed shape of `run`.
var RunSchema = celenv.Schema{runType: {Name: runType, Fields: map[string]celenv.Field{
	"id":                       {Type: cel.StringType},
	"agent_id":                 {Type: cel.StringType},
	"consequences_pending":     {Type: cel.IntType},
	"consequences_unconfirmed": {Type: cel.IntType},
}}}

// RunVariable declares `run`.
var RunVariable = celenv.Variable{Name: "run", Type: types.NewObjectType(runType)}

// RunRecord builds the runtime value of `run`; nil is no run.
func RunRecord(r *Run) *celenv.Record {
	fields := map[string]ref.Val{
		"id": types.String(""), "agent_id": types.String(""),
		"consequences_pending": types.Int(0), "consequences_unconfirmed": types.Int(0),
	}
	if r != nil {
		fields["id"], fields["agent_id"] = types.String(r.ID), types.String(r.AgentID)
		fields["consequences_pending"] = types.Int(r.ConsequencesPending)
		fields["consequences_unconfirmed"] = types.Int(r.ConsequencesUnconfirmed)
	}
	return &celenv.Record{TypeName: runType, Fields: fields}
}

// ReadsRunConsequences reports whether a rule of b may read the run's
// consequence counts, so the Authority reads them only then (D103). It
// scans every CEL expression the compiler compiles (celExpressions, D141)
// and errs toward reading: any mention of either field counts.
func ReadsRunConsequences(b *domain.Bundle) bool {
	if b == nil {
		return false
	}
	for i := range b.Rules {
		for _, x := range celExpressions(&b.Rules[i]) {
			if strings.Contains(x, "consequences_pending") || strings.Contains(x, "consequences_unconfirmed") {
				return true
			}
		}
	}
	return false
}

// celExpressions are every CEL expression of r the compiler compiles; the
// first is the rule's condition. A new CEL site belongs here, so that
// ReadsRunConsequences sees it as soon as it is compiled.
func celExpressions(r *domain.Rule) []string { return []string{r.When} }
