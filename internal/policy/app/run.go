// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// Policy rules see the run an action belongs to as `run` (G0 M8 C4, the
// coordinator's decision of 2026-10-13): its id and its agent's id. Both
// come from the server's own run record, found by the run the action names
// and checked against the agent's verified identity, never from the
// request or the ActionIR, so an agent cannot claim another agent's run.
// Without a run both are "".
const runType = "pc.Run"

// Run is the server's record of the action's run.
type Run struct {
	ID, AgentID string
}

// RunSchema is the typed shape of `run`.
var RunSchema = celenv.Schema{runType: {Name: runType, Fields: map[string]celenv.Field{
	"id":       {Type: cel.StringType},
	"agent_id": {Type: cel.StringType},
}}}

// RunVariable declares `run`.
var RunVariable = celenv.Variable{Name: "run", Type: types.NewObjectType(runType)}

// RunRecord builds the runtime value of `run`; nil is no run.
func RunRecord(r *Run) *celenv.Record {
	fields := map[string]ref.Val{"id": types.String(""), "agent_id": types.String("")}
	if r != nil {
		fields["id"], fields["agent_id"] = types.String(r.ID), types.String(r.AgentID)
	}
	return &celenv.Record{TypeName: runType, Fields: fields}
}
