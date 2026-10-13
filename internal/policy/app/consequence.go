// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// A consequence is decided with the action that may cause it (G0 M8,
// HR-206, design decision 6): policy rules see it as `consequence`. For
// the action itself, consequence.present is false. A rule may forbid on
// consequence.unknown, but nothing it says makes an unknown consequence
// safe: the Authority holds it whatever the rules allow.
const consequenceType = "pc.Consequence"

// Consequence is the consequence being decided, when the action is one.
type Consequence struct {
	// Rule is the consequence rule; State PREDICTED or UNKNOWN.
	Rule, State string
	// Environments are the ones a predicted consequence reaches.
	Environments []string
}

// ConsequenceSchema is the typed shape of `consequence`.
var ConsequenceSchema = celenv.Schema{consequenceType: {Name: consequenceType, Fields: map[string]celenv.Field{
	"present":      {Type: cel.BoolType},
	"rule":         {Type: cel.StringType},
	"state":        {Type: cel.StringType},
	"unknown":      {Type: cel.BoolType},
	"environments": {Type: cel.ListType(cel.StringType)},
}}}

// ConsequenceVariable declares `consequence`.
var ConsequenceVariable = celenv.Variable{Name: "consequence", Type: types.NewObjectType(consequenceType)}

// ConsequenceRecord builds the runtime value of `consequence`; nil is the
// action itself.
func ConsequenceRecord(c *Consequence) *celenv.Record {
	fields := map[string]ref.Val{
		"present": types.False, "rule": types.String(""), "state": types.String(""), "unknown": types.False,
		"environments": types.NewStringList(types.DefaultTypeAdapter, nil),
	}
	if c != nil {
		fields["present"], fields["rule"], fields["state"] = types.True, types.String(c.Rule), types.String(c.State)
		fields["unknown"] = types.Bool(c.State == "UNKNOWN")
		fields["environments"] = types.NewStringList(types.DefaultTypeAdapter, c.Environments)
	}
	return &celenv.Record{TypeName: consequenceType, Fields: fields}
}
