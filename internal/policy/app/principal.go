// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"

	"github.com/katocxl/pantherclaw/internal/platform/celenv"
)

// Policy rules see the people behind an action's run as `principal` (G0
// M16 D82, founder decision F8): `principal.risk` is an open identity-risk
// signal about the run's represented person or its launcher when that is
// a person, from the pc.identity.risk facts the Shared Signals receiver
// writes. `open` is true while such a fact is at most 24 hours old; `event`
// and `at` (Unix seconds) are the newest one's. A missing or older fact is
// no risk: risk can only make a rule match, which only restricts, so its
// absence never fails a decision (HR-441).
const (
	principalType = "pc.Principal"
	riskType      = "pc.Risk"
)

// Risk is an open identity-risk signal; nil is none.
type Risk struct {
	Event string
	At    int64
}

// PrincipalSchema is the typed shape of `principal`.
var PrincipalSchema = celenv.Schema{
	principalType: {Name: principalType, Fields: map[string]celenv.Field{
		"risk": {Type: types.NewObjectType(riskType)},
	}},
	riskType: {Name: riskType, Fields: map[string]celenv.Field{
		"open":  {Type: cel.BoolType},
		"event": {Type: cel.StringType},
		"at":    {Type: cel.IntType},
	}},
}

// PrincipalVariable declares `principal`.
var PrincipalVariable = celenv.Variable{Name: "principal", Type: types.NewObjectType(principalType)}

// PrincipalRecord builds the runtime value of `principal`.
func PrincipalRecord(r *Risk) *celenv.Record {
	risk := map[string]ref.Val{"open": types.False, "event": types.String(""), "at": types.Int(0)}
	if r != nil {
		risk["open"], risk["event"], risk["at"] = types.True, types.String(r.Event), types.Int(r.At)
	}
	return &celenv.Record{TypeName: principalType, Fields: map[string]ref.Val{
		"risk": &celenv.Record{TypeName: riskType, Fields: risk},
	}}
}

// UsesPrincipal reports whether a rule that covers the operation (in any
// environment) reads `principal`, so the pipeline reads identity-risk facts
// only for a policy that can use them.
func (c *Compiled) UsesPrincipal(operation string) bool {
	for i := range c.Bundle.Rules {
		r := &c.Bundle.Rules[i]
		if r.CoversOperation(operation) && strings.Contains(r.When, "principal") {
			return true
		}
	}
	return false
}
