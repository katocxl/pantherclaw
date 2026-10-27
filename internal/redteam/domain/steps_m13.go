// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// M13's range step (G0 M13 D8, D27; RT-065):
//
//   - api.flood {procedure, as, calls}: one credential of the org's person
//     as calls procedure calls times in a row through the API's
//     authentication layer with the server's default API limits. ALLOW
//     when every call got through, REFUSED (RATE_LIMITED) when the limits
//     refused some; the detail says how many got through.
type apiFloodWith struct {
	Procedure string `json:"procedure"`
	As        string `json:"as"`
	Calls     int    `json:"calls"`
}

// floodRoles are the roles an api.flood step may call as: the person.rpc
// roles and the two that contain (responder, security_admin).
var floodRoles = append(slices.Clone(rpcRoles), "responder", "security_admin")

// MaxFloodCalls bounds an api.flood step.
const MaxFloodCalls = 20_000

var m13StepKinds = map[string]func(strict func(any) error) error{
	"api.flood": func(strict func(any) error) error {
		var w apiFloodWith
		if err := strict(&w); err != nil {
			return err
		}
		if !procedureRE.MatchString(w.Procedure) || !slices.Contains(floodRoles, w.As) || w.Calls < 1 || w.Calls > MaxFloodCalls {
			return fmt.Errorf("procedure must be a /pantherclaw.v1.Service/Method name, as one of %v and calls 1 to %d", floodRoles, MaxFloodCalls)
		}
		return nil
	},
}

func init() {
	for k := range m13StepKinds {
		StepKinds = append(StepKinds, k)
		kindsNeedingEx[k] = true
	}
}
