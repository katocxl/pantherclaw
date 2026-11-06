// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// The M29 model connection range step (G0 M29 D827; RT-192..RT-197):
//
//   - model.call {attack, connection?}: the scenario's agent calls its model
//     through the model connection "anthropic" (default) or "openai" to
//     pantherclaw-sim model. call is an ordinary call (ALLOW when the
//     simulator answered). over_cap asks for more tokens than the
//     scenario's token rule has left (DENY, TOKEN_BUDGET_EXHAUSTED). secret
//     puts a credential format in the prompt (HOLD, SECRET_IN_PAYLOAD).
//     big_body sends a body over 16 MiB, server_tool asks the provider to
//     run a web search, duplicate_member names max_tokens twice: each
//     REFUSED with the gateway's code, and the simulator saw nothing.
//     cut_stream asks for a stream the simulator cuts: UNKNOWN when the
//     reservation stays HELD. Harness-only: it needs the stack's simulator
//     and database.
//
// The capability "model" is the harness's: the stack runs the fake model
// and seeds the model connections (never a customer's live range).
const stepModelCall = "model.call"

// ModelAttacks are the model.call attacks.
var ModelAttacks = []string{"call", "over_cap", "secret", "big_body", "cut_stream", "server_tool", "duplicate_member"}

// ModelConnections are the model connections a model.call may name.
var ModelConnections = []string{"", "anthropic", "openai"}

func init() {
	capabilities = append(capabilities, "model")
	StepKinds = append(StepKinds, stepModelCall)
	harnessOnlyKinds = append(harnessOnlyKinds, stepModelCall)
	kindsNeedingEx[stepModelCall] = true
	// The sandbox probes of the model route (RT-190, RT-191): the agent's
	// own key is stripped and the simulator sees only the injected one; a
	// model host no connection maps is refused.
	probes = append(probes, "model_own_key", "model_unmapped_host")
	uiStepKinds[stepModelCall] = func(strict func(any) error) error {
		var w struct {
			Attack     string `json:"attack"`
			Connection string `json:"connection,omitempty"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(ModelAttacks, w.Attack) || !slices.Contains(ModelConnections, w.Connection) {
			return fmt.Errorf("attack must be one of %v and connection one of %v", ModelAttacks, ModelConnections[1:])
		}
		return nil
	}
}
