// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// The range step of PantherClaw's own MCP server (G0 M27 D510; RT-163,
// RT-164):
//
//   - selfmcp.probe {attack}: a SOC agent's service account works through
//     pclaw mcp self against the stack's API. poisoned_record gives an agent
//     a name that carries an instruction and reads it with the search tool:
//     REFUSED (RECORD_STAYED_LABELED) when it came back inside the labeled
//     block with no markup left, ALLOW when it broke out. no_permission reads
//     with an account that holds no read: REFUSED with the refusal's decisive
//     code, ALLOW when any record came back. write_with_the_key sends an
//     Investigator's key straight at SaveQuery: REFUSED with the server's
//     reason, ALLOW when the write ran. Harness-only: it seeds accounts and
//     rewrites an agent's name.
const stepSelfMCPProbe = "selfmcp.probe"

// SelfMCPAttacks are the selfmcp.probe attacks.
var SelfMCPAttacks = []string{"poisoned_record", "no_permission", "write_with_the_key"}

func init() {
	StepKinds = append(StepKinds, stepSelfMCPProbe)
	harnessOnlyKinds = append(harnessOnlyKinds, stepSelfMCPProbe)
	kindsNeedingEx[stepSelfMCPProbe] = true
	uiStepKinds[stepSelfMCPProbe] = func(strict func(any) error) error {
		var w struct {
			Attack string `json:"attack"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(SelfMCPAttacks, w.Attack) {
			return fmt.Errorf("attack must be one of %v", SelfMCPAttacks)
		}
		return nil
	}
}
