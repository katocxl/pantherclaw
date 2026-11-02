// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// The M26 SaaS discovery range step (G0 M26 D407; RT-154):
//
//   - saas.probe {attack}: the org's admin imports a SaaS report and works
//     with the external agent it found. hostile_field imports a name that
//     reads as an instruction and an attribute no kind names, and proves
//     nothing acted on them (REFUSED, SAAS_TEXT_INERT); forged_key imports a
//     finding under another record's key; claim_external claims the agent as
//     one would an ordinary discovered one; set_owner names its owner, and
//     proves it stays DISCOVERED with no key path (ALLOW). Harness-only: it
//     seeds a person and reads the database.
const stepSaaSProbe = "saas.probe"

// SaaSAttacks are the saas.probe attacks.
var SaaSAttacks = []string{"hostile_field", "forged_key", "claim_external", "set_owner"}

func init() {
	StepKinds = append(StepKinds, stepSaaSProbe)
	harnessOnlyKinds = append(harnessOnlyKinds, stepSaaSProbe)
	kindsNeedingEx[stepSaaSProbe] = true
	uiStepKinds[stepSaaSProbe] = func(strict func(any) error) error {
		var w struct {
			Attack string `json:"attack"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(SaaSAttacks, w.Attack) {
			return fmt.Errorf("attack must be one of %v", SaaSAttacks)
		}
		return nil
	}
}
