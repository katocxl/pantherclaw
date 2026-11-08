// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// The range step for M36 reach (G0 M36; RT-235..RT-239). Harness-only:
// each attack is one of ReachAttacks, and the driver reports REFUSED when
// the product stops it.
//
//   - reach.probe {attack}
const stepReachProbe = "reach.probe"

// ReachAttacks are the reach.probe attacks.
var ReachAttacks = []string{"forged_trace", "otlp_exfil", "fatigue_stamp", "deputy_widen", "push_leak"}

func init() {
	StepKinds = append(StepKinds, stepReachProbe)
	harnessOnlyKinds = append(harnessOnlyKinds, stepReachProbe)
	kindsNeedingEx[stepReachProbe] = true
	uiStepKinds[stepReachProbe] = func(strict func(any) error) error {
		var w struct {
			Attack string `json:"attack"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(ReachAttacks, w.Attack) {
			return fmt.Errorf("attack must be one of %v", ReachAttacks)
		}
		return nil
	}
}
