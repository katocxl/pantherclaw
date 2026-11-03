// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// The M27 content signal range step (G0 M27 D507, D512; RT-158..RT-161):
//
//   - operator.content_mode {mode}: the org's content signal mode becomes
//     OFF, WATCHING or ACTIVE, and the step returns once the gateway runs
//     with it. It skips the step-up and the second person a person's change
//     takes, so only harness-only scenarios use it.
const stepContentMode = "operator.content_mode"

// ContentModes are the operator.content_mode modes.
var ContentModes = []string{"OFF", "WATCHING", "ACTIVE"}

func init() {
	StepKinds = append(StepKinds, stepContentMode)
	harnessOnlyKinds = append(harnessOnlyKinds, stepContentMode)
	uiStepKinds[stepContentMode] = func(strict func(any) error) error {
		var w struct {
			Mode string `json:"mode"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(ContentModes, w.Mode) {
			return fmt.Errorf("mode must be one of %v", ContentModes)
		}
		return nil
	}
}
