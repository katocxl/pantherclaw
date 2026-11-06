// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// runtime.probe uses a simulated cloud account and an isolated stack to
// exercise the runtime gateway, discovery and cloud-command boundaries.
// It is harness-only because it creates issuers, grants and schedules.
var RuntimeAttacks = []string{"missing_proof", "other_account", "unseen_deploy", "other_instance", "stale_credential"}

func init() {
	const kind = "runtime.probe"
	StepKinds = append(StepKinds, kind)
	harnessOnlyKinds = append(harnessOnlyKinds, kind)
	kindsNeedingEx[kind] = true
	uiStepKinds[kind] = func(strict func(any) error) error {
		var w struct {
			Attack string `json:"attack"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(RuntimeAttacks, w.Attack) {
			return fmt.Errorf("attack must be one of %v", RuntimeAttacks)
		}
		return nil
	}
}
