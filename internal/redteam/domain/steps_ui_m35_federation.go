// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// federation.probe exercises the federation face, the replay store, an L3
// binding for another key, and a non-https TUF repository. It is
// harness-only: the face and the replay store need the range stack.
var FederationAttacks = []string{"forged_token", "replay", "unpinned_token", "other_key", "http_tuf"}

func init() {
	const kind = "federation.probe"
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
		if !slices.Contains(FederationAttacks, w.Attack) {
			return fmt.Errorf("attack must be one of %v", FederationAttacks)
		}
		return nil
	}
}
