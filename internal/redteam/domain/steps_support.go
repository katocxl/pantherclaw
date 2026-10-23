// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// Support probes run the production service against the harness database.
// They are closed operations, never arbitrary SQL or caller supplied code.
func init() {
	StepKinds = append(StepKinds, "support.probe")
	kindsNeedingEx["support.probe"] = true
}

func supportStep(strict func(any) error) error {
	var w struct {
		Attack string `json:"attack"`
	}
	if err := strict(&w); err != nil {
		return err
	}
	if !slices.Contains([]string{"self_approval", "revoked_session", "unregistered_holder", "stale_key"}, w.Attack) {
		return fmt.Errorf("unknown support attack")
	}
	return nil
}
