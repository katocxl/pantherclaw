// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// The M13 data range steps (G0 M13 D22, D34; RT-068, RT-069):
//
//   - operator.delete_org {}: the org's deletion starts: the org becomes
//     DELETED, as the data.delete_org job's first step makes it, before
//     any of its rows go. It does what a range never does to real state,
//     so only harness-only scenarios use it.
//   - data.probe {attack}: the org's admin works with a tenant export the
//     export job built with the server's own keys. own_export downloads
//     the org's export and verifies it offline; other_org asks for another
//     org's export by its id; expired_export asks for a part after the
//     export expired; tampered_part verifies a part changed after the
//     download. ALLOW when the download (and its offline check) succeeded,
//     REFUSED otherwise (the reason says why). Harness-only: it seeds a
//     second org and moves the export's clock.
const (
	stepDeleteOrg = "operator.delete_org"
	stepDataProbe = "data.probe"
)

// DataAttacks are the data.probe attacks.
var DataAttacks = []string{"own_export", "other_org", "expired_export", "tampered_part"}

func init() {
	StepKinds = append(StepKinds, stepDeleteOrg, stepDataProbe)
	harnessOnlyKinds = append(harnessOnlyKinds, stepDeleteOrg, stepDataProbe)
	kindsNeedingEx[stepDataProbe] = true
	uiStepKinds[stepDeleteOrg] = func(strict func(any) error) error {
		var w emptyWith
		return strict(&w)
	}
	uiStepKinds[stepDataProbe] = func(strict func(any) error) error {
		var w struct {
			Attack string `json:"attack"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(DataAttacks, w.Attack) {
			return fmt.Errorf("attack must be one of %v", DataAttacks)
		}
		return nil
	}
}
