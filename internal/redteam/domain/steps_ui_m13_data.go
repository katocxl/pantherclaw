// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// The M13 data range steps (G0 M13 D22, D34; RT-068):
//
//   - operator.delete_org {}: the org's deletion starts: the org becomes
//     DELETED, as the data.delete_org job's first step makes it, before
//     any of its rows go. It does what a range never does to real state,
//     so only harness-only scenarios use it.
const stepDeleteOrg = "operator.delete_org"

func init() {
	StepKinds = append(StepKinds, stepDeleteOrg)
	harnessOnlyKinds = append(harnessOnlyKinds, stepDeleteOrg)
	uiStepKinds[stepDeleteOrg] = func(strict func(any) error) error {
		var w emptyWith
		return strict(&w)
	}
}
