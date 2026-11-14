// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// Publisher bundle attacks (G0 M37; RT-240..RT-244). Harness-only: the
// driver pins a key and installs a bundle in the scenario's org.
//
//   - executable: a bundle whose item is a script. REFUSED (BUNDLE_EXECUTABLE).
//   - stolen_key: a bundle signed by a key the org did not pin. REFUSED
//     (PUBLISHER_NOT_PINNED).
//   - rollback: a second install of an older version. REFUSED (ROLLBACK).
//   - namespace: an item named in another publisher's ext. namespace.
//     REFUSED (BUNDLE_NAMESPACE).
//   - spoofed_listing: a marketplace listing whose homepage is not https.
//     REFUSED (LISTING_REFUSED).
const stepBundleProbe = "bundle.probe"

// BundleAttacks are the bundle.probe attacks.
var BundleAttacks = []string{"executable", "stolen_key", "rollback", "namespace", "spoofed_listing"}

func init() {
	StepKinds = append(StepKinds, stepBundleProbe)
	harnessOnlyKinds = append(harnessOnlyKinds, stepBundleProbe)
	kindsNeedingEx[stepBundleProbe] = true
	uiStepKinds[stepBundleProbe] = func(strict func(any) error) error {
		var w struct {
			Attack string `json:"attack"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(BundleAttacks, w.Attack) {
			return fmt.Errorf("attack must be one of %v", BundleAttacks)
		}
		return nil
	}
}
