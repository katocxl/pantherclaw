// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// The M31 range step and capabilities (G0 M31; RT-210..RT-214):
//
//   - package.import {file}: an Org Admin imports a package drafted by
//     pclaw package draft openapi, signed with the org's package key.
//     draft is the file as drafted (review_required still at its top):
//     REFUSED with the importer's reason (DRAFT_NOT_REVIEWED), ALLOW when
//     it was imported. reviewed is the same draft once a person removed
//     review_required: ALLOW when imported. Harness-only: it registers a
//     signing key and signs targets for the draft itself, which a person
//     never does.
//
// The capabilities are agents working through the M31 packages against
// their simulators, each credential held by the gateway: gmail.send sends
// Gmail through pc.gmail with a Google service account acting as one
// mailbox, drive.share shares Drive files through pc.google-workspace,
// and linear.issue creates Linear issues through pc.linear. Harness-only:
// on a live range they would send mail and share files for real.
const stepPackageImport = "package.import"

// PackageImportFiles are the package.import files.
var PackageImportFiles = []string{"draft", "reviewed"}

// M31 capabilities.
var m31Capabilities = []string{"gmail.send", "drive.share", "linear.issue"}

func init() {
	capabilities = append(capabilities, m31Capabilities...)
	StepKinds = append(StepKinds, stepPackageImport)
	harnessOnlyKinds = append(harnessOnlyKinds, stepPackageImport)
	kindsNeedingEx[stepPackageImport] = true
	uiStepKinds[stepPackageImport] = func(strict func(any) error) error {
		var w struct {
			File string `json:"file"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(PackageImportFiles, w.File) {
			return fmt.Errorf("file must be one of %v", PackageImportFiles)
		}
		return nil
	}
}
