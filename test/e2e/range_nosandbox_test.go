// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && !sandbox

package e2e

import (
	"errors"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// Without the sandbox build tag the driver has no sandbox: scenarios that
// require one are skipped.
const sandboxBuilt = false

type sandboxRig struct{}

func sandboxSetup(*rangeDriver) error { return errors.New("built without the sandbox tag") }

func sandboxStart(d *rangeDriver) *stack {
	d.t.Fatal("built without the sandbox tag")
	return nil
}

func sandboxProbe(*rangeDriver, domain.Step) (domain.Observation, error) {
	return domain.Observation{}, errors.New("built without the sandbox tag")
}
