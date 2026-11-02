// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package packbuild

import (
	"errors"
	"fmt"
	"testing"

	coapp "github.com/katocxl/pantherclaw/internal/compliance/app"
)

// TestComplianceReportErrorsThatNoRetryMends: a bad period, an unknown
// framework or a server with no store fail the pack at once; anything else
// (a database hiccup) is retried.
// Covers: F894
func TestComplianceReportErrorsThatNoRetryMends(t *testing.T) {
	for _, err := range []error{coapp.ErrBadPeriod, coapp.ErrUnknown, coapp.ErrUnavailable, fmt.Errorf("wrapped: %w", coapp.ErrBadPeriod)} {
		if !permanent(err) {
			t.Errorf("%v is retried", err)
		}
		if !errors.Is(errors.Join(errCompliance, err), errCompliance) {
			t.Errorf("%v does not fail the pack", err)
		}
	}
	for _, err := range []error{nil, errors.New("connection reset"), coapp.ErrEdition} {
		if permanent(err) {
			t.Errorf("%v fails the pack at once", err)
		}
	}
}
