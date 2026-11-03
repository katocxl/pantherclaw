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
// framework or a server with no store fail the pack at once as unavailable;
// anything else (a database hiccup) is retried.
// Covers: F894
func TestComplianceReportErrorsThatNoRetryMends(t *testing.T) {
	for _, err := range []error{coapp.ErrBadPeriod, coapp.ErrUnknown, coapp.ErrUnavailable, fmt.Errorf("wrapped: %w", coapp.ErrBadPeriod)} {
		got := classify(err)
		if !errors.Is(got, errCompliance) || errors.Is(got, errComplianceEdition) || !errors.Is(got, err) {
			t.Errorf("%v: %v", err, got)
		}
	}
	if classify(nil) != nil {
		t.Error("no error became one")
	}
	hiccup := errors.New("connection reset")
	if got := classify(hiccup); got != hiccup {
		t.Errorf("a passing error is not retried: %v", got)
	}
}

// TestComplianceEditionFailsThePack: an edition that no longer includes the
// framework fails the pack with EDITION_REQUIRED, never a retry (D545).
// Covers: F897
func TestComplianceEditionFailsThePack(t *testing.T) {
	for _, err := range []error{coapp.ErrEdition, fmt.Errorf("wrapped: %w", coapp.ErrEdition)} {
		got := classify(err)
		if !errors.Is(got, errComplianceEdition) || errors.Is(got, errCompliance) {
			t.Errorf("%v: %v", err, got)
		}
	}
	if CodeEditionRequired != "EDITION_REQUIRED" {
		t.Errorf("code %q", CodeEditionRequired)
	}
}
