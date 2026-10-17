// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"errors"
	"testing"

	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// TestM14_PatternRefusalFailsClosed: a GitHub App credential is refused
// for a package that declares a credential pattern and for one that cannot
// be read (it cannot be checked); a readable package without a pattern
// takes it (G0 M14 D85).
func TestM14_PatternRefusalFailsClosed(t *testing.T) {
	if err := patternRefusal(mockpayments.Package); err != nil {
		t.Fatalf("no pattern: %v", err)
	}
	patterned := bytes.Replace(mockpayments.Package, []byte("    dispatch:\n      http:\n        method: POST\n"),
		[]byte("    dispatch:\n      credential_pattern: '^sk_[a-z]+$'\n      http:\n        method: POST\n"), 1)
	if err := patternRefusal(patterned); !errors.Is(err, ErrPatternNeedsStatic) {
		t.Fatalf("a pattern: %v", err)
	}
	if err := patternRefusal([]byte("not: [a package")); !errors.Is(err, ErrPatternUnchecked) {
		t.Fatalf("unreadable: %v", err)
	}
}
