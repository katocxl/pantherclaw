// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/approvals/domain"
)

// TestHR034_CleanRemovesInvisibleMarks: variation selectors (both blocks)
// and the combining grapheme joiner are removed like other invisible
// characters, so untrusted text looks and compares the same in the server
// pages and the console (G0 UI D64); visible text around them stays.
func TestHR034_CleanRemovesInvisibleMarks(t *testing.T) {
	r := func(c rune) string { return string(c) }
	for in, want := range map[string]string{
		"pay" + r(0xFE0F) + "pal":           "paypal",
		"pay" + r(0xFE00) + "pal":           "paypal",
		"a" + r(0xE0100) + "b":              "ab",
		"a" + r(0xE01EF) + "b":              "ab",
		"re" + r(0x034F) + "fund":           "refund",
		r(0xFE0F) + r(0x034F):               "",
		"heart " + r(0x2764) + r(0xFE0F):    "heart " + r(0x2764),
		r(0xFDFF) + "x" + r(0xFE10):         r(0xFDFF) + "x" + r(0xFE10), // just outside the ranges
		"x" + r(0xE00FF) + "y" + r(0xE01F0): "x" + r(0xE00FF) + "y" + r(0xE01F0),
	} {
		if got := domain.Clean("test", in, 0).Text; got != want {
			t.Errorf("Clean(%+q) = %+q, want %+q", in, got, want)
		}
	}
}
