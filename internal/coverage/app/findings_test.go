// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestF048_ASubjectIsCutAtACharacterBoundary: a finding's subject, built
// from an untrusted app slug, is at most 256 bytes and stays valid UTF-8.
func TestF048_ASubjectIsCutAtACharacterBoundary(t *testing.T) {
	for _, s := range []string{"GitHub App ci", strings.Repeat("é", 200), "x" + strings.Repeat("😀", 100)} {
		got := truncate(s, 256)
		if len(got) > 256 || !utf8.ValidString(got) || !strings.HasPrefix(s, got) || (len(s) <= 256 && got != s) {
			t.Errorf("truncate(%d bytes) = %d bytes, valid %v", len(s), len(got), utf8.ValidString(got))
		}
	}
}
