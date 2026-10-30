// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package fanout

import (
	"errors"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, ok := range []string{"pc_wait", "pc_containment", "pc_a1"} {
		if err := Validate(ok, "org:id"); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	// Names are spliced into LISTEN, so only safe identifiers pass.
	for _, bad := range []string{"", "wait", "pc_", "PC_wait", "pc_wait; DROP TABLE x", `pc_"x"`, "pc_" + strings.Repeat("a", 61)} {
		if err := Validate(bad, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := Validate("pc_wait", strings.Repeat("x", MaxPayload+1)); !errors.Is(err, ErrInvalid) {
		t.Error("oversized payload accepted")
	}
}
