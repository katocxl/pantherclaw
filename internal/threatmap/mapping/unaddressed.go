// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

// UnaddressedEntry is a technique inside an agent platform's reach for which
// PantherClaw ships no control (G0 M28 D714, founder FQ2 A): shown red in
// the "No PantherClaw control yet" list with its reason, every lane
// NONE_SHIPPED, fix NONE.
type UnaddressedEntry struct {
	ID string `json:"id"`
	// Why is one line citing the id.
	Why string `json:"why"`
}

// Unaddressed is every technique PantherClaw ships no control for yet.
var Unaddressed = []UnaddressedEntry{}
