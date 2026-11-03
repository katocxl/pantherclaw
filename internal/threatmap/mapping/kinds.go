// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

// KindMapping maps one behavior or content signal kind to techniques
// (G0 M28 D714): ids XOR None.
type KindMapping struct {
	ATLAS  []string `json:"atlas,omitzero"`
	ATTACK []string `json:"attack,omitzero"`
	// Why gives each id one line that cites it.
	Why map[string]string `json:"why,omitzero"`
	// None says in one line why the kind maps to no technique.
	None string `json:"none,omitzero"`
}

// Kinds maps "behavior.<KIND>" (the behavior deviation kinds) and
// "content.<kind>" (the content signal kinds, all but scan_incomplete,
// which is an owned failure) to techniques (D714).
var Kinds = map[string]KindMapping{}
