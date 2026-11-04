// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package auditkind names every audit kind the core writes (HR-664,
// T-286). Each kind is one constant, in the file of its prefix, named by
// CamelCasing the kind ("policy.rule_changed" is PolicyRuleChanged); a
// misspelt kind keeps its spelling. Every audit write in the core uses one
// of these constants, and a test refuses a string literal at an audit
// writer's call site, so a kind can't be misspelt in one place.
//
// To add a kind, add its constant to the prefix's file and its name to
// all. The package imports nothing outside the standard library.
package auditkind

import "slices"

// All returns every audit kind the core writes, sorted. The slice is a
// copy; changing it changes nothing here.
func All() []string {
	out := slices.Clone(all)
	slices.Sort(out)
	return out
}
