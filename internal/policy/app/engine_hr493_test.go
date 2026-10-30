// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/policy/domain"
)

// TestHR493_CompiledConditionsAreContentAddressed (ADR-0040, compiled
// policy conditions): the cache is keyed by the definition's digest, so a
// changed definition is compiled afresh and never served the conditions
// compiled for its earlier content; the same content reuses its entry.
// Covers: HR-493
func TestHR493_CompiledConditionsAreContentAddressed(t *testing.T) {
	f := newFixture(t)
	c, err := f.compile(refundRule("f", domain.Forbid, `action.params.amount > money("1.00", "USD")`))
	if err != nil {
		t.Fatal(err)
	}
	d := f.def("payments.refund.create")
	c.forDefinition(d)
	n := len(c.byDef)
	c.forDefinition(d)
	if len(c.byDef) != n {
		t.Fatalf("the same digest compiled again: %d entries, want %d", len(c.byDef), n)
	}
	changed := *d
	changed.Digest = "sha256:" + d.Digest + "-changed"
	c.forDefinition(&changed)
	if len(c.byDef) != n+1 {
		t.Fatalf("a changed definition reused an entry: %d entries, want %d", len(c.byDef), n+1)
	}
	if _, ok := c.byDef[changed.Digest]; !ok {
		t.Fatal("the changed definition has no entry of its own")
	}
}
