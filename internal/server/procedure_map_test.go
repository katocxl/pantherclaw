// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/entitlements"
)

// TestProcedureMapMatchesTheTables (G0 M22 D9): the map holds every procedure
// exactly once, with the permission and class the server enforces, side maps
// included.
//
// Covers: F835
func TestProcedureMapMatchesTheTables(t *testing.T) {
	got := ProcedureMap()
	if len(got) != len(procedurePermissions) {
		t.Fatalf("map has %d procedures, table has %d", len(got), len(procedurePermissions))
	}
	for proc, perm := range procedurePermissions {
		info, ok := got[proc]
		if !ok {
			t.Errorf("%s is missing", proc)
			continue
		}
		if info.Permission != string(perm) {
			t.Errorf("%s: permission %q, table has %q", proc, info.Permission, perm)
		}
		want := entitlements.ClassUnknown.String()
		if c, ok := procedureClasses[proc]; ok {
			want = c.String()
		}
		if info.Class != want {
			t.Errorf("%s: class %q, table has %q", proc, info.Class, want)
		}
	}
	for proc := range procedureClasses {
		if _, ok := got[proc]; !ok {
			t.Errorf("%s has a class but is not in the map", proc)
		}
	}
	// A procedure that only a side map classifies must come through.
	const side = "/pantherclaw.v1.ModelService/DisableModelDrafting"
	if got[side].Class != entitlements.ClassSafety.String() {
		t.Errorf("%s: class %q, want the side map's safety", side, got[side].Class)
	}
}
