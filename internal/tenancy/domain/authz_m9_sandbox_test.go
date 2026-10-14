// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestM9_SandboxRunIsHeldByOwnersAndDevelopers: sandbox.run (G0 M9 track
// B) is in the catalog and held by exactly the Agent Owner and Developer
// roles. A service account may hold it (the CI path, design decision 9):
// the instance's admission still needs a person or an L2 policy.
func TestM9_SandboxRunIsHeldByOwnersAndDevelopers(t *testing.T) {
	p := domain.PermSandboxRun
	if !p.Known() || !p.Declarable() || p.HumanOnly() {
		t.Fatalf("%s: known %v, declarable %v, human only %v", p, p.Known(), p.Declarable(), p.HumanOnly())
	}
	want := []domain.RoleName{domain.RoleAgentOwner, domain.RoleDeveloper}
	slices.Sort(want)
	if got := holders(p); !slices.Equal(got, want) {
		t.Fatalf("%s is held by %v, want %v", p, got, want)
	}
}
