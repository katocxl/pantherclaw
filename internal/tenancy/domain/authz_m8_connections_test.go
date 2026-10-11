// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestF354_ConnectionTestIsTheGatewayAdminsAndHumanOnly: connection.test
// (G0 M8, Contracts → Permissions) is held by those who hold
// connection.manage, the Gateway Admin, and only a person may use it.
func TestF354_ConnectionTestIsTheGatewayAdminsAndHumanOnly(t *testing.T) {
	p := domain.PermConnectionTest
	if !p.Known() || !p.HumanOnly() {
		t.Fatalf("%s: known %v, human only %v", p, p.Known(), p.HumanOnly())
	}
	if got, want := holders(p), holders(domain.PermConnectionManage); !slices.Equal(got, want) || !slices.Equal(got, []domain.RoleName{domain.RoleGatewayAdmin}) {
		t.Fatalf("%s is held by %v; connection.manage by %v", p, got, want)
	}
}
