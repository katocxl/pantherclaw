// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestEveryDeclaredPermissionIsInTheCatalog: each rpc's "// permission:"
// names a catalog permission (or public/authenticated/gateway.*), and the
// tenancy, access and service-account services never use public or gateway
// permissions.
func TestEveryDeclaredPermissionIsInTheCatalog(t *testing.T) {
	declared, err := protoperms.Declared(filepath.Join("..", "..", "..", "proto"))
	if err != nil {
		t.Fatal(err)
	}
	m2 := 0
	for proc, perm := range declared {
		p := domain.Permission(perm)
		if !p.Declarable() {
			t.Errorf("%s declares unknown permission %q", proc, perm)
		}
		for _, svc := range []string{"TenancyService", "AccessService", "ServiceAccountService"} {
			if strings.Contains(proc, "."+svc+"/") {
				m2++
				if p == domain.PermPublic || p.Gateway() {
					t.Errorf("%s must not be %s", proc, perm)
				}
				if p.HumanOnly() {
					t.Errorf("%s requires a human-only permission; service accounts could never call it", proc)
				}
			}
		}
	}
	if m2 < 40 {
		t.Fatalf("found %d M2 procedures, want ≥ 40", m2)
	}
}

// TestTheCatalogNamesEachPermissionOnce: merged permission lists keep no
// duplicate.
func TestTheCatalogNamesEachPermissionOnce(t *testing.T) {
	seen := map[domain.Permission]bool{}
	for _, p := range domain.Catalog() {
		if seen[p] {
			t.Errorf("%s is in the catalog twice", p)
		}
		seen[p] = true
	}
}
