// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func TestM35_FederationManagementRequiresAPerson(t *testing.T) {
	tr := newTree()
	binding := bind(domain.RoleOrgAdmin, domain.ScopeOrg, tr.org.UUID())
	if _, err := domain.CheckBindable(domain.RoleOrgAdmin, domain.KindServiceAccount, domain.ScopeOrg); err != nil {
		t.Fatalf("Org Admin must remain bindable to service accounts: %v", err)
	}
	if !user(tr.org, binding).CanAnywhere(domain.PermFederationManage) {
		t.Error("a person with Org Admin must be able to manage federation")
	}
	if serviceAccount(tr.org, binding).CanAnywhere(domain.PermFederationManage) {
		t.Error("a service account must not manage federation")
	}
	if domain.PermFederationManage.APIKeyScopable() {
		t.Error("federation management must not be API-key scopable")
	}
}
