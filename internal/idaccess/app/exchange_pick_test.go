// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR622_AnIssuerWithAPinnedTenantNeverFallsBack: the entry pinning an
// assertion's tenant is chosen; the untenanted entry serves only while no
// entry of that issuer pins a tenant, so an assertion of another tenant
// matches nothing once one does.
// Covers: F910
func TestHR622_AnIssuerWithAPinnedTenantNeverFallsBack(t *testing.T) {
	acme, open := "acme", dbq.PcOrgAssertionIssuer{ID: ids.NewV7()}
	pinned := dbq.PcOrgAssertionIssuer{ID: ids.NewV7(), Tenant: &acme}
	for name, tc := range map[string]struct {
		rows   []dbq.PcOrgAssertionIssuer
		tenant string
		want   *dbq.PcOrgAssertionIssuer
	}{
		"the pinned tenant":                   {[]dbq.PcOrgAssertionIssuer{open, pinned}, "acme", &pinned},
		"another tenant beside a pinned one":  {[]dbq.PcOrgAssertionIssuer{open, pinned}, "evil", nil},
		"no tenant beside a pinned one":       {[]dbq.PcOrgAssertionIssuer{pinned, open}, "", nil},
		"any tenant with only an open entry":  {[]dbq.PcOrgAssertionIssuer{open}, "evil", &open},
		"no tenant with only an open entry":   {[]dbq.PcOrgAssertionIssuer{open}, "", &open},
		"another tenant with only pinned one": {[]dbq.PcOrgAssertionIssuer{pinned}, "evil", nil},
	} {
		got, ok := pickIssuer(tc.rows, tc.tenant)
		if (tc.want == nil) == ok || (ok && got.ID != tc.want.ID) {
			t.Errorf("%s: %v %v", name, got.ID, ok)
		}
	}
}
