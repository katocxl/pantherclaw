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
// entry of that issuer pins a tenant, in any state, so an assertion of
// another tenant matches nothing once one does.
// Covers: F910
func TestHR622_AnIssuerWithAPinnedTenantNeverFallsBack(t *testing.T) {
	acme, open := "acme", dbq.PcOrgAssertionIssuer{ID: ids.NewV7()}
	pinned := dbq.PcOrgAssertionIssuer{ID: ids.NewV7(), Tenant: &acme}
	for name, tc := range map[string]struct {
		rows      []dbq.PcOrgAssertionIssuer
		tenant    string
		elsewhere bool // a PENDING or DISABLED entry pins a tenant
		want      *dbq.PcOrgAssertionIssuer
	}{
		"the pinned tenant":                       {[]dbq.PcOrgAssertionIssuer{open, pinned}, "acme", false, &pinned},
		"another tenant beside a pinned one":      {[]dbq.PcOrgAssertionIssuer{open, pinned}, "evil", false, nil},
		"no tenant beside a pinned one":           {[]dbq.PcOrgAssertionIssuer{pinned, open}, "", false, nil},
		"any tenant with only an open entry":      {[]dbq.PcOrgAssertionIssuer{open}, "evil", false, &open},
		"no tenant with only an open entry":       {[]dbq.PcOrgAssertionIssuer{open}, "", false, &open},
		"another tenant with only a pinned one":   {[]dbq.PcOrgAssertionIssuer{pinned}, "evil", false, nil},
		"an open entry beside an inactive pinned": {[]dbq.PcOrgAssertionIssuer{open}, "", true, nil},
		"a tenant beside an inactive pinned":      {[]dbq.PcOrgAssertionIssuer{open}, "evil", true, nil},
	} {
		got, ok := pickIssuer(tc.rows, tc.tenant, tc.elsewhere)
		if (tc.want == nil) == ok || (ok && got.ID != tc.want.ID) {
			t.Errorf("%s: %v %v", name, got.ID, ok)
		}
	}
}
