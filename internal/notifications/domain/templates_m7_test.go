// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/notifications/domain"
)

// TestHR192_UnknownOutcomeNoticesLinkOnlyToTheirReconciliation (G0 M7
// slice A11): the notices of an unknown outcome link to its reconciliation
// page, where a person releases it; only a canonical id fills the link, and
// a template may not link a reconciliation through another placeholder.
func TestHR192_UnknownOutcomeNoticesLinkOnlyToTheirReconciliation(t *testing.T) {
	for _, typ := range []string{"reconciliation.waiting", "reconciliation.escalated", "transaction.reconciliation_released"} {
		params := map[string]string{
			"operation": "payments.refund.create", "agent": "019a0000-0000-7000-8000-000000000001",
			"reconciliation": "019a0000-0000-7000-8000-000000000003",
		}
		r, err := domain.Render(typ, params)
		if err != nil || r.Link != "/reconciliations/019a0000-0000-7000-8000-000000000003" || r.Severity != domain.Warning {
			t.Fatalf("%s: %+v, %v", typ, r, err)
		}
		for _, bad := range []string{"../approvals", "https://evil.example", "019A0000-0000-7000-8000-000000000003", "x"} {
			params["reconciliation"] = bad
			if _, err := domain.Render(typ, params); !errors.Is(err, domain.ErrBadParams) {
				t.Errorf("%s with reconciliation %q: %v", typ, bad, err)
			}
		}
	}
}
