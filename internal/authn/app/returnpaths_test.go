// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
)

// TestHR152_SignInMayReturnToTheApprovalPages (G0 M5 part 2): a sign-in may
// return to /approvals and to one request's page, matched exactly; nothing
// else under /approvals.
func TestHR152_SignInMayReturnToTheApprovalPages(t *testing.T) {
	for p, ok := range map[string]bool{
		"/approvals": true,
		"/approvals/0192f3a0-0000-7000-8000-000000000001":         true,
		"/approvals/0192F3A0-0000-7000-8000-000000000001":         false,
		"/approvals/0192f3a0-0000-7000-8000-000000000001/approve": false,
		"/approvals/../account":                                   false,
		"/approvals/x":                                            false,
		"/approvals/":                                             false,
		"//approvals":                                             false,
		"/account":                                                true,
	} {
		if authnapp.ValidReturnPath(p) != ok {
			t.Errorf("ValidReturnPath(%q) = %v, want %v", p, !ok, ok)
		}
	}
}
