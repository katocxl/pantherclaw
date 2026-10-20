// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"strings"
	"testing"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
)

// TestHR345_ConsoleReturnPaths: a sign-in may return to any clean
// same-origin console path; nothing with a scheme, host, "//", backslash,
// percent, query, fragment, dot segment or trailing slash, and nothing
// that only starts like /app.
func TestHR345_ConsoleReturnPaths(t *testing.T) {
	for p, ok := range map[string]bool{
		"/app":        true,
		"/app/agents": true,
		"/app/agents/0192f3a0-0000-7000-8000-000000000001": true,
		"/app/settings/plan-and_billing.v2~x":              true,
		"/app/":                                            false,
		"/app/agents/":                                     false,
		"/apps":                                            false,
		"/application":                                     false,
		"//app":                                            false,
		"/app//evil.example":                               false,
		"/app/../account":                                  false,
		"/app/./agents":                                    false,
		"/app/..":                                          false,
		"/app/%2F%2Fevil.example":                          false,
		"/app/%2e%2e/account":                              false,
		`/app\evil.example`:                                false,
		`/app/\evil.example`:                               false,
		"/app?next=//evil.example":                         false,
		"/app#x":                                           false,
		"/app/x y":                                         false,
		"/app/x:y":                                         false,
		"/app/x@evil.example":                              false,
		"https://evil.example/app":                         false,
		"app":                                              false,
		"":                                                 false,
		"/app/" + strings.Repeat("a", 600):                 false,
	} {
		if authnapp.ValidReturnPath(p) != ok || authnapp.ValidConsolePath(p) != ok {
			t.Errorf("ValidReturnPath(%q) = %v, ValidConsolePath = %v, want %v", p, authnapp.ValidReturnPath(p),
				authnapp.ValidConsolePath(p), ok)
		}
	}
}

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
		// The reconciliation page (G0 M7 design decision 3).
		"/reconciliations/0192f3a0-0000-7000-8000-000000000001":         true,
		"/reconciliations/0192f3a0-0000-7000-8000-000000000001/release": false,
		"/reconciliations":   false,
		"/reconciliations/x": false,
	} {
		if authnapp.ValidReturnPath(p) != ok {
			t.Errorf("ValidReturnPath(%q) = %v, want %v", p, !ok, ok)
		}
	}
}
