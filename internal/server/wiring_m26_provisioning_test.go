// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/extension"
)

// Covers: F918. An extension audit kind names one of the three extensions
// and nothing else (D405, D88).
func TestExtensionAuditKinds(t *testing.T) {
	for _, k := range []string{"billing.subscription.ended", "scim.user.created", "saml.assertion_refused"} {
		if !validExtensionKind(k) {
			t.Errorf("%q refused", k)
		}
	}
	for _, k := range []string{
		"", "billing", "billing.", "scim.", "saml..x", "scim.User", "access.role_bound", "authn.login", "xscim.user",
		"scim.1x", "saml.a b", "scim.\n", "billing." + strings.Repeat("a", 64),
	} {
		if validExtensionKind(k) {
			t.Errorf("%q allowed", k)
		}
	}
	for _, p := range extension.AuditKindPrefixes {
		if !validExtensionKind(p + "x") {
			t.Errorf("prefix %q is not accepted", p)
		}
	}
}
