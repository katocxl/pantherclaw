// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package extension

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
)

// TestHR664_CoreAuditKindsDerived: CoreAuditKinds holds every kind the core
// writes under AuditKindPrefixes and the reserved notification template,
// and nothing else; today that is the 24 kinds the hand-kept list had plus
// billing.lapse_reminder (HR-664, T-286).
func TestHR664_CoreAuditKindsDerived(t *testing.T) {
	t.Parallel()
	want := 0
	for _, k := range auditkind.All() {
		for _, p := range AuditKindPrefixes {
			if strings.HasPrefix(k, p) {
				want++
				if !CoreAuditKinds[k] {
					t.Errorf("core kind %q is missing", k)
				}
			}
		}
	}
	if !CoreAuditKinds["billing.lapse_reminder"] {
		t.Error("billing.lapse_reminder is not reserved")
	}
	if len(CoreAuditKinds) != want+1 {
		t.Errorf("CoreAuditKinds has %d kinds, want %d core plus the reserved one", len(CoreAuditKinds), want)
	}
	// The 24 kinds the list held by hand before it was derived.
	for _, k := range []string{
		"billing.comp_granted", "billing.comp_revoked", "billing.checkout_recorded", "billing.subscription_bound",
		"billing.subscription_duplicate", "billing.subscription_ended", "billing.plan_event_ignored", "billing.plan_applied",
		"scim.user_created", "scim.user_changed", "scim.user_deleted", "scim.user_deprovisioned",
		"scim.user_deprovision_refused", "scim.parts_dropped", "scim.group_created", "scim.group_changed",
		"scim.group_deleted", "scim.group_role_mapping_added", "scim.group_role_mapping_removed", "scim.token_created",
		"scim.token_activated", "scim.token_revoked", "saml.connection_put", "saml.connection_disabled",
	} {
		if !CoreAuditKinds[k] {
			t.Errorf("%q is no longer a core kind", k)
		}
	}
	if want != 24 {
		t.Errorf("the core writes %d kinds under the extension prefixes, want 24; update this test with the new kind", want)
	}
}
