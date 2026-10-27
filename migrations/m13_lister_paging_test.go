// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package migrations

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var purposeBody = regexp.MustCompile(`(?s)WHEN '([a-z_]+)' THEN(.*?)LIMIT p_max_rows`)

// TestHR054_ListerPagingKeepsEveryPurposeAndDownRestoresIt (G0 M13 D45):
// 00184 keeps every purpose 00180 (the latest lister before it) defined,
// stays the same SECURITY DEFINER function with the same signature, keys
// every org-keyed purpose on the cursor, refuses it for the others, records
// it in the audit row, and its Down migration restores 00180's lister
// exactly.
func TestHR054_ListerPagingKeepsEveryPurposeAndDownRestoresIt(t *testing.T) {
	before := listerIn(t, "00180_account_deletion_journal.sql", "Up")
	after := listerIn(t, "00184_lister_paging.sql", "Up")
	want := purposes(before)
	slices.Sort(want)
	got := purposes(after)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("00184 lister purposes = %v, want %v", got, want)
	}
	head := "CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)\nRETURNS TABLE (org_id uuid, id uuid)\nLANGUAGE plpgsql\nSECURITY DEFINER\nSET search_path = pc, pg_temp\n"
	if !strings.HasPrefix(after, head) {
		t.Error("00184 changes the lister's signature or security attributes")
	}
	unpaged := []string{"account_memberships", "account_users", "billing_link_lookup"}
	for _, m := range purposeBody.FindAllStringSubmatch(after, -1) {
		keyed := strings.Contains(m[2], "> v_after")
		if paged := !slices.Contains(unpaged, m[1]); keyed != paged {
			t.Errorf("purpose %s: keyed on the cursor = %v, want %v", m[1], keyed, paged)
		}
	}
	if !strings.Contains(after, "'account_memberships', 'account_users', 'billing_link_lookup') THEN\n        RAISE EXCEPTION") {
		t.Error("the purposes that do not page do not refuse a cursor")
	}
	if !strings.Contains(after, "WHEN v_after IS NOT NULL THEN 'after:' || v_after::text END") {
		t.Error("the audit row does not record the cursor")
	}
	if down := listerIn(t, "00184_lister_paging.sql", "Down"); down != before {
		t.Error("00184's Down migration does not restore the lister of 00180 exactly")
	}
}
