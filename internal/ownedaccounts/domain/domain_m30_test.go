// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"strings"
	"testing"
)

// TestHR708_OwnedAccountValueFormats: each kind takes only its own value
// format (G0 M30 D933).
//
// Covers: HR-708
func TestHR708_OwnedAccountValueFormats(t *testing.T) {
	good := map[Kind]string{
		KindAWSAccount:  "111122223333",
		KindGitHubOrg:   "acme-corp",
		KindEmailDomain: "mail.example.com",
		KindGCPProject:  "acme-prod-1",
		KindAzureTenant: "0192aaaa-bbbb-7ccc-8ddd-eeeeffff0000",
	}
	for k, v := range good {
		if !k.Valid() || !ValidValue(k, v) {
			t.Errorf("%s %q refused", k, v)
		}
	}
	bad := map[Kind][]string{
		KindAWSAccount:  {"", "11112222333", "1111222233334", "arn:aws:iam::111122223333:root"},
		KindGitHubOrg:   {"acme_corp", strings.Repeat("a", 40)},
		KindEmailDomain: {"Example.com", "localhost", "-a.com", "a..com"},
		KindGCPProject:  {"1acme-prod", "short", "Acme-prod-1"},
		KindAzureTenant: {"not-a-uuid", "0192AAAA-BBBB-7CCC-8DDD-EEEEFFFF0000"},
		"slack_team":    {"T0123"},
	}
	for k, vs := range bad {
		for _, v := range vs {
			if ValidValue(k, v) {
				t.Errorf("%s %q accepted", k, v)
			}
		}
	}
	if Kind("slack_team").Valid() {
		t.Error("an unknown kind is valid")
	}
}
