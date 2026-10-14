// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"strings"
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// TestHR206_AStatusListTooLongGivesNoVerdict (#349 review): a status list
// longer than the read takes is no verdict, never one from part of it; a
// short one gives its latest status from the named creator.
func TestHR206_AStatusListTooLongGivesNoVerdict(t *testing.T) {
	l := &defs.VerifierLookup{
		Creator:  &defs.CreatorSpec{Field: "/creator/login", OneOf: []string{"github-actions[bot]"}},
		Statuses: &defs.StatusList{Field: "/state"},
	}
	status := func(state string) string {
		return `{"state":"` + state + `","creator":{"login":"github-actions[bot]"}}`
	}
	long := "[" + status("success") + strings.Repeat(","+status("failure"), 1000) + "]"
	if got := verdict([]byte(long), l); got != "" {
		t.Fatalf("1001 statuses: %q", got)
	}
	if got := verdict([]byte("["+status("success")+","+status("failure")+"]"), l); got != "success" {
		t.Fatalf("two statuses: %q", got)
	}
}
