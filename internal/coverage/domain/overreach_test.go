// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
)

// TestF048_ReachBeyondTheDeclaredNeedIsExposure: held permissions above
// the declared level are the excess, ranked by what they allow; what is
// declared, or held at a lower level, is not.
func TestF048_ReachBeyondTheDeclaredNeedIsExposure(t *testing.T) {
	declared := domain.ParsePermissions("contents:write,pull_requests:write,metadata:read")
	for _, c := range []struct {
		held     string
		excess   []string
		severity string
	}{
		{`{"contents":"read","metadata":"read"}`, nil, ""},
		{"contents:write,pull_requests:write", nil, ""},
		{"contents:write,issues:read", []string{"issues:read"}, "low"},
		{"contents:write,issues:write", []string{"issues:write"}, "medium"},
		{`{"administration":"write","contents":"write"}`, []string{"administration:write"}, "high"},
		{"metadata:admin,workflows:write", []string{"metadata:admin", "workflows:write"}, "critical"},
		{"bogus,contents:owner,:write", nil, ""},
	} {
		excess, severity := domain.Overreach(declared, domain.ParsePermissions(c.held))
		if !slices.Equal(excess, c.excess) || severity != c.severity {
			t.Errorf("held %s: %v %q, want %v %q", c.held, excess, severity, c.excess, c.severity)
		}
	}
	merged := domain.ParsePermissions("contents:read").Merge(domain.ParsePermissions("contents:write,metadata:read"))
	if !slices.Equal(merged.List(), []string{"contents:write", "metadata:read"}) {
		t.Errorf("merge %v", merged.List())
	}
}
