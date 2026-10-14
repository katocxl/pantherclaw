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
	declared := domain.ParsePermissions("contents:write,pull_requests:write")
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
		{"bogus,:write,metadata:", nil, ""},
		// A level it does not know is ranked as admin.
		{"contents:owner", []string{"contents:owner"}, "critical"},
		// Every GitHub App holds metadata:read.
		{"metadata:read", nil, ""},
		{"secrets:read,repository_hooks:write", []string{"repository_hooks:write", "secrets:read"}, "high"},
		{"pull_requests:write,actions:write", []string{"actions:write"}, "high"},
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

// TestF048_AnUnknownLevelDeclaresNothing: a level the package declares
// that coverage does not know never covers a held permission.
func TestF048_AnUnknownLevelDeclaresNothing(t *testing.T) {
	declared := domain.Permissions{}.Merge(domain.ParsePermissions("issues:owner"))
	if excess, severity := domain.Overreach(declared, domain.ParsePermissions("issues:write")); !slices.Equal(excess, []string{"issues:write"}) || severity != "medium" {
		t.Errorf("an unknown declared level covered issues:write: %v %q", excess, severity)
	}
}
