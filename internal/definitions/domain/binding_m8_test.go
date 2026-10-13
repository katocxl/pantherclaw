// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// TestFactBindings (G0 M8, HR-205): a prerequisite may bind a member of
// its fact to a material identifier, enum or integer param, with the
// reason a mismatch gives; any other binding is refused.
func TestFactBindings(t *testing.T) {
	d := minimal(map[string]domain.ParamSpec{
		"sha":  {Type: domain.TypeIdentifier, Material: true, Pattern: "^[0-9a-f]{40}$"},
		"note": {Type: domain.TypeText},
		"tag":  {Type: domain.TypeIdentifier, Pattern: "^[a-z]+$"},
	})
	d.Prerequisites = []domain.Prerequisite{{
		Fact: "x.pull.head", MaxAgeSeconds: 30, Binds: &domain.FactBinding{Member: "sha", Param: "sha", Reason: "HEAD_MOVED"},
	}}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]domain.FactBinding{
		"an undeclared param": {Member: "sha", Param: "ref", Reason: "HEAD_MOVED"},
		"untrusted text":      {Member: "sha", Param: "note", Reason: "HEAD_MOVED"},
		"an immaterial param": {Member: "sha", Param: "tag", Reason: "HEAD_MOVED"},
		"a member name":       {Member: "Head SHA", Param: "sha", Reason: "HEAD_MOVED"},
		"a reason code":       {Member: "sha", Param: "sha", Reason: "head moved"},
	} {
		c := *d
		c.Prerequisites = []domain.Prerequisite{{Fact: "x.pull.head", MaxAgeSeconds: 30, Binds: &b}}
		if err := c.Validate(); !errors.Is(err, domain.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
