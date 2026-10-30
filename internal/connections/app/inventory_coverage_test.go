// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
)

// TestHR414_ResourceCoverageMatchesReviewedTemplates: a listed resource is
// covered when its URI matches a reviewed mcp_resource template through
// the resources face's matcher, a listed template only when it equals a
// reviewed one, and anything else stays NEW (D43 L5).
// Covers: F352
func TestHR414_ResourceCoverageMatchesReviewedTemplates(t *testing.T) {
	defs := []domain.Definition{
		{Mappings: []domain.Mapping{{Channel: domain.ChannelMCPResource, Resource: "docs://files/{name}"}}},
		{Mappings: []domain.Mapping{{Channel: domain.ChannelMCPResource, Resource: "docs://index"}}},
		{Mappings: []domain.Mapping{{Channel: domain.ChannelMCP, Resource: "docs://other/{name}"}}},
	}
	cov := coverage{defs: defs, templates: reviewedTemplates(defs)}
	for _, c := range []struct {
		kind, name string
		want       bool
	}{
		{InventoryResource, "docs://files/readme", true},
		{InventoryResource, "docs://index", true},
		{InventoryResource, "docs://files/a/b", false},
		{InventoryResource, "docs://files/", false},
		{InventoryResource, "docs://other/readme", false},
		{InventoryResource, "docs://elsewhere/readme", false},
		{InventoryTemplate, "docs://files/{name}", true},
		{InventoryTemplate, "docs://files/{other}", false},
		{InventoryTemplate, "docs://files/readme", false},
		{InventoryTemplate, "docs://other/{name}", false},
	} {
		if got := cov.covers(c.kind, c.name, ""); got != c.want {
			t.Errorf("covers(%s, %q) = %v, want %v", c.kind, c.name, got, c.want)
		}
	}
	if (coverage{}).covers(InventoryResource, "docs://index", "") {
		t.Error("an empty coverage covers a resource")
	}
}
