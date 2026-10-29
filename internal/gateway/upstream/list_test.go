// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package upstream

import (
	"context"
	"fmt"
	"testing"

	"github.com/katocxl/pantherclaw/internal/sim/mcpsim"
)

// TestHR418_InventoryListingsReadEveryPageWithinBounds: resources, resource
// templates and tools are read page by page in both protocol versions; a
// server without resources lists none, completely; a listing past the
// bounds is cut and not complete.
// Covers: F352
func TestHR418_InventoryListingsReadEveryPageWithinBounds(t *testing.T) {
	ctx := context.Background()
	for _, legacy := range []bool{false, true} {
		f := mcpsim.Faults{
			Legacy: legacy, PageSize: 1,
			Extra:     []mcpsim.ExtraTool{{Name: "echo", Description: "Echo.", Params: []string{"text"}}},
			Resources: []mcpsim.Resource{{URI: "file:///a.txt", Name: "a"}, {URI: "file:///b.txt", Name: "b"}},
			Templates: []mcpsim.ResourceTemplate{{URITemplate: "file:///docs/{name}", Name: "docs"}},
		}
		_, c := simClient(t, f, 1<<20)
		for name, list := range map[string]func(context.Context, Decorate) (Listing, error){
			"tools": c.ListToolsInventory, "resources": c.ListResources, "templates": c.ListResourceTemplates,
		} {
			want := map[string]int{"tools": 3, "resources": 2, "templates": 1}[name]
			l, err := list(ctx, nil)
			if err != nil || !l.Complete || len(l.Items) != want {
				t.Errorf("legacy=%v %s: %d items, complete %v, %v; want %d complete", legacy, name, len(l.Items), l.Complete, err, want)
			}
		}
		_, plain := simClient(t, mcpsim.Faults{Legacy: legacy}, 1<<20)
		if l, err := plain.ListResources(ctx, nil); err != nil || !l.Complete || len(l.Items) != 0 {
			t.Errorf("legacy=%v: a server without resources: %+v, %v", legacy, l, err)
		}
	}

	many := make([]mcpsim.Resource, maxListPages+1)
	for i := range many {
		many[i] = mcpsim.Resource{URI: fmt.Sprintf("file:///%d", i), Name: "r"}
	}
	_, c := simClient(t, mcpsim.Faults{PageSize: 1, Resources: many}, 1<<20)
	l, err := c.ListResources(ctx, nil)
	if err != nil || l.Complete || len(l.Items) != maxListPages {
		t.Errorf("past the page bound: %d items, complete %v, %v; want %d, not complete", len(l.Items), l.Complete, err, maxListPages)
	}
	big := make([]mcpsim.Resource, MaxListItems+1)
	for i := range big {
		big[i] = mcpsim.Resource{URI: fmt.Sprintf("file:///%d", i), Name: "r"}
	}
	_, c = simClient(t, mcpsim.Faults{Resources: big}, 8<<20)
	if l, err := c.ListResources(ctx, nil); err != nil || l.Complete || len(l.Items) != MaxListItems {
		t.Errorf("past the item bound: %d items, complete %v, %v", len(l.Items), l.Complete, err)
	}
}
