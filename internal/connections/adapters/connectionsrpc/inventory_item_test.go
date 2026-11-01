// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectionsrpc

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
)

// TestD241_ListsLeaveTheSchemaOut: a list item has the schema's digest and marks
// and no text, and only the single read returns it.
// Covers: F868
func TestD241_ListsLeaveTheSchemaOut(t *testing.T) {
	r := dbq.PcConnectionInventory{InputSchema: `{"type":"object"}`, InputSchemaDigest: "sha256:a", InputSchemaTruncated: true, ListedExtra: `{"title":"x"}`}
	it := inventoryItemOf(r)
	if it.GetInputSchema() != "" || it.GetListedExtra() != "" || it.GetInputSchemaDigest() != "sha256:a" || !it.GetInputSchemaTruncated() {
		t.Fatalf("%v", it)
	}
	full := inventoryDetailOf(r)
	if full.GetInputSchema() != r.InputSchema || full.GetListedExtra() != r.ListedExtra {
		t.Fatalf("%v", full)
	}
}
