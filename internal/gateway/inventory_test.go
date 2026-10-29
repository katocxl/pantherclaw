// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"encoding/json/jsontext"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
)

// TestHR418_GatewayInventoryReportsStayWithinBounds: descriptions are cut
// to 8 KiB and marked; entries the report cannot carry (a bad tool name, a
// URI over 2,048 bytes, a non-object) are left out and the report is then
// not complete; digests are the canonical entry's.
// Covers: F352
func TestHR418_GatewayInventoryReportsStayWithinBounds(t *testing.T) {
	long := strings.Repeat("é", 5000)
	inv := dispatch.Inventory{
		Complete: true,
		Tools: upstream.Listing{Items: []jsontext.Value{
			jsontext.Value(`{"name":"search","description":"` + long + `","inputSchema":{"type":"object"}}`),
			jsontext.Value(`{"name":"bad name","inputSchema":{"type":"object"}}`),
		}},
		Resources: upstream.Listing{Items: []jsontext.Value{
			jsontext.Value(`{"uri":"file:///a","name":"a","mimeType":"text/plain","description":"A file."}`),
			jsontext.Value(`{"uri":"file:///` + strings.Repeat("x", 2048) + `"}`),
			jsontext.Value(`[1]`),
		}},
		Templates: upstream.Listing{Items: []jsontext.Value{jsontext.Value(`{"uriTemplate":"file:///{name}","name":"files"}`)}},
	}
	req := inventoryRequest("c", inv)
	if req.GetComplete() {
		t.Error("a report that left entries out is complete")
	}
	if len(req.GetTools()) != 1 || len(req.GetResources()) != 1 || len(req.GetResourceTemplates()) != 1 {
		t.Fatalf("tools %d, resources %d, templates %d", len(req.GetTools()), len(req.GetResources()), len(req.GetResourceTemplates()))
	}
	tool := req.GetTools()[0]
	if !tool.GetDescriptionTruncated() || len(tool.GetDescription()) > 8192 || !strings.HasPrefix(tool.GetDigest(), "sha256:") {
		t.Errorf("tool: truncated %v, %d bytes, digest %q", tool.GetDescriptionTruncated(), len(tool.GetDescription()), tool.GetDigest())
	}
	want, _ := upstream.ToolDigest(inv.Resources.Items[0])
	if r := req.GetResources()[0]; r.GetUri() != "file:///a" || r.GetDigest() != want || r.GetDescription() != "A file." || r.GetDescriptionTruncated() {
		t.Errorf("resource = %v", r)
	}
	// An over-long name or MIME type is cut on a rune boundary and flagged;
	// the report stays complete (D43).
	longName := inventoryRequest("c", dispatch.Inventory{Complete: true, Resources: upstream.Listing{Items: []jsontext.Value{
		jsontext.Value(`{"uri":"file:///b","name":"` + strings.Repeat("é", 100) + `","mimeType":"` + strings.Repeat("m", 129) + `"}`),
	}}})
	if r := longName.GetResources(); !longName.GetComplete() || len(r) != 1 || !r[0].GetNameTruncated() || !r[0].GetMimeTypeTruncated() ||
		len(r[0].GetName()) != 128 || !utf8.ValidString(r[0].GetName()) || len(r[0].GetMimeType()) != 128 {
		t.Errorf("an over-long name: complete %v, %v", longName.GetComplete(), r)
	}
	if !inventoryRequest("c", dispatch.Inventory{Complete: true}).GetComplete() {
		t.Error("an empty complete listing is not complete")
	}
}
