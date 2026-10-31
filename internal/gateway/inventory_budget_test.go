// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"encoding/json/jsontext"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
)

func tool(name, description string, schemaBytes int) jsontext.Value {
	return jsontext.Value(`{"name":"` + name + `","description":"` + description + `","inputSchema":{"type":"object","description":"` + strings.Repeat("x", schemaBytes) + `"}}`)
}

// TestD240_AReportStaysWithinItsBudget: however much a server lists, the report
// fits, every tool keeps its digest, what is left out is marked, and the
// server's longest entries cost its shortest nothing.
// Covers: F868
func TestD240_AReportStaysWithinItsBudget(t *testing.T) {
	t.Run("schemas", func(t *testing.T) {
		tools := []jsontext.Value{}
		for i := range 60 {
			tools = append(tools, tool("big"+strconv.Itoa(i), "d", 60<<10))
		}
		tools = append(tools, tool("small", "d", 10))
		req := inventoryRequest("c", dispatch.Inventory{Complete: true, Tools: upstream.Listing{Items: tools}})
		if size := proto.Size(req); size > maxInventoryReport {
			t.Fatalf("%d bytes", size)
		}
		if !req.GetComplete() || len(req.GetTools()) != len(tools) {
			t.Fatalf("complete %v, %d tools", req.GetComplete(), len(req.GetTools()))
		}
		omitted := 0
		for _, x := range req.GetTools() {
			if x.GetInputSchemaDigest() == "" || x.GetDigest() == "" {
				t.Errorf("%s lost its digest", x.GetName())
			}
			if x.GetSchemaOmitted() {
				omitted++
				if x.GetInputSchema() != "" {
					t.Errorf("%s: omitted with text", x.GetName())
				}
			}
			if x.GetName() == "small" && (x.GetSchemaOmitted() || x.GetInputSchema() == "") {
				t.Errorf("the shortest paid for the longest: %v", x.GetSchemaOmitted())
			}
		}
		if omitted == 0 || omitted == len(tools) {
			t.Errorf("%d omitted of %d", omitted, len(tools))
		}
	})
	t.Run("descriptions", func(t *testing.T) {
		tools := []jsontext.Value{}
		for i := range 1000 {
			tools = append(tools, tool("t"+strconv.Itoa(i), strings.Repeat("d", 8<<10), 10))
		}
		req := inventoryRequest("c", dispatch.Inventory{Complete: true, Tools: upstream.Listing{Items: tools}})
		if size := proto.Size(req); size > maxInventoryReport {
			t.Fatalf("%d bytes", size)
		}
		if !req.GetTools()[0].GetDescriptionTruncated() || !req.GetTools()[0].GetSchemaOmitted() || !req.GetComplete() {
			t.Errorf("%v", req.GetTools()[0].GetDescriptionTruncated())
		}
	})
	t.Run("a report that fits is left alone", func(t *testing.T) {
		req := inventoryRequest("c", dispatch.Inventory{Complete: true, Tools: upstream.Listing{Items: []jsontext.Value{tool("a", "d", 10)}}})
		if req.GetTools()[0].GetSchemaOmitted() || req.GetTools()[0].GetInputSchema() == "" {
			t.Errorf("%v", req.GetTools()[0])
		}
	})
}

// TestD245_GatewayReportsTheOtherListedFields: title, annotations and output
// schema travel for the checks; anything else stays out.
// Covers: F868
func TestD245_GatewayReportsTheOtherListedFields(t *testing.T) {
	big := strings.Repeat("x", maxListedExtra)
	req := inventoryRequest("c", dispatch.Inventory{Complete: true, Tools: upstream.Listing{Items: []jsontext.Value{
		jsontext.Value(`{"name":"a","title":"T","annotations":{"readOnlyHint":true},"outputSchema":{"type":"object"},"_meta":{"x":"y"}}`),
		jsontext.Value(`{"name":"b"}`),
		jsontext.Value(`{"name":"c","title":"` + big + `"}`),
	}}})
	got := req.GetTools()
	if x := got[0].GetListedExtra(); !strings.Contains(x, `"title":"T"`) || !strings.Contains(x, "readOnlyHint") || !strings.Contains(x, "outputSchema") || strings.Contains(x, "_meta") {
		t.Errorf("a: %s", x)
	}
	if got[1].GetListedExtra() != "" || got[1].GetListedExtraTruncated() {
		t.Errorf("b: %v", got[1])
	}
	if got[2].GetListedExtra() != "" || !got[2].GetListedExtraTruncated() {
		t.Errorf("c: %d bytes", len(got[2].GetListedExtra()))
	}
}
