// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/upstream"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Discovery inventory (F352, G0 M15 D20): on every drift check the gateway
// lists each kind-mcp connection's tools, resources and resource templates
// and reports them. The report only informs review: the gateway serves
// reviewed definitions alone, whatever it lists here (HR-414).

// Report bounds (HR-418): what breaks them is left out and the report is
// then not complete.
const (
	maxInventoryURI  = 2048
	maxInventoryName = 128
	// maxInventorySchema caps a tool's input schema (G0 M24 D211).
	maxInventorySchema = 64 << 10
	// maxListedExtra caps a tool's other listed fields (D245).
	maxListedExtra = 16 << 10
	// maxInventoryReport caps one report (D240), under what the control plane
	// reads, so that a long list cannot lose the whole report.
	maxInventoryReport = 768 << 10
)

var inventoryTool = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)

// inventory lists and reports one connection's inventory; a failure is
// logged and tried again on the next check.
func (g *Gateway) inventory(ctx context.Context, id string, conn *control.Connection) {
	if g.reportInventory == nil {
		return
	}
	inv, err := g.engine.ListInventory(ctx, conn)
	if err != nil {
		g.log.WarnContext(ctx, "gateway.inventory_list_failed", slog.String("connection_id", id), pclog.Err(err))
		return
	}
	if err := g.reportInventory(ctx, id, inv); err != nil {
		g.log.WarnContext(ctx, "gateway.inventory_not_reported", slog.String("connection_id", id), pclog.Err(err))
	}
}

// inventoryRequest is the ReportInventory request of a listing. Each
// description is cut to 8 KiB as drift reports cut it.
func inventoryRequest(conn string, inv dispatch.Inventory) *pb.ReportInventoryRequest {
	req := &pb.ReportInventoryRequest{ConnectionId: conn, Complete: inv.Complete}
	for _, t := range inv.Tools.Items {
		var n struct {
			Name        string         `json:"name"`
			Description jsontext.Value `json:"description"`
			InputSchema jsontext.Value `json:"inputSchema"`
		}
		d, err := upstream.ToolDigest(t)
		if err != nil || json.Unmarshal(t, &n) != nil || !inventoryTool.MatchString(n.Name) {
			req.Complete = false
			continue
		}
		desc, cut := description(n.Description)
		schema, schemaDigest, schemaCut := inputSchema(n.InputSchema)
		extra, extraCut := listedExtra(t)
		req.Tools = append(req.Tools, &pb.InventoryTool{
			Name: n.Name, Digest: d, Description: desc, DescriptionTruncated: cut,
			InputSchema: schema, InputSchemaDigest: schemaDigest, InputSchemaTruncated: schemaCut,
			ListedExtra: extra, ListedExtraTruncated: extraCut,
		})
	}
	for _, r := range inv.Resources.Items {
		e, ok := resourceEntry(r, "uri")
		if !ok {
			req.Complete = false
			continue
		}
		req.Resources = append(req.Resources, &pb.InventoryResource{
			Uri: e.ref, Name: e.name, MimeType: e.mime, Description: e.desc, DescriptionTruncated: e.cut, Digest: e.digest,
			NameTruncated: e.nameCut, MimeTypeTruncated: e.mimeCut,
		})
	}
	for _, r := range inv.Templates.Items {
		e, ok := resourceEntry(r, "uriTemplate")
		if !ok {
			req.Complete = false
			continue
		}
		req.ResourceTemplates = append(req.ResourceTemplates, &pb.InventoryResourceTemplate{
			UriTemplate: e.ref, Name: e.name, MimeType: e.mime, Description: e.desc, DescriptionTruncated: e.cut, Digest: e.digest,
			NameTruncated: e.nameCut, MimeTypeTruncated: e.mimeCut,
		})
	}
	capReport(req)
	return req
}

// listedExtra is a tool's other listed fields as reported.
func listedExtra(t jsontext.Value) (string, bool) {
	v, cut := upstream.ListedExtra(t)
	if len(v) > maxListedExtra || !utf8.Valid(v) {
		return "", true
	}
	return string(v), cut
}

// capReport fits a report to maxInventoryReport, so a server cannot silence
// its own inventory by listing too much (D240). Schemas and other listed
// fields go first, the longest of them, each leaving its digest and a mark the
// server flags. If that is not enough, descriptions are cut evenly and marked,
// and last resources are left out, which makes the report not complete.
func capReport(req *pb.ReportInventoryRequest) {
	if proto.Size(req) <= maxInventoryReport {
		return
	}
	omitListed(req)
	for range 3 { // each pass adds its marks, so a second may be needed
		cutDescriptions(req)
	}
	over := proto.Size(req) - maxInventoryReport
	for over > 0 && len(req.GetResourceTemplates()) > 0 {
		last := len(req.ResourceTemplates) - 1
		over -= proto.Size(req.ResourceTemplates[last])
		req.ResourceTemplates, req.Complete = req.ResourceTemplates[:last], false
	}
	for over > 0 && len(req.GetResources()) > 0 {
		last := len(req.Resources) - 1
		over -= proto.Size(req.Resources[last])
		req.Resources, req.Complete = req.Resources[:last], false
	}
}

// omitListed takes every schema and listed extra out, then puts back the
// shortest for as long as they fit: one long entry costs the others nothing.
func omitListed(req *pb.ReportInventoryRequest) {
	type piece struct {
		size    int
		restore func()
	}
	var pieces []piece
	for _, t := range req.GetTools() {
		if s := t.GetInputSchema(); s != "" {
			t.InputSchema, t.SchemaOmitted = "", true
			pieces = append(pieces, piece{len(s), func() { t.InputSchema, t.SchemaOmitted = s, false }})
		}
		if x := t.GetListedExtra(); x != "" {
			cut := t.GetListedExtraTruncated() // a field it left out stays marked
			t.ListedExtra, t.ListedExtraTruncated = "", true
			pieces = append(pieces, piece{len(x), func() { t.ListedExtra, t.ListedExtraTruncated = x, cut }})
		}
	}
	slices.SortStableFunc(pieces, func(a, b piece) int { return a.size - b.size })
	room := maxInventoryReport - proto.Size(req)
	for _, p := range pieces {
		const overhead = 6 // a field's tag and length
		if p.size+overhead > room {
			return
		}
		room -= p.size + overhead
		p.restore()
	}
}

// cutDescriptions gives each description an even share of what the report has
// left for them.
func cutDescriptions(req *pb.ReportInventoryRequest) {
	over := proto.Size(req) - maxInventoryReport
	if over <= 0 {
		return
	}
	type text struct {
		s   *string
		cut *bool
	}
	var texts []text
	total := 0
	for _, t := range req.GetTools() {
		texts = append(texts, text{&t.Description, &t.DescriptionTruncated})
		total += len(t.GetDescription())
	}
	for _, r := range req.GetResources() {
		texts = append(texts, text{&r.Description, &r.DescriptionTruncated})
		total += len(r.GetDescription())
	}
	for _, r := range req.GetResourceTemplates() {
		texts = append(texts, text{&r.Description, &r.DescriptionTruncated})
		total += len(r.GetDescription())
	}
	if len(texts) == 0 || total == 0 {
		return
	}
	share := max(0, (total-over)/len(texts))
	for _, x := range texts {
		if len(*x.s) > share {
			n := share
			for n > 0 && !utf8.RuneStart((*x.s)[n]) {
				n--
			}
			*x.s, *x.cut = (*x.s)[:n], true
		}
	}
}

// inputSchema is a tool's listed schema as reported (G0 M24 D211): its text
// and digest, or only the digest when it is over 64 KiB, since a cut schema
// is not JSON. A schema that cannot be sent or digested is reported as cut,
// so the server knows it was not checked.
func inputSchema(v jsontext.Value) (string, string, bool) {
	if len(v) == 0 {
		return "", "", false
	}
	digest, err := upstream.SchemaDigest(v)
	if err != nil || !utf8.Valid(v) {
		return "", "", true
	}
	if len(v) > maxInventorySchema {
		return "", digest, true
	}
	return string(v), digest, false
}

// listed is one resource or template as reported.
type listed struct {
	ref, name, mime, desc, digest string
	cut, nameCut, mimeCut         bool
}

// resourceEntry reads a resource (field "uri") or template ("uriTemplate")
// listing entry; its digest is the SHA-256 of the canonical entry without
// _meta, as a tool's is.
func resourceEntry(v jsontext.Value, field string) (listed, bool) {
	var m map[string]jsontext.Value
	if json.Unmarshal(v, &m) != nil {
		return listed{}, false
	}
	str := func(k string) (string, bool) {
		raw, ok := m[k]
		if !ok {
			return "", true
		}
		var s string
		return s, json.Unmarshal(raw, &s) == nil
	}
	ref, ok1 := str(field)
	name, ok2 := str("name")
	mime, ok3 := str("mimeType")
	d, err := upstream.ToolDigest(v)
	if !ok1 || !ok2 || !ok3 || err != nil || ref == "" || len(ref) > maxInventoryURI {
		return listed{}, false
	}
	desc, cut := description(m["description"])
	// An over-long name or MIME type is display text only: cut and flagged,
	// so the report stays complete (D43).
	name, nameCut := cutUTF8(name, maxInventoryName)
	mime, mimeCut := cutUTF8(mime, maxInventoryName)
	return listed{ref: ref, name: name, mime: mime, desc: desc, cut: cut, nameCut: nameCut, mimeCut: mimeCut, digest: d}, true
}

// description is a listed description as reported: valid UTF-8 cut to
// 8 KiB; a non-string description is reported empty.
func description(v jsontext.Value) (string, bool) {
	s, cut, _ := driftDescription(descriptionText(v))
	if s == nil {
		return "", false
	}
	return *s, cut
}

func descriptionText(v jsontext.Value) *string {
	if len(v) == 0 || v.Kind() != '"' {
		return nil
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return nil
	}
	return &s
}

// cutUTF8 is s as valid UTF-8 cut to at most n bytes on a rune boundary,
// and whether it was cut.
func cutUTF8(s string, n int) (string, bool) {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s, false
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s, true
}
