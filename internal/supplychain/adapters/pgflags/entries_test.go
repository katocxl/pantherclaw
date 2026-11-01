// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgflags

import (
	"errors"
	"strings"
	"testing"

	ddomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	"github.com/katocxl/pantherclaw/internal/supplychain/domain"
)

const upstreamDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

// TestD244_ImportComparesTheUpstreamDigest: a tool at import carries the digest
// approvals hold, so the same tool elsewhere is not shadowing itself, and
// another definition under that name is.
// Covers: T-252, F869
func TestD244_ImportComparesTheUpstreamDigest(t *testing.T) {
	p := &ddomain.Package{Definitions: []ddomain.Definition{{
		Digest:   "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		Dispatch: &ddomain.Dispatch{MCP: &ddomain.MCPDispatch{UpstreamDigest: upstreamDigest}},
		Mappings: []ddomain.Mapping{{Channel: ddomain.ChannelMCP, Tool: "get_refund", Description: "Reads one refund."}},
	}}}
	entries, err := packageEntries(p)
	if err != nil || len(entries) != 1 || entries[0].tool.Digest != upstreamDigest {
		t.Fatalf("%+v %v", entries, err)
	}
	same := domain.Known{Provenance: true, Approved: []domain.Approved{{Name: "get_refund", Digest: upstreamDigest}}}
	if r := domain.Check(entries[0].tool, same); domain.Summary(r) == string(domain.KindToolShadowing) {
		t.Errorf("the same tool: %+v", r)
	}
	other := domain.Known{Provenance: true, Approved: []domain.Approved{{Name: "get_refund", Digest: "sha256:other"}}}
	if r := domain.Check(entries[0].tool, other); len(r.Flags) == 0 || r.Flags[0].Kind != domain.KindToolShadowing {
		t.Errorf("another definition: %+v", r)
	}
}

// TestD245_ImportChecksEveryMapping: a second mapping of a tool and a resource
// mapping each say something of their own to an agent.
// Covers: T-250, F869
func TestD245_ImportChecksEveryMapping(t *testing.T) {
	p := &ddomain.Package{Definitions: []ddomain.Definition{{
		Digest: upstreamDigest,
		Mappings: []ddomain.Mapping{
			{Channel: ddomain.ChannelMCP, Tool: "t", Description: "First."},
			{Channel: ddomain.ChannelMCP, Tool: "t", Description: "Second <!-- x -->."},
			{Channel: ddomain.ChannelMCPResource, Resource: "file:///{id}", Description: "A file <!-- y -->."},
			{Channel: ddomain.ChannelHTTP, Method: "GET", Path: "/x"},
		},
	}}}
	entries, err := packageEntries(p)
	if err != nil || len(entries) != 3 {
		t.Fatalf("%d entries, %v", len(entries), err)
	}
	if entries[1].tool.Description != "Second <!-- x -->." || entries[2].tool.IsTool || entries[2].tool.Description != "A file <!-- y -->." {
		t.Errorf("%+v", entries)
	}
}

// TestD255_BelowItsScopeTheSourceSaysRestricted: a viewer without org scope
// gets a refusal, which the queue shows as RESTRICTED, never an empty COMPLETE.
// Covers: F860, F863
func TestD255_BelowItsScopeTheSourceSaysRestricted(t *testing.T) {
	_, _, err := (&Source{}).Findings(t.Context(), ports.Viewer{Org: ids.OrgID{}, Posture: ports.Reach{All: true}}, pvdomain.Filter{})
	e, ok := errors.AsType[*pcerr.Error](err)
	if !ok || e.Code() != pcerr.PermissionDenied {
		t.Fatalf("%v", err)
	}
}

// TestD272_AToolWithNoUpstreamDigestSaysSo: a package that pins no digest gives
// the checks nothing to compare, and the stored flag keeps the reason.
// Covers: T-252, F869
func TestD272_AToolWithNoUpstreamDigestSaysSo(t *testing.T) {
	p := &ddomain.Package{Definitions: []ddomain.Definition{{
		Digest:   upstreamDigest,
		Mappings: []ddomain.Mapping{{Channel: ddomain.ChannelMCP, Tool: "t", Description: "Reads."}},
	}}}
	entries, err := packageEntries(p)
	if err != nil || len(entries) != 1 || !entries[0].tool.DigestUnknown {
		t.Fatalf("%+v %v", entries, err)
	}
	r := domain.Check(entries[0].tool, domain.Known{Provenance: true, Approved: []domain.Approved{{Name: "t", Digest: "sha256:other"}}})
	if len(r.Flags) != 1 || r.Flags[0].Severity != domain.SeverityMedium {
		t.Fatalf("%+v", r)
	}
	b, err := encode(r.Flags[0])
	if err != nil || !strings.Contains(string(b), `"reason":"digest_unknown"`) {
		t.Errorf("%s %v", b, err)
	}
}

// TestD272_EachResourceHasItsOwnKey: a key holds the URI, within what an index
// takes, and two long URIs stay apart.
// Covers: F869
func TestD272_EachResourceHasItsOwnKey(t *testing.T) {
	if k := resourceKey("file:///{id}"); k != "resource:file:///{id}" {
		t.Errorf("%s", k)
	}
	a, b := resourceKey(strings.Repeat("a", maxResourceKey+1)), resourceKey(strings.Repeat("b", maxResourceKey+1))
	if a == b || len(a) > 100 {
		t.Errorf("%s %s", a, b)
	}
}

// TestD260_AnObservedNameStaysOutOfTheTitle: the title is fixed words, and the
// name a tool was listed under is detail.
// Covers: F860, F869
func TestD260_AnObservedNameStaysOutOfTheTitle(t *testing.T) {
	f := finding(dbq.PcSupplychainFlag{CheckKind: string(domain.KindToolShadowing), Tool: "list_issues", Severity: "HIGH", State: "OPEN"})
	if strings.Contains(f.Title, "list_issues") || f.Title != domain.Title(domain.KindToolShadowing) {
		t.Errorf("title %q", f.Title)
	}
	if f.Detail["name"] != "list_issues" {
		t.Errorf("detail %v", f.Detail)
	}
	if f := finding(dbq.PcSupplychainFlag{CheckKind: string(domain.KindHiddenInstruction)}); f.Detail != nil {
		t.Errorf("no name: %v", f.Detail)
	}
}
