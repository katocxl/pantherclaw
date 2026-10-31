// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgflags

import (
	"errors"
	"testing"

	ddomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
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
