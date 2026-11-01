// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/mcpcatalog/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	"github.com/katocxl/pantherclaw/internal/postureview/ports"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// KindUnapprovedServer is the posture queue's finding for a running server
// the catalogue has not approved (D226, F879).
const KindUnapprovedServer = "UNAPPROVED_SERVER"

// Source reports unapproved servers to the ranked posture queue (D226). It
// reports nothing until the catalogue holds an APPROVED server: an empty
// catalogue is not yet a statement about anything. A connection finding has
// no agent, so it needs org scope; a scanned server's finding belongs to its
// discovered agent. Both need catalog.read as well as posture.read. A title
// is fixed text: a name, which a scan reports, stays in Detail (D260).
type Source struct {
	Pool     *db.Pool
	Editions Editions
}

var _ ports.Source = (*Source)(nil)

// Name implements ports.Source.
func (s *Source) Name() pvdomain.Source { return pvdomain.SourceCatalog }

// Findings implements ports.Source.
func (s *Source) Findings(ctx context.Context, v ports.Viewer, _ pvdomain.Filter) ([]pvdomain.Finding, bool, error) {
	if s.Editions == nil {
		return nil, false, ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return nil, false, err
	}
	if !e.MCPCatalog() {
		return nil, false, ErrEdition
	}
	reach := v.Posture
	if v.Under != nil {
		r, err := v.Under(ctx, td.PermCatalogRead)
		if err != nil {
			return nil, false, err
		}
		reach = reach.Intersect(r)
		if none(reach) && !none(v.Posture) {
			return nil, false, td.ErrPermissionDenied(td.PermCatalogRead) // RESTRICTED, never empty (D255)
		}
	}
	var out []pvdomain.Finding
	truncated := false
	add := func(f pvdomain.Finding) bool {
		if len(out) == pvdomain.MaxPerSource {
			truncated = true
			return false
		}
		out = append(out, f)
		return true
	}
	err = s.Pool.InTenantTx(ctx, v.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		servers, err := decidedServers(ctx, q, v.Org)
		if err != nil {
			return err
		}
		if !anyApproved(servers) {
			return nil
		}
		if reach.Has(nil) {
			conns, err := q.McpConnections(ctx, v.Org)
			if err != nil {
				return err
			}
			for _, c := range conns {
				if c.State != capp.StateActive || allowed(servers, candidate(target(c))) {
					continue
				}
				if !add(connectionFinding(c)) {
					return nil
				}
			}
		}
		locals, err := q.McpScanServers(ctx, v.Org)
		if err != nil {
			return err
		}
		for _, l := range locals {
			if !reach.Has(&l.AgentID) || allowed(servers, scanCandidate(l)) {
				continue
			}
			if !add(scanFinding(l)) {
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if len(out) == 0 && !reach.Has(nil) {
		// Connection findings need org scope: an empty answer here would
		// claim there are none (D255).
		return nil, false, td.ErrPermissionDenied(td.PermCatalogRead)
	}
	return out, truncated, nil
}

// none reports whether a reach covers nothing at all.
func none(r ports.Reach) bool { return !r.All && !r.Org && len(r.Agents) == 0 }

func anyApproved(servers []dbq.PcMcpServer) bool {
	for _, s := range servers {
		if domain.Status(s.Status) == domain.StatusApproved {
			return true
		}
	}
	return false
}

// scanCandidate is what a scan saw. Its host comes without a path, so a
// server with a path prefix never matches a scan.
func scanCandidate(l dbq.McpScanServersRow) domain.Candidate {
	return domain.Candidate{Host: l.UrlHost, PackageRef: l.PackageRef}
}

func connectionFinding(c dbq.McpConnectionsRow) pvdomain.Finding {
	id := c.ID
	return pvdomain.Finding{
		Source: pvdomain.SourceCatalog, SourceID: "connection:" + c.ID.String(), Kind: KindUnapprovedServer,
		ConnectionID: &id, Title: "An MCP connection reaches a server the catalogue has not approved",
		Detail: map[string]string{"name": c.Name}, State: "OPEN", Since: c.CreatedAt,
		Fix: pvdomain.Fix{Kind: pvdomain.FixReviewServer, TargetID: "connection:" + c.ID.String(), Label: "Review this server for the catalogue"},
	}
}

func scanFinding(l dbq.McpScanServersRow) pvdomain.Finding {
	agent := l.AgentID
	return pvdomain.Finding{
		Source: pvdomain.SourceCatalog, SourceID: "discovery:" + l.ID.String(), Kind: KindUnapprovedServer, AgentID: &agent,
		Title: "A local MCP server is not in the catalogue", Detail: map[string]string{"name": l.Name}, State: "OPEN", Since: l.FirstSeenAt,
		Fix: pvdomain.Fix{Kind: pvdomain.FixReviewServer, TargetID: "discovery:" + l.ID.String(), Label: "Review this server for the catalogue"},
	}
}
