// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	iddomain "github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// WithMcpIssuerBase sets the server's public URL, under which every org's
// authorization server issuer lives (G0 M26 D402). Without it no gateway
// opens its MCP face's OAuth route. It is set once, before serving.
func (s *Service) WithMcpIssuerBase(publicURL string) *Service {
	s.mcpIssuerBase = publicURL
	return s
}

// mcpIssuer is the org's issuer while its MCP authorization is on.
func (s *Service) mcpIssuer(ctx context.Context, q *dbq.Queries, org ids.OrgID) (string, error) {
	if s.mcpIssuerBase == "" {
		return "", nil
	}
	a, err := q.GetOrgMcpAccess(ctx, org)
	if db.IsNoRows(err) || (err == nil && !a.Enabled) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	return iddomain.IssuerID(s.mcpIssuerBase, org), nil
}
