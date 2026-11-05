// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Shared intel matching at discovery and drift (G0 M38 D1104; HR-819,
// HR-822), beside the injection scan. It runs in the report's transaction
// and only records matches: it never refuses a report, quarantines or
// changes what is served.

// ServerInfo is what an upstream MCP server said of itself in serverInfo:
// UNTRUSTED, recorded for matching only (HR-822).
type ServerInfo struct {
	Name, Version string
}

// IntelMatcher matches against the shared intel indicators
// (intel/app.Matcher).
type IntelMatcher interface {
	// Server records a connection's upstream serverInfo, when the gateway
	// learned it, and matches the server.
	Server(ctx context.Context, tx db.TenantTx, conn ids.UUID, name, version string, by evdomain.Actor) error
	// Tool matches a tool's listed description; item is zero for a drift
	// report.
	Tool(ctx context.Context, tx db.TenantTx, conn, item ids.UUID, tool, description string, by evdomain.Actor) error
}

// WithIntel sets the intel matcher.
func (s *Service) WithIntel(m IntelMatcher) *Service {
	s.intel = m
	return s
}

// intelServer matches the connection's upstream server.
func (s *Service) intelServer(ctx context.Context, tx db.TenantTx, conn ids.UUID, info *ServerInfo, by evdomain.Actor) error {
	if s.intel == nil {
		return nil
	}
	name, version := "", ""
	if info != nil {
		name, version = info.Name, info.Version
	}
	return s.intel.Server(ctx, tx, conn, name, version, by)
}

// intelTool matches a tool's description.
func (s *Service) intelTool(ctx context.Context, tx db.TenantTx, conn, item ids.UUID, tool, description string, by evdomain.Actor) error {
	if s.intel == nil || description == "" {
		return nil
	}
	return s.intel.Tool(ctx, tx, conn, item, tool, description, by)
}
