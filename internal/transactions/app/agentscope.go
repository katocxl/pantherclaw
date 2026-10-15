// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// AgentScope answers, per agent, whether the caller holds one permission
// where the agent lives, and caches the answer for the caller's request.
// Lists, searches, graphs, counts and summaries filter rows through it
// before they aggregate, so a count never includes a row the caller may
// not read (G0 M10 D8, T-042, F298).
type AgentScope struct {
	c       tenancy.Caller
	q       *dbq.Queries
	perm    td.Permission
	allowed map[ids.UUID]bool
}

// NewAgentScope returns the scope of c for perm, reading agents through q
// (the caller's tenant transaction).
func NewAgentScope(c tenancy.Caller, q *dbq.Queries, perm td.Permission) *AgentScope {
	return &AgentScope{c: c, q: q, perm: perm, allowed: map[ids.UUID]bool{}}
}

// Can reports whether the caller holds the scope's permission where agent
// lives.
func (s *AgentScope) Can(ctx context.Context, agent ids.UUID) (bool, error) {
	if ok, seen := s.allowed[agent]; seen {
		return ok, nil
	}
	a, err := s.q.GetAgent(ctx, s.c.Org, agent)
	if err != nil {
		return false, err
	}
	path, err := agents.PathOf(ctx, s.q, a)
	if err != nil {
		return false, err
	}
	ok := s.c.Can(s.perm, path)
	s.allowed[agent] = ok
	return ok, nil
}
