// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
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

// MaxVisibleAgents bounds the agents a scoped viewer's lists filter by
// (D60); an org with more refuses scoped lists with RESOURCE_EXHAUSTED.
const MaxVisibleAgents = 10_000

// ErrTooManyAgents reports a scoped list over an org with more agents than
// MaxVisibleAgents.
var ErrTooManyAgents = pcerr.New(pcerr.ResourceExhausted, "TOO_MANY_AGENTS",
	"this list needs the permission at the organization: it has too many agents to filter by scope")

// Visible returns the agents a list may show, for filtering in SQL before
// paging (G0 M10 D60, T-042): all is true when the caller holds the
// permission at the org, otherwise agents are the ids of every agent where
// the caller holds it. Lists never page first and filter after.
func (s *AgentScope) Visible(ctx context.Context) (all bool, visible []string, err error) {
	if s.c.Can(s.perm, td.OrgPath(s.c.Org)) {
		return true, nil, nil
	}
	rows, err := s.q.ScopeAgentPlacements(ctx, s.c.Org, MaxVisibleAgents+1)
	if err != nil {
		return false, nil, err
	}
	if len(rows) > MaxVisibleAgents {
		return false, nil, ErrTooManyAgents
	}
	type place struct{ team, env ids.UUID }
	byPlace := map[place]bool{}
	visible = []string{}
	for _, r := range rows {
		var p place
		if r.TeamID != nil && r.EnvironmentID != nil {
			p = place{*r.TeamID, *r.EnvironmentID}
		}
		ok, seen := byPlace[p]
		if !seen {
			path, err := agents.PathOf(ctx, s.q, dbq.PcAgent{OrgID: s.c.Org, ID: r.ID, TeamID: r.TeamID, EnvironmentID: r.EnvironmentID})
			if err != nil {
				return false, nil, err
			}
			ok = s.c.Can(s.perm, path)
			byPlace[p] = ok
		}
		if ok {
			s.allowed[r.ID] = true
			visible = append(visible, r.ID.String())
		}
	}
	return false, visible, nil
}
