// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Scope is what a viewer may read of one entity: every row of the org
// (All), the rows of the listed agents, or nothing (Restricted). It is
// derived from the viewer's bindings and the agents' places alone, never
// from which rows exist (D8).
type Scope struct {
	Permission td.Permission
	All        bool
	Agents     []ids.UUID
	Restricted bool
}

// agentList returns the agents parameter, never nil.
func (s Scope) agentList() []ids.UUID {
	if s.Agents == nil {
		return []ids.UUID{}
	}
	return s.Agents
}

// orgScope is the scope of an org-level permission: everything or nothing.
func orgScope(c tenancy.Caller, p td.Permission) Scope {
	if c.Can(p, td.OrgPath(c.Org)) {
		return Scope{Permission: p, All: true}
	}
	return Scope{Permission: p, Restricted: true}
}

// AgentScope returns the agents whose rows c may read with p: all of them
// when c holds p at the org, none when c holds it nowhere, else each agent
// whose place (agents.PathOf) carries p for c.
func AgentScope(ctx context.Context, c tenancy.Caller, q *dbq.Queries, p td.Permission) (Scope, error) {
	if c.Can(p, td.OrgPath(c.Org)) {
		return Scope{Permission: p, All: true}, nil
	}
	if !c.CanAnywhere(p) {
		return Scope{Permission: p, Restricted: true}, nil
	}
	rows, err := q.SearchAgentPlacements(ctx, c.Org)
	if err != nil {
		return Scope{}, err
	}
	type place struct{ team, env ids.UUID }
	seen := map[place]bool{}
	out := Scope{Permission: p, Agents: []ids.UUID{}}
	for _, r := range rows {
		if r.TeamID == nil || r.EnvironmentID == nil {
			continue // a discovered agent lives at the org, which c does not cover
		}
		k := place{*r.TeamID, *r.EnvironmentID}
		ok, known := seen[k]
		if !known {
			path, err := agents.PathOf(ctx, q, dbq.PcAgent{OrgID: c.Org, ID: r.ID, TeamID: r.TeamID, EnvironmentID: r.EnvironmentID})
			if err != nil {
				return Scope{}, err
			}
			ok = c.Can(p, path)
			seen[k] = ok
		}
		if ok {
			out.Agents = append(out.Agents, r.ID)
		}
	}
	return out, nil
}
