// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	tapp "github.com/katocxl/pantherclaw/internal/transactions/app"
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
// when c holds p at the org, none when c holds it nowhere, else the agents
// core's scope (tapp.AgentScope.Visible, D60) lists, which refuses an org
// with more than 10 000 agents with RESOURCE_EXHAUSTED.
func AgentScope(ctx context.Context, c tenancy.Caller, q *dbq.Queries, p td.Permission) (Scope, error) {
	if !c.CanAnywhere(p) {
		return Scope{Permission: p, Restricted: true}, nil
	}
	all, visible, err := tapp.NewAgentScope(c, q, p).Visible(ctx)
	if err != nil {
		return Scope{}, err
	}
	if all {
		return Scope{Permission: p, All: true}, nil
	}
	out := Scope{Permission: p, Agents: make([]ids.UUID, 0, len(visible))}
	for _, v := range visible {
		id, err := ids.ParseUUID(v)
		if err != nil {
			return Scope{}, err
		}
		out.Agents = append(out.Agents, id)
	}
	return out, nil
}

// intersect narrows s to the agents also in o (both scopes of one viewer).
func (s Scope) intersect(o Scope) Scope {
	switch {
	case s.Restricted || o.Restricted:
		return Scope{Permission: s.Permission, Restricted: true}
	case o.All:
		return s
	case s.All:
		return Scope{Permission: s.Permission, Agents: o.Agents}
	}
	in := make(map[ids.UUID]bool, len(o.Agents))
	for _, a := range o.Agents {
		in[a] = true
	}
	out := Scope{Permission: s.Permission, Agents: []ids.UUID{}}
	for _, a := range s.Agents {
		if in[a] {
			out.Agents = append(out.Agents, a)
		}
	}
	return out
}
