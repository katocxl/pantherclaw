// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cohorts

import (
	"context"
	"encoding/json/v2"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// A cohort's scope (D71 G4, G8) is where it is read and managed: the
// narrowest scope holding its rule's scope (a team rule: the team; an
// environment rule: the environment; a task-type rule alone: the org) and
// every static member's path. A cohort with neither is the org's. Viewers
// need agent.read there, managers cohort.manage there and at each static
// member they add or remove.

// ruleScope is where a rule's agents live.
func ruleScope(ctx context.Context, q *dbq.Queries, org ids.OrgID, r *Rule) (td.Path, error) {
	path := td.OrgPath(org)
	team := r.TeamID
	var envTeam *ids.UUID
	if r.EnvironmentID != nil {
		e, err := q.GetEnvironmentPlacement(ctx, org, *r.EnvironmentID)
		if db.IsNoRows(err) {
			return nil, invalid("the rule's environment does not exist")
		} else if err != nil {
			return nil, err
		}
		envTeam = e.TeamID
		if team == nil {
			team = envTeam
		}
	}
	if team == nil {
		return path, nil // an org environment, or a task type alone
	}
	t, err := q.GetTeamPlacement(ctx, org, *team)
	if db.IsNoRows(err) {
		return nil, invalid("the rule's team does not exist")
	} else if err != nil {
		return nil, err
	}
	if t.BusinessUnitID != nil {
		path = path.Child(td.ScopeBusinessUnit, *t.BusinessUnitID)
	}
	path = path.Child(td.ScopeTeam, *team)
	if r.EnvironmentID != nil && envTeam != nil && *envTeam == *team {
		path = path.Child(td.ScopeEnvironment, *r.EnvironmentID)
	}
	return path, nil
}

// common is the longest shared prefix of two paths.
func common(a, b td.Path) td.Path {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return a[:n:n]
}

// scopeOf is a cohort's scope from its rule (rule) and static members.
func scopeOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, cohort ids.UUID, rule *Rule) (td.Path, error) {
	var scope td.Path
	if rule != nil {
		p, err := ruleScope(ctx, q, org, rule)
		if err != nil {
			return nil, err
		}
		scope = p
	}
	members, err := q.FleetCohortStaticAgents(ctx, org, cohort)
	if err != nil {
		return nil, err
	}
	for _, a := range members {
		p, err := aapp.PathOf(ctx, q, a)
		if err != nil {
			return nil, err
		}
		if scope == nil {
			scope = p
		} else {
			scope = common(scope, p)
		}
	}
	if len(scope) == 0 {
		return td.OrgPath(org), nil
	}
	return scope, nil
}

// storedScope is a stored cohort's scope.
func storedScope(ctx context.Context, q *dbq.Queries, co dbq.PcFleetCohort) (td.Path, error) {
	var r *Rule
	if co.Rule != nil {
		r = &Rule{}
		if err := json.Unmarshal(co.Rule, r); err != nil {
			return nil, err
		}
	}
	return scopeOf(ctx, q, co.OrgID, co.ID, r)
}
