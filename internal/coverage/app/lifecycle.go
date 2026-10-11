// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"slices"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Protection is what an agent's coverage says about it (F021, design
// decision 11): PROTECTED only when every scope that counts is ENFORCED
// now, PARTIALLY_PROTECTED when at least one is, OBSERVED otherwise. A
// scope a person excluded as a whole does not count (HR-212); an agent
// with no scope that counts is OBSERVED.
func Protection(states []domain.State, excluded []bool) adomain.State {
	enforced, counted := 0, 0
	for i, s := range states {
		if excluded[i] {
			continue
		}
		counted++
		if s == domain.Enforced {
			enforced++
		}
	}
	if enforced == 0 {
		return adomain.StateObserved
	}
	if enforced == counted {
		return adomain.StateProtected
	}
	return adomain.StatePartiallyProtected
}

// grantedScopes are the agent's scopes that count: every operation its
// active grants allow, on every connection whose pinned package defines it.
func grantedScopes(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent ids.UUID, pkgs packages) ([]domain.Scope, error) {
	rows, err := q.CoverageGrantBoundsOfAgent(ctx, org, agent)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	var bounds []gdomain.Bounds
	for _, raw := range rows {
		var b gdomain.Bounds
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, err
		}
		bounds = append(bounds, b)
	}
	allowed := func(op string) bool {
		return slices.ContainsFunc(bounds, func(b gdomain.Bounds) bool { return b.Operations == nil || b.Operations.Matches(op) })
	}
	conns, err := q.CoverageConnectionPackages(ctx, org)
	if err != nil {
		return nil, err
	}
	var out []domain.Scope
	for _, c := range conns {
		pkg, err := pkgs.get(ctx, q, org, c.VersionID)
		if err != nil {
			return nil, err
		}
		for _, d := range pkg.Definitions {
			sc := domain.Scope{Agent: agent, Connection: c.ID, Operation: d.Operation}
			if allowed(d.Operation) && !slices.Contains(out, sc) {
				out = append(out, sc)
			}
		}
	}
	return out, nil
}

// deriveLifecycle moves the agent among OBSERVED, PARTIALLY_PROTECTED and
// PROTECTED from the scopes its grants allow, each as it reads at now; a
// scope never assessed counts as not ENFORCED.
func (s *Service) deriveLifecycle(ctx context.Context, tx db.TenantTx, agent ids.UUID, now time.Time, pkgs packages) error {
	q := dbq.New(tx)
	scopes, err := grantedScopes(ctx, q, tx.OrgID(), agent, pkgs)
	if err != nil {
		return err
	}
	states := make([]domain.State, len(scopes))
	excluded := make([]bool, len(scopes))
	for i, sc := range scopes {
		row, err := q.CurrentCoverageSnapshot(ctx, dbq.CurrentCoverageSnapshotParams{
			OrgID: tx.OrgID(), AgentID: sc.Agent, ConnectionID: sc.Connection, Operation: sc.Operation,
		})
		if db.IsNoRows(err) {
			// Never assessed: not ENFORCED, unless a person excluded it whole.
			states[i] = domain.Unknown
			if excluded[i], err = wholeScopeExcluded(ctx, q, tx.OrgID(), sc); err != nil {
				return err
			}
			continue
		} else if err != nil {
			return err
		}
		r, err := s.record(ctx, tx, sc, &row, false, pkgs, now)
		if err != nil {
			return err
		}
		states[i], excluded[i] = r.State, r.Body.Excluded
	}
	return agents.MarkProtection(ctx, q, tx.OrgID(), agent, Protection(states, excluded), adomain.System)
}

// deriveAgents derives the protection of each agent of scopes once, after
// they were reassessed (design decision 11), so a change of grants or
// exclusions that recorded no snapshot still reaches the agent.
func (s *Service) deriveAgents(ctx context.Context, tx db.TenantTx, scopes []domain.Scope, now time.Time, pkgs packages) error {
	var done []ids.UUID
	for _, sc := range scopes {
		if slices.Contains(done, sc.Agent) {
			continue
		}
		done = append(done, sc.Agent)
		if err := s.deriveLifecycle(ctx, tx, sc.Agent, now, pkgs); err != nil {
			return err
		}
	}
	return nil
}

// wholeScopeExcluded reports whether an active exclusion covers the whole
// scope.
func wholeScopeExcluded(ctx context.Context, q *dbq.Queries, org ids.OrgID, sc domain.Scope) (bool, error) {
	rows, err := q.CoverageExclusionsForScope(ctx, dbq.CoverageExclusionsForScopeParams{
		OrgID: org, ConnectionID: sc.Connection, AgentID: &sc.Agent, Operation: sc.Operation,
	})
	return slices.ContainsFunc(rows, func(x dbq.PcCoverageExclusion) bool { return x.RouteKind == nil }), err
}
