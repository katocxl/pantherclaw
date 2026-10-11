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
// scope with an exclusion counts as not protected, whatever its state:
// exclusions never raise (HR-212, design decision 1 as the founder
// decided), so an agent with one is PARTIALLY_PROTECTED at most. An agent
// with no scope that counts is OBSERVED.
func Protection(states []domain.State, excluded []bool) adomain.State {
	enforced := 0
	for i, s := range states {
		if s == domain.Enforced && !excluded[i] {
			enforced++
		}
	}
	if enforced == 0 {
		return adomain.StateObserved
	}
	if enforced == len(states) {
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
			states[i] = domain.Unknown // never assessed: not ENFORCED
			continue
		} else if err != nil {
			return err
		}
		r, err := s.record(ctx, tx, sc, &row, false, pkgs, now)
		if err != nil {
			return err
		}
		states[i], excluded[i] = r.State, len(r.Body.Exclusions) > 0
	}
	return agents.MarkProtection(ctx, q, tx.OrgID(), agent, Protection(states, excluded), adomain.System)
}

// scopeAgents lists the agents of scopes.
func scopeAgents(scopes []domain.Scope) []ids.UUID {
	out := make([]ids.UUID, 0, len(scopes))
	for _, sc := range scopes {
		out = append(out, sc.Agent)
	}
	return out
}

// deriveAgents derives the protection of each of agents once, after their
// scopes were reassessed (design decision 11), so a change of grants or
// exclusions that recorded no snapshot still reaches the agent.
func (s *Service) deriveAgents(ctx context.Context, tx db.TenantTx, agents []ids.UUID, now time.Time, pkgs packages) error {
	var done []ids.UUID
	for _, a := range agents {
		if slices.Contains(done, a) {
			continue
		}
		done = append(done, a)
		if err := s.deriveLifecycle(ctx, tx, a, now, pkgs); err != nil {
			return err
		}
	}
	return nil
}
