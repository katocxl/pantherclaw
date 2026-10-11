// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// readers answers whether the caller holds coverage.read over an agent;
// a nil agent (a route of every agent of a connection) needs it at org
// scope. Paths are looked up once per agent.
type readers struct {
	c     tenancy.Caller
	q     *dbq.Queries
	paths map[ids.UUID]td.Path
}

func (r *readers) can(ctx context.Context, agent *ids.UUID) (bool, error) {
	if agent == nil {
		return r.c.Can(td.PermCoverageRead, td.OrgPath(r.c.Org)), nil
	}
	path, ok := r.paths[*agent]
	if !ok {
		a, err := r.q.GetAgent(ctx, r.c.Org, *agent)
		if err != nil {
			return false, err
		}
		if path, err = agents.PathOf(ctx, r.q, a); err != nil {
			return false, err
		}
		r.paths[*agent] = path
	}
	return r.c.Can(td.PermCoverageRead, path), nil
}

// read runs fn read-only in the caller's org, for a caller holding
// coverage.read somewhere.
func (s *Service) read(ctx context.Context, fn func(context.Context, *readers) error) error {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return err
	}
	if !c.CanAnywhere(td.PermCoverageRead) {
		return td.ErrPermissionDenied(td.PermCoverageRead)
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, &readers{c: c, q: dbq.New(tx), paths: map[ids.UUID]td.Path{}})
	}, db.ReadOnly())
}

// Closure is a recorded closure with what its probes prove.
type Closure struct {
	dbq.PcCoverageClosure
	Probes  []domain.ProbeResult
	Verdict domain.Verdict
}

func closureOf(row dbq.PcCoverageClosure) (Closure, error) {
	c := Closure{PcCoverageClosure: row}
	if err := json.Unmarshal(row.Probes, &c.Probes); err != nil {
		return Closure{}, err
	}
	c.Verdict = domain.Evaluate(c.Probes)
	return c, nil
}

// GetClosure returns one closure (F457).
func (s *Service) GetClosure(ctx context.Context, id ids.UUID) (Closure, error) {
	var out Closure
	err := s.read(ctx, func(ctx context.Context, r *readers) error {
		row, err := r.q.GetCoverageClosure(ctx, r.c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if ok, err := r.can(ctx, &row.AgentID); err != nil || !ok {
			return orNotFound(err)
		}
		out, err = closureOf(row)
		return err
	})
	return out, err
}

// Filter narrows a list to one agent and/or connection.
type Filter struct {
	Agent, Connection *ids.UUID
}

// ListClosures lists closures newest first, the ones the caller may read.
func (s *Service) ListClosures(ctx context.Context, f Filter, size int32, token string) ([]Closure, string, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []Closure
	var next string
	err = s.read(ctx, func(ctx context.Context, r *readers) error {
		rows, err := r.q.ListCoverageClosuresPage(ctx, dbq.ListCoverageClosuresPageParams{
			OrgID: r.c.Org, ConnectionID: f.Connection, AgentID: f.Agent, Before: before(p), MaxRows: p.Limit(),
		})
		if err != nil {
			return err
		}
		rows, next = page.Finish(p, rows, func(x dbq.PcCoverageClosure) ids.UUID { return x.ID })
		for _, row := range rows {
			if ok, err := r.can(ctx, &row.AgentID); err != nil {
				return err
			} else if ok {
				c, err := closureOf(row)
				if err != nil {
					return err
				}
				out = append(out, c)
			}
		}
		return nil
	})
	return out, next, err
}

func before(p page.Request) *ids.UUID {
	if p.After.IsZero() {
		return nil
	}
	return &p.After
}

// orNotFound hides what the caller may not read.
func orNotFound(err error) error {
	if err != nil {
		return err
	}
	return ErrNotFound
}
