// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// ErrInvalidKind rejects an unknown environment kind.
var ErrInvalidKind = pcerr.New(pcerr.InvalidArgument, "INVALID_ENVIRONMENT_KIND", "kind must be DEVELOPMENT, STAGING or PRODUCTION")

// pathCache resolves environment paths, loading each parent team once.
type pathCache struct {
	c     Caller
	q     *dbq.Queries
	teams map[ids.UUID]dbq.PcTeam
}

func (pc *pathCache) env(ctx context.Context, e dbq.PcEnvironment) (td.Path, error) {
	if e.TeamID == nil {
		return td.OrgPath(pc.c.Org).Child(td.ScopeEnvironment, e.ID), nil
	}
	t, ok := pc.teams[*e.TeamID]
	if !ok {
		var err error
		if t, err = pc.q.GetTeam(ctx, pc.c.Org, *e.TeamID); err != nil {
			return nil, err // a missing parent is a broken foreign key: internal error
		}
		pc.teams[*e.TeamID] = t
	}
	return teamPath(pc.c.Org, t).Child(td.ScopeEnvironment, e.ID), nil
}

func newPathCache(c Caller, q *dbq.Queries) *pathCache {
	return &pathCache{c: c, q: q, teams: map[ids.UUID]dbq.PcTeam{}}
}

// environment loads an environment and checks p at its scope.
func environment(ctx context.Context, c Caller, q *dbq.Queries, id td.EnvironmentID, p td.Permission) (dbq.PcEnvironment, error) {
	r, err := q.GetEnvironment(ctx, c.Org, id.UUID())
	if err != nil {
		return r, notFound(err, ErrEnvironmentNotFound)
	}
	path, err := newPathCache(c, q).env(ctx, r)
	if err != nil {
		return r, err
	}
	return r, c.Require(p, path)
}

// CreateEnvironment creates an environment under the org or an active team.
func (h *Hierarchy) CreateEnvironment(ctx context.Context, teamID td.TeamID, kind td.EnvironmentKind, in NewEntity) (Environment, error) {
	in, err := in.check()
	if err != nil {
		return Environment{}, err
	}
	if !kind.Valid() {
		return Environment{}, ErrInvalidKind
	}
	var out Environment
	err = inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		path := td.OrgPath(c.Org)
		if !teamID.IsZero() {
			t, err := q.GetTeam(ctx, c.Org, teamID.UUID())
			if err != nil {
				return notFound(err, ErrTeamNotFound)
			}
			if state, err := q.ShareTeam(ctx, c.Org, t.ID); err != nil {
				return notFound(err, ErrTeamNotFound)
			} else if td.State(state) != td.Active {
				return ErrArchived
			}
			path = teamPath(c.Org, t)
		}
		if err := c.Require(td.PermEnvironmentManage, path); err != nil {
			return err
		}
		if err := checkEnvironmentLimit(ctx, h.ents, q, c.Org); err != nil {
			return err
		}
		r, err := q.InsertEnvironment(ctx, dbq.InsertEnvironmentParams{
			OrgID: c.Org, ID: ids.NewV7(), TeamID: optUUID(teamID), Slug: in.Slug, Name: in.Name,
			Description: in.Description, Kind: string(kind),
		})
		if db.IsUniqueViolation(err) {
			return ErrSlugTaken
		} else if err != nil {
			return err
		}
		out = environmentView(r)
		return record(ctx, tx, c, "tenancy.environment_created", "environment", r.ID,
			map[string]string{"slug": r.Slug, "kind": r.Kind})
	})
	return out, err
}

// GetEnvironment returns one environment.
func (h *Hierarchy) GetEnvironment(ctx context.Context, id td.EnvironmentID) (Environment, error) {
	var out Environment
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		r, err := environment(ctx, c, q, id, td.PermEnvironmentRead)
		out = environmentView(r)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListEnvironments lists the environments the caller may read, optionally
// of one team.
func (h *Hierarchy) ListEnvironments(ctx context.Context, pr page.Request, teamID td.TeamID, includeArchived bool) (Page[Environment], error) {
	var out Page[Environment]
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		rows, err := q.ListEnvironments(ctx, dbq.ListEnvironmentsParams{
			OrgID: c.Org, After: pr.After, TeamID: optUUID(teamID), IncludeArchived: includeArchived, PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcEnvironment) ids.UUID { return r.ID })
		paths := newPathCache(c, q)
		for _, r := range rows {
			path, err := paths.env(ctx, r)
			if err != nil {
				return err
			}
			if c.Can(td.PermEnvironmentRead, path) {
				out.Items = append(out.Items, environmentView(r))
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// UpdateEnvironment changes the name and/or description.
func (h *Hierarchy) UpdateEnvironment(ctx context.Context, id td.EnvironmentID, name, description *string) (Environment, error) {
	name, description, err := checkText(name, description)
	if err != nil {
		return Environment{}, err
	}
	var out Environment
	err = inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := environment(ctx, c, q, id, td.PermEnvironmentManage)
		if err != nil {
			return err
		}
		r, err = q.UpdateEnvironment(ctx, dbq.UpdateEnvironmentParams{OrgID: c.Org, ID: r.ID, Name: name, Description: description})
		if err != nil {
			return notFound(err, ErrArchived)
		}
		out = environmentView(r)
		return record(ctx, tx, c, "tenancy.environment_updated", "environment", r.ID, changed(name, description))
	})
	return out, err
}

// ArchiveEnvironment archives an environment.
func (h *Hierarchy) ArchiveEnvironment(ctx context.Context, id td.EnvironmentID) (Environment, error) {
	var out Environment
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := environment(ctx, c, q, id, td.PermEnvironmentManage)
		if err != nil {
			return err
		}
		r, err = q.ArchiveEnvironment(ctx, c.Org, r.ID)
		if err != nil {
			return notFound(err, ErrArchived)
		}
		out = environmentView(r)
		return record(ctx, tx, c, "tenancy.environment_archived", "environment", r.ID, nil)
	})
	return out, err
}
