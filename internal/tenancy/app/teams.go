// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// CreateTeam creates a team under the org or an active business unit.
func (h *Hierarchy) CreateTeam(ctx context.Context, bu td.BusinessUnitID, in NewEntity) (Team, error) {
	in, err := in.check()
	if err != nil {
		return Team{}, err
	}
	var out Team
	err = inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		path := td.OrgPath(c.Org)
		if !bu.IsZero() {
			state, err := q.ShareBusinessUnit(ctx, c.Org, bu.UUID())
			if err != nil {
				return notFound(err, ErrBusinessUnitNotFound)
			}
			if td.State(state) != td.Active {
				return ErrArchived
			}
			path = businessUnitPath(c.Org, bu.UUID())
		}
		if err := c.Require(td.PermTeamManage, path); err != nil {
			return err
		}
		r, err := q.InsertTeam(ctx, dbq.InsertTeamParams{
			OrgID: c.Org, ID: ids.NewV7(), BusinessUnitID: optUUID(bu), Slug: in.Slug, Name: in.Name, Description: in.Description,
		})
		if db.IsUniqueViolation(err) {
			return ErrSlugTaken
		} else if err != nil {
			return err
		}
		out = teamView(r)
		return record(ctx, tx, c, auditkind.TenancyTeamCreated, "team", r.ID, map[string]string{"slug": r.Slug})
	})
	return out, err
}

// team loads a team and checks p at its scope.
func team(ctx context.Context, c Caller, q *dbq.Queries, id td.TeamID, p td.Permission) (dbq.PcTeam, error) {
	r, err := q.GetTeam(ctx, c.Org, id.UUID())
	if err != nil {
		return r, notFound(err, ErrTeamNotFound)
	}
	return r, c.Require(p, teamPath(c.Org, r))
}

// GetTeam returns one team.
func (h *Hierarchy) GetTeam(ctx context.Context, id td.TeamID) (Team, error) {
	var out Team
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		r, err := team(ctx, c, q, id, td.PermTeamRead)
		out = teamView(r)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListTeams lists the teams the caller may read, optionally of one business
// unit.
func (h *Hierarchy) ListTeams(ctx context.Context, pr page.Request, bu td.BusinessUnitID, includeArchived bool) (Page[Team], error) {
	var out Page[Team]
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		rows, err := q.ListTeams(ctx, dbq.ListTeamsParams{
			OrgID: c.Org, After: pr.After, BusinessUnitID: optUUID(bu), IncludeArchived: includeArchived, PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcTeam) ids.UUID { return r.ID })
		for _, r := range rows {
			if c.Can(td.PermTeamRead, teamPath(c.Org, r)) {
				out.Items = append(out.Items, teamView(r))
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// UpdateTeam changes the name and/or description.
func (h *Hierarchy) UpdateTeam(ctx context.Context, id td.TeamID, name, description *string) (Team, error) {
	name, description, err := checkText(name, description)
	if err != nil {
		return Team{}, err
	}
	var out Team
	err = inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := team(ctx, c, q, id, td.PermTeamManage)
		if err != nil {
			return err
		}
		r, err = q.UpdateTeam(ctx, dbq.UpdateTeamParams{OrgID: c.Org, ID: r.ID, Name: name, Description: description})
		if err != nil {
			return notFound(err, ErrArchived)
		}
		out = teamView(r)
		return record(ctx, tx, c, auditkind.TenancyTeamUpdated, "team", r.ID, changed(name, description))
	})
	return out, err
}

// ArchiveTeam archives a team without active environments (row locked
// first, as for business units).
func (h *Hierarchy) ArchiveTeam(ctx context.Context, id td.TeamID) (Team, error) {
	var out Team
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := team(ctx, c, q, id, td.PermTeamManage)
		if err != nil {
			return err
		}
		if state, err := q.LockTeam(ctx, c.Org, r.ID); err != nil {
			return notFound(err, ErrTeamNotFound)
		} else if td.State(state) != td.Active {
			return ErrArchived
		}
		if n, err := q.CountActiveEnvironmentsInTeam(ctx, c.Org, &r.ID); err != nil {
			return err
		} else if n > 0 {
			return ErrNotEmpty
		}
		r, err = q.ArchiveTeam(ctx, c.Org, r.ID)
		if err != nil {
			return notFound(err, ErrArchived)
		}
		out = teamView(r)
		return record(ctx, tx, c, auditkind.TenancyTeamArchived, "team", r.ID, nil)
	})
	return out, err
}

// AddTeamMember adds an active user to an active team.
func (h *Hierarchy) AddTeamMember(ctx context.Context, teamID td.TeamID, user td.UserID) (TeamMember, error) {
	var out TeamMember
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		t, err := team(ctx, c, q, teamID, td.PermTeamMembersManage)
		if err != nil {
			return err
		}
		if state, err := q.ShareTeam(ctx, c.Org, t.ID); err != nil {
			return notFound(err, ErrTeamNotFound)
		} else if td.State(state) != td.Active {
			return ErrArchived
		}
		u, err := q.ShareUser(ctx, c.Org, user.UUID())
		if err != nil {
			return notFound(err, ErrUserNotFound)
		}
		if td.AccountState(u.State) != td.Enabled {
			return ErrUserDisabled
		}
		added, err := q.InsertMembership(ctx, dbq.InsertMembershipParams{OrgID: c.Org, ID: ids.NewV7(), TeamID: t.ID, UserID: u.ID})
		if db.IsUniqueViolation(err) {
			return ErrAlreadyMember
		} else if err != nil {
			return err
		}
		out = TeamMember{User: user, Email: u.Email, DisplayName: u.DisplayName, AddedAt: added}
		return record(ctx, tx, c, auditkind.TenancyTeamMemberAdded, "team", t.ID, map[string]string{"user": u.ID.String()})
	})
	return out, err
}

// RemoveTeamMember removes a user from a team.
func (h *Hierarchy) RemoveTeamMember(ctx context.Context, teamID td.TeamID, user td.UserID) error {
	return inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		t, err := team(ctx, c, q, teamID, td.PermTeamMembersManage)
		if err != nil {
			return err
		}
		n, err := q.DeleteMembership(ctx, c.Org, t.ID, user.UUID())
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrMemberNotFound
		}
		return record(ctx, tx, c, auditkind.TenancyTeamMemberRemoved, "team", t.ID, map[string]string{"user": user.String()})
	})
}

// ListTeamMembers lists a team's members.
func (h *Hierarchy) ListTeamMembers(ctx context.Context, teamID td.TeamID, pr page.Request) (Page[TeamMember], error) {
	var out Page[TeamMember]
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		t, err := team(ctx, c, q, teamID, td.PermTeamRead)
		if err != nil {
			return err
		}
		rows, err := q.ListTeamMembers(ctx, dbq.ListTeamMembersParams{OrgID: c.Org, TeamID: t.ID, After: pr.After, PageLimit: pr.Limit()})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListTeamMembersRow) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, TeamMember{
				User: idOf[td.User](r.UserID), Email: r.Email, DisplayName: r.DisplayName, AddedAt: r.CreatedAt,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
