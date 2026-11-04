// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"context"
	"strings"

	"github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the hierarchy use cases. Ids of other orgs are NotFound, never
// a more specific error (RLS hides them).
var (
	ErrOrgNotFound          = pcerr.New(pcerr.NotFound, "ORG_NOT_FOUND", "organization not found")
	ErrBusinessUnitNotFound = pcerr.New(pcerr.NotFound, "BUSINESS_UNIT_NOT_FOUND", "business unit not found")
	ErrTeamNotFound         = pcerr.New(pcerr.NotFound, "TEAM_NOT_FOUND", "team not found")
	ErrEnvironmentNotFound  = pcerr.New(pcerr.NotFound, "ENVIRONMENT_NOT_FOUND", "environment not found")
	ErrUserNotFound         = pcerr.New(pcerr.NotFound, "USER_NOT_FOUND", "user not found")
	ErrMemberNotFound       = pcerr.New(pcerr.NotFound, "MEMBER_NOT_FOUND", "user is not a member of the team")
	ErrSlugTaken            = pcerr.New(pcerr.AlreadyExists, "SLUG_TAKEN", "slug already in use")
	ErrAlreadyMember        = pcerr.New(pcerr.AlreadyExists, "ALREADY_MEMBER", "user is already a member of the team")
	ErrArchived             = pcerr.New(pcerr.FailedPrecondition, "ARCHIVED", "archived: it cannot be changed and nothing can be attached to it")
	ErrNotEmpty             = pcerr.New(pcerr.FailedPrecondition, "NOT_EMPTY", "archive its active children first")
	ErrUserDisabled         = pcerr.New(pcerr.FailedPrecondition, "USER_DISABLED", "user is disabled")
	ErrEditionRequired      = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "business units need the Business or Enterprise edition")
)

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(context.Context) (domain.Entitlements, error)
}

// Hierarchy implements the TenancyService use cases.
type Hierarchy struct {
	pool *db.Pool
	ents Entitlements
}

// NewHierarchy returns the hierarchy use cases.
func NewHierarchy(pool *db.Pool, ents Entitlements) *Hierarchy {
	return &Hierarchy{pool: pool, ents: ents}
}

// inOrg runs fn in a tenant transaction for the caller's org.
func inOrg(ctx context.Context, pool *db.Pool, fn func(context.Context, Caller, *dbq.Queries, db.TenantTx) error, opts ...db.TxOption) error {
	c, err := CallerFrom(ctx)
	if err != nil {
		return err
	}
	return pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, c, dbq.New(tx), tx)
	}, opts...)
}

// record audits a change made by c in tx (F585).
func record(ctx context.Context, tx db.TenantTx, c Caller, name, objType string, objID ids.UUID, details map[string]string) error {
	if details == nil {
		details = map[string]string{}
	}
	if c.Credential != "" {
		details["via"] = string(c.Credential)
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: objType, ID: objID.String()}, Details: details,
	})
	return err
}

// notFound maps "no row" to the given NotFound error.
func notFound(err, nf error) error {
	if db.IsNoRows(err) {
		return nf
	}
	return err
}

// changed lists the fields an update sets, for the audit record.
func changed(name, description *string) map[string]string {
	var f []string
	if name != nil {
		f = append(f, "name")
	}
	if description != nil {
		f = append(f, "description")
	}
	return map[string]string{"fields": strings.Join(f, ",")}
}

// checkText validates optional update fields.
func checkText(name, description *string) (*string, *string, error) {
	if name != nil {
		n, err := td.CheckName("name", *name)
		if err != nil {
			return nil, nil, err
		}
		name = &n
	}
	if description != nil {
		d, err := td.CheckDescription(*description)
		if err != nil {
			return nil, nil, err
		}
		description = &d
	}
	return name, description, nil
}

// NewEntity is the input to create a business unit, team or environment.
type NewEntity struct {
	Slug, Name, Description string
}

func (n NewEntity) check() (NewEntity, error) {
	if err := td.CheckSlug("slug", n.Slug); err != nil {
		return n, err
	}
	var err error
	if n.Name, err = td.CheckName("name", n.Name); err != nil {
		return n, err
	}
	n.Description, err = td.CheckDescription(n.Description)
	return n, err
}

// GetOrg returns the caller's org. Any principal that may read the org
// somewhere may read its name.
func (h *Hierarchy) GetOrg(ctx context.Context) (Org, error) {
	var out Org
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		if !c.CanAnywhere(td.PermOrgRead) {
			return td.ErrPermissionDenied(td.PermOrgRead)
		}
		r, err := q.GetOrg(ctx, c.Org)
		if err != nil {
			return notFound(err, ErrOrgNotFound)
		}
		out = orgView(r)
		return nil
	}, db.ReadOnly())
	return out, err
}

// UpdateOrg renames the caller's org.
func (h *Hierarchy) UpdateOrg(ctx context.Context, name string) (Org, error) {
	name, err := td.CheckName("name", name)
	if err != nil {
		return Org{}, err
	}
	var out Org
	err = inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermOrgUpdate, td.OrgPath(c.Org)); err != nil {
			return err
		}
		r, err := q.UpdateOrgName(ctx, name, c.Org)
		if err != nil {
			return notFound(err, ErrArchived)
		}
		out = orgView(r)
		return record(ctx, tx, c, auditkind.TenancyOrgUpdated, "org", c.Org.UUID(), map[string]string{"fields": "name"})
	})
	return out, err
}

// CreateBusinessUnit creates a business unit (Business edition).
func (h *Hierarchy) CreateBusinessUnit(ctx context.Context, in NewEntity) (BusinessUnit, error) {
	in, err := in.check()
	if err != nil {
		return BusinessUnit{}, err
	}
	ent, err := h.ents.Current(ctx)
	if err != nil {
		return BusinessUnit{}, err
	}
	if !ent.BusinessUnits() {
		return BusinessUnit{}, ErrEditionRequired
	}
	var out BusinessUnit
	err = inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		if err := c.Require(td.PermBusinessUnitManage, td.OrgPath(c.Org)); err != nil {
			return err
		}
		r, err := q.InsertBusinessUnit(ctx, dbq.InsertBusinessUnitParams{
			OrgID: c.Org, ID: ids.NewV7(), Slug: in.Slug, Name: in.Name, Description: in.Description,
		})
		if db.IsUniqueViolation(err) {
			return ErrSlugTaken
		} else if err != nil {
			return err
		}
		out = businessUnitView(r)
		return record(ctx, tx, c, auditkind.TenancyBusinessUnitCreated, "business_unit", r.ID, map[string]string{"slug": r.Slug})
	})
	return out, err
}

// GetBusinessUnit returns one business unit.
func (h *Hierarchy) GetBusinessUnit(ctx context.Context, id td.BusinessUnitID) (BusinessUnit, error) {
	var out BusinessUnit
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		r, err := q.GetBusinessUnit(ctx, c.Org, id.UUID())
		if err != nil {
			return notFound(err, ErrBusinessUnitNotFound)
		}
		if err := c.Require(td.PermBusinessUnitRead, businessUnitPath(c.Org, r.ID)); err != nil {
			return err
		}
		out = businessUnitView(r)
		return nil
	}, db.ReadOnly())
	return out, err
}

// ListBusinessUnits lists the business units the caller may read.
func (h *Hierarchy) ListBusinessUnits(ctx context.Context, pr page.Request, includeArchived bool) (Page[BusinessUnit], error) {
	var out Page[BusinessUnit]
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, _ db.TenantTx) error {
		rows, err := q.ListBusinessUnits(ctx, dbq.ListBusinessUnitsParams{
			OrgID: c.Org, After: pr.After, IncludeArchived: includeArchived, PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcBusinessUnit) ids.UUID { return r.ID })
		for _, r := range rows {
			if c.Can(td.PermBusinessUnitRead, businessUnitPath(c.Org, r.ID)) {
				out.Items = append(out.Items, businessUnitView(r))
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// UpdateBusinessUnit changes the name and/or description.
func (h *Hierarchy) UpdateBusinessUnit(ctx context.Context, id td.BusinessUnitID, name, description *string) (BusinessUnit, error) {
	name, description, err := checkText(name, description)
	if err != nil {
		return BusinessUnit{}, err
	}
	var out BusinessUnit
	err = inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := q.GetBusinessUnit(ctx, c.Org, id.UUID())
		if err != nil {
			return notFound(err, ErrBusinessUnitNotFound)
		}
		if err := c.Require(td.PermBusinessUnitManage, businessUnitPath(c.Org, r.ID)); err != nil {
			return err
		}
		r, err = q.UpdateBusinessUnit(ctx, dbq.UpdateBusinessUnitParams{OrgID: c.Org, ID: r.ID, Name: name, Description: description})
		if err != nil {
			return notFound(err, ErrArchived)
		}
		out = businessUnitView(r)
		return record(ctx, tx, c, auditkind.TenancyBusinessUnitUpdated, "business_unit", r.ID, changed(name, description))
	})
	return out, err
}

// ArchiveBusinessUnit archives a business unit without active teams. The
// row is locked first, so a concurrent CreateTeam (which shares the lock)
// either finishes before the count or sees the unit archived.
func (h *Hierarchy) ArchiveBusinessUnit(ctx context.Context, id td.BusinessUnitID) (BusinessUnit, error) {
	var out BusinessUnit
	err := inOrg(ctx, h.pool, func(ctx context.Context, c Caller, q *dbq.Queries, tx db.TenantTx) error {
		r, err := q.GetBusinessUnit(ctx, c.Org, id.UUID())
		if err != nil {
			return notFound(err, ErrBusinessUnitNotFound)
		}
		if err := c.Require(td.PermBusinessUnitManage, businessUnitPath(c.Org, r.ID)); err != nil {
			return err
		}
		if state, err := q.LockBusinessUnit(ctx, c.Org, r.ID); err != nil {
			return notFound(err, ErrBusinessUnitNotFound)
		} else if td.State(state) != td.Active {
			return ErrArchived
		}
		if n, err := q.CountActiveTeamsInBusinessUnit(ctx, c.Org, &r.ID); err != nil {
			return err
		} else if n > 0 {
			return ErrNotEmpty
		}
		r, err = q.ArchiveBusinessUnit(ctx, c.Org, r.ID)
		if err != nil {
			return notFound(err, ErrArchived)
		}
		out = businessUnitView(r)
		return record(ctx, tx, c, auditkind.TenancyBusinessUnitArchived, "business_unit", r.ID, nil)
	})
	return out, err
}
