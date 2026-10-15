// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Visibility says who may see and run a saved query. Whoever runs it, it
// runs under their own permissions: sharing never widens (HR-257).
type Visibility string

// Visibilities.
const (
	Private Visibility = "PRIVATE"
	Team    Visibility = "TEAM"
	Org     Visibility = "ORG"
)

// Spec is what a saved query stores: exactly one structured query or one
// built-in query with its parameters. Never results, never SQL.
type Spec struct {
	Query   *Query        `json:"query,omitzero"`
	Builtin *BuiltinQuery `json:"builtin,omitzero"`
}

// maxSpecBytes matches the table's bound.
const maxSpecBytes = 8192

// Validate checks that s names exactly one valid query.
func (s Spec) Validate() error {
	switch {
	case (s.Query == nil) == (s.Builtin == nil):
		return ErrInvalidQuery("a saved query holds one query or one built-in query")
	case s.Query != nil:
		return s.Query.Validate()
	default:
		q, _, err := s.Builtin.expand(time.Now())
		if err != nil {
			return err
		}
		return q.Validate()
	}
}

// SavedQuery is a saved query as its viewer sees it.
type SavedQuery struct {
	ID          ids.UUID
	Owner       string
	Name        string
	Description string
	Visibility  Visibility
	Team        *ids.UUID
	Spec        Spec
	Created     time.Time
	Updated     time.Time
	// Mine reports whether the viewer owns it (and may change it).
	Mine bool
}

// SaveInput creates or replaces a saved query.
type SaveInput struct {
	Name        string
	Description string
	Visibility  Visibility
	Team        *ids.UUID
	Spec        Spec
}

// Errors.
var (
	ErrSavedQueryNotFound = pcerr.New(pcerr.NotFound, "SAVED_QUERY_NOT_FOUND", "saved query not found")
	ErrSavedQueryExists   = pcerr.New(pcerr.AlreadyExists, "SAVED_QUERY_EXISTS", "you already have a saved query with this name")
)

func (in SaveInput) validate() error {
	name := strings.TrimSpace(in.Name)
	switch {
	case name == "" || len([]rune(name)) > 120:
		return ErrInvalidQuery("name must be 1 to 120 characters")
	case len([]rune(in.Description)) > 500:
		return ErrInvalidQuery("description must be at most 500 characters")
	case in.Visibility != Private && in.Visibility != Team && in.Visibility != Org:
		return ErrInvalidQuery("visibility must be PRIVATE, TEAM or ORG")
	case (in.Visibility == Team) != (in.Team != nil):
		return ErrInvalidQuery("a team is given exactly for TEAM visibility")
	}
	return in.Spec.Validate()
}

// visibleTeams returns the teams where c holds search.read: a TEAM query
// shared with one of them is visible to c.
func visibleTeams(ctx context.Context, c tenancy.Caller, q *dbq.Queries) ([]ids.UUID, error) {
	rows, err := q.SavedQueryTeams(ctx, c.Org)
	if err != nil {
		return nil, err
	}
	out := []ids.UUID{}
	for _, r := range rows {
		if c.Can(PermSearch, teamPath(c.Org, r.ID, r.BusinessUnitID)) {
			out = append(out, r.ID)
		}
	}
	return out, nil
}

func teamPath(org ids.OrgID, team ids.UUID, bu *ids.UUID) td.Path {
	p := td.OrgPath(org)
	if bu != nil {
		p = p.Child(td.ScopeBusinessUnit, *bu)
	}
	return p.Child(td.ScopeTeam, team)
}

// searcher returns the caller once it holds search.read somewhere.
func searcher(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	if !c.CanAnywhere(PermSearch) {
		return tenancy.Caller{}, td.ErrPermissionDenied(PermSearch)
	}
	return c, nil
}

// checkTeam refuses sharing with a team where c does not hold search.read.
func checkTeam(ctx context.Context, c tenancy.Caller, q *dbq.Queries, in SaveInput) error {
	if in.Team == nil {
		return nil
	}
	teams, err := visibleTeams(ctx, c, q)
	if err != nil {
		return err
	}
	if !slices.Contains(teams, *in.Team) {
		return td.ErrPermissionDenied(PermSearch)
	}
	return nil
}

func (c savedRow) view(viewer string) (SavedQuery, error) {
	var spec Spec
	if err := json.Unmarshal(c.Spec, &spec); err != nil {
		return SavedQuery{}, err
	}
	return SavedQuery{
		ID: c.ID, Owner: c.Owner, Name: c.Name, Description: c.Description, Visibility: Visibility(c.Visibility),
		Team: c.TeamID, Spec: spec, Created: c.CreatedAt, Updated: c.UpdatedAt, Mine: c.Owner == viewer,
	}, nil
}

type savedRow dbq.PcSavedQuery

// visible reports whether c may see r.
func visible(ctx context.Context, c tenancy.Caller, q *dbq.Queries, r dbq.PcSavedQuery) (bool, error) {
	switch Visibility(r.Visibility) {
	case Org:
		return true, nil
	case Team:
		teams, err := visibleTeams(ctx, c, q)
		if err != nil {
			return false, err
		}
		return r.TeamID != nil && slices.Contains(teams, *r.TeamID), nil
	case Private:
		return r.Owner == c.Principal.String(), nil
	default:
		return false, nil
	}
}

// Save creates a saved query owned by the caller.
func (s *Service) Save(ctx context.Context, in SaveInput) (SavedQuery, error) {
	c, err := searcher(ctx)
	if err != nil {
		return SavedQuery{}, err
	}
	if err := in.validate(); err != nil {
		return SavedQuery{}, err
	}
	spec, err := json.Marshal(in.Spec)
	if err != nil {
		return SavedQuery{}, err
	}
	if len(spec) > maxSpecBytes {
		return SavedQuery{}, ErrInvalidQuery("query is too large")
	}
	var out SavedQuery
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := checkTeam(ctx, c, q, in); err != nil {
			return err
		}
		r, err := q.InsertSavedQuery(ctx, dbq.InsertSavedQueryParams{
			OrgID: c.Org, ID: ids.NewV7(), Owner: c.Principal.String(), Name: strings.TrimSpace(in.Name),
			Description: in.Description, Visibility: string(in.Visibility), TeamID: in.Team, Spec: spec,
		})
		if db.IsUniqueViolation(err) {
			return ErrSavedQueryExists
		} else if err != nil {
			return err
		}
		out, err = savedRow(r).view(c.Principal.String())
		return err
	})
	return out, err
}

// Update replaces a saved query the caller owns.
func (s *Service) Update(ctx context.Context, id ids.UUID, in SaveInput) (SavedQuery, error) {
	c, err := searcher(ctx)
	if err != nil {
		return SavedQuery{}, err
	}
	if err := in.validate(); err != nil {
		return SavedQuery{}, err
	}
	spec, err := json.Marshal(in.Spec)
	if err != nil {
		return SavedQuery{}, err
	}
	if len(spec) > maxSpecBytes {
		return SavedQuery{}, ErrInvalidQuery("query is too large")
	}
	var out SavedQuery
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := checkTeam(ctx, c, q, in); err != nil {
			return err
		}
		r, err := q.UpdateSavedQuery(ctx, dbq.UpdateSavedQueryParams{
			OrgID: c.Org, ID: id, Owner: c.Principal.String(), Name: strings.TrimSpace(in.Name),
			Description: in.Description, Visibility: string(in.Visibility), TeamID: in.Team, Spec: spec,
		})
		switch {
		case db.IsNoRows(err):
			return ErrSavedQueryNotFound
		case db.IsUniqueViolation(err):
			return ErrSavedQueryExists
		case err != nil:
			return err
		}
		out, err = savedRow(r).view(c.Principal.String())
		return err
	})
	return out, err
}

// Delete removes a saved query the caller owns.
func (s *Service) Delete(ctx context.Context, id ids.UUID) error {
	c, err := searcher(ctx)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := dbq.New(tx).DeleteSavedQuery(ctx, c.Org, id, c.Principal.String())
		if err == nil && n == 0 {
			return ErrSavedQueryNotFound
		}
		return err
	})
}

// Get returns a saved query the caller may see.
func (s *Service) Get(ctx context.Context, id ids.UUID) (SavedQuery, error) {
	c, err := searcher(ctx)
	if err != nil {
		return SavedQuery{}, err
	}
	var out SavedQuery
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.get(ctx, c, dbq.New(tx), id)
		return err
	}, db.ReadOnly())
	return out, err
}

func (s *Service) get(ctx context.Context, c tenancy.Caller, q *dbq.Queries, id ids.UUID) (SavedQuery, error) {
	r, err := q.GetSavedQuery(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return SavedQuery{}, ErrSavedQueryNotFound
	} else if err != nil {
		return SavedQuery{}, err
	}
	ok, err := visible(ctx, c, q, r)
	if err != nil {
		return SavedQuery{}, err
	}
	if !ok {
		return SavedQuery{}, ErrSavedQueryNotFound
	}
	return savedRow(r).view(c.Principal.String())
}

// SavedPage is one page of saved queries.
type SavedPage struct {
	Items []SavedQuery
	Next  string
}

// List lists the saved queries the caller may see, newest first: its own,
// the org's, and those shared with teams where it holds search.read.
func (s *Service) List(ctx context.Context, pr page.Request) (SavedPage, error) {
	c, err := searcher(ctx)
	if err != nil {
		return SavedPage{}, err
	}
	if pr.Size <= 0 || pr.Size > page.Max {
		pr.Size = page.Default
	}
	var out SavedPage
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		teams, err := visibleTeams(ctx, c, q)
		if err != nil {
			return err
		}
		rows, err := q.ListSavedQueries(ctx, dbq.ListSavedQueriesParams{
			OrgID: c.Org, Owner: c.Principal.String(), Teams: teams, Before: before(pr), PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcSavedQuery) ids.UUID { return r.ID })
		for _, r := range rows {
			v, err := savedRow(r).view(c.Principal.String())
			if err != nil {
				return err
			}
			out.Items = append(out.Items, v)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// RunSaved runs a saved query the caller may see, under the caller's own
// permissions: whoever saved or shared it, nothing beyond the viewer's
// scope is read or counted (HR-257).
func (s *Service) RunSaved(ctx context.Context, id ids.UUID, pr page.Request) (Result, error) {
	sq, err := s.Get(ctx, id)
	if err != nil {
		return Result{}, err
	}
	if sq.Spec.Builtin != nil {
		return s.RunBuiltin(ctx, *sq.Spec.Builtin, pr)
	}
	return s.Search(ctx, *sq.Spec.Query, pr)
}

// CanSearch returns nil when the caller holds search.read somewhere.
func (s *Service) CanSearch(ctx context.Context) error {
	_, err := searcher(ctx)
	return err
}
