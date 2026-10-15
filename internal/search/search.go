// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"errors"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// PermSearch is the permission every search needs (D4). Each entity also
// needs its own read permission where its rows live (entityPerm).
const PermSearch = td.PermSearchRead

// entityPerm is the permission that reads each entity's rows.
var entityPerm = map[Entity]td.Permission{
	EntityTransactions: td.PermEvidenceRead,
	EntityRuns:         td.PermRunRead,
	EntityAgents:       td.PermAgentRead,
	EntityGrants:       td.PermGrantRead,
	EntityGrantChanges: td.PermGrantRead,
	EntityConnections:  td.PermConnectionRead,
	EntityApprovals:    td.PermApprovalRead,
	EntityAudit:        td.PermAuditRead,
	EntityOperations:   td.PermPackageRead,
}

// orgLevel lists the entities that live at the org rather than at an
// agent's place.
var orgLevel = map[Entity]bool{EntityConnections: true, EntityAudit: true, EntityOperations: true}

// EmptyReason says why a result has no items (F627).
type EmptyReason string

// Empty reasons. RESTRICTED comes from the viewer's scope (it holds the
// entity's permission nowhere), never from hidden rows; NO_DATA_COLLECTED
// means nothing at all is recorded in the viewer's scope; NOTHING_IN_SCOPE
// means data exists in scope but none matches.
const (
	EmptyNothingInScope       EmptyReason = "NOTHING_IN_SCOPE"
	EmptyNoDataCollected      EmptyReason = "NO_DATA_COLLECTED"
	EmptyRestricted           EmptyReason = "RESTRICTED"
	omissionScopeLimited                  = "SCOPE_LIMITED"
	omissionRestricted                    = "RESTRICTED"
	omissionUnobservedUse                 = "UNOBSERVED_ROUTES"
	omissionUnknownDependents             = "UNKNOWN_DEPENDENCIES"
)

// Omission is a note about what a result cannot show, derived from the
// viewer's permissions or from what PantherClaw does not observe.
type Omission struct {
	Code   string
	Detail string
}

// Range is the evidence range a result covers. Changing marks a range that
// reaches the present: its results may still grow (F317).
type Range struct {
	Start, End *time.Time
	Changing   bool
}

// Item is one result row: scalar fields only, and links to the evidence
// that supports it ("<kind>:<id>").
type Item struct {
	Entity   Entity
	ID       string
	Time     time.Time
	Label    string
	Fields   map[string]string
	Evidence []string
}

// Result is one page of a search.
type Result struct {
	Items []Item
	Next  string
	// Count is the number of matching rows in the viewer's scope, at most
	// MaxCount; Capped says there are more.
	Count     int
	Capped    bool
	Scope     Scope
	Range     Range
	AsOf      time.Time
	Omissions []Omission
	Empty     EmptyReason
}

// Definitions reads the operations of an org's active packages.
type Definitions interface {
	ActiveDefinitionsInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) ([]*defs.Definition, error)
}

// Service runs searches, built-in queries and saved queries.
type Service struct {
	Pool  *db.Pool
	Defs  Definitions
	Clock clock.Clock
	// Exposure answers who_can_write and widest_exposure; nil: those
	// queries are not available (D49).
	Exposure ExposureReader
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return time.Now().UTC()
	}
	return s.Clock.Now().UTC()
}

// ErrNoDefinitions is returned when operations are searched without a
// definitions store (a wiring error).
var ErrNoDefinitions = errors.New("search: no definitions store")

// Search runs q under the caller's permissions.
func (s *Service) Search(ctx context.Context, q Query, pr page.Request) (Result, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Result{}, err
	}
	if !c.CanAnywhere(PermSearch) {
		return Result{}, td.ErrPermissionDenied(PermSearch)
	}
	if err := q.Validate(); err != nil {
		return Result{}, err
	}
	var out Result
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = s.run(ctx, c, tx, q, pr)
		return err
	}, db.ReadOnly())
	return out, err
}

// run executes a validated query in tx.
func (s *Service) run(ctx context.Context, c tenancy.Caller, tx db.TenantTx, q Query, pr page.Request) (Result, error) {
	if pr.Size <= 0 || pr.Size > page.Max {
		pr.Size = page.Default
	}
	dq := dbq.New(tx)
	perm := entityPerm[q.Entity]
	var sc Scope
	if orgLevel[q.Entity] {
		sc = orgScope(c, perm)
	} else {
		var err error
		if sc, err = AgentScope(ctx, c, dq, perm); err != nil {
			return Result{}, err
		}
	}
	asOf := s.now()
	out := Result{Scope: sc, AsOf: asOf, Range: rangeOf(q.Filters, asOf)}
	switch {
	case sc.Restricted:
		out.Omissions = append(out.Omissions, Omission{
			Code:   omissionRestricted,
			Detail: "you do not hold " + string(perm) + " anywhere in this org",
		})
	case !sc.All:
		out.Omissions = append(out.Omissions, Omission{
			Code:   omissionScopeLimited,
			Detail: "results cover only the agents where you hold " + string(perm),
		})
	}
	if sc.Restricted {
		out.Empty = EmptyRestricted
		return out, nil
	}
	r := runners[q.Entity]
	items, next, err := r.page(ctx, s, c, tx, sc, q.Filters, pr)
	if err != nil {
		return Result{}, err
	}
	n, err := r.count(ctx, s, c, tx, sc, q.Filters)
	if err != nil {
		return Result{}, err
	}
	out.Items, out.Next = items, next
	out.Count, out.Capped = min(n, MaxCount), n > MaxCount
	if len(items) == 0 && pr.After.IsZero() {
		out.Empty = EmptyNothingInScope
		all, err := r.count(ctx, s, c, tx, sc, Filters{})
		if err != nil {
			return Result{}, err
		}
		if all == 0 {
			out.Empty = EmptyNoDataCollected
		}
	}
	return out, nil
}

// rangeOf is the evidence range of f as of asOf: a range without an end, or
// ending within liveLag of asOf, is still changing.
func rangeOf(f Filters, asOf time.Time) Range {
	r := Range{Start: f.Start, End: f.End}
	r.Changing = f.End == nil || f.End.After(asOf.Add(-liveLag))
	return r
}
