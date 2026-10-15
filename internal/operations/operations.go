// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package operations is the Operations surface (G0 M10 D33; F211, F212,
// F219; HR-258): the ranked work queue, the scope- and time-stamped
// summary and the evidence status of each telemetry source.
//
// Every read runs under the viewer's permissions. Rows are filtered by the
// viewer's scope before they are ranked or counted (D8): an item about
// agents is shown only when every one of them is in the viewer's scope for
// the item's read permission, and an item about no agent only to a viewer
// holding that permission at the org. The summary states its scope and
// as-of time and lists what it does not know; it never claims that the
// estate is safe. A source that has gone quiet shows as a gap with its
// last-seen time, never as a quiet interval.
package operations

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/search"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Service serves the Operations surface.
type Service struct {
	Pool  *db.Pool
	Clock clock.Clock
	// Sources are the other streams' ports (D49); any may be nil.
	Sources Sources
}

// viewer is a caller with its scopes, computed once per request.
type viewer struct {
	c      tenancy.Caller
	q      *dbq.Queries
	scopes map[td.Permission]search.Scope
}

// operator returns the caller once it holds operations.read somewhere.
func operator(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	if !c.CanAnywhere(td.PermOperationsRead) {
		return tenancy.Caller{}, td.ErrPermissionDenied(td.PermOperationsRead)
	}
	return c, nil
}

func (v *viewer) scope(ctx context.Context, p td.Permission) (search.Scope, error) {
	if sc, ok := v.scopes[p]; ok {
		return sc, nil
	}
	sc, err := search.AgentScope(ctx, v.c, v.q, p)
	if err != nil {
		return search.Scope{}, err
	}
	v.scopes[p] = sc
	return sc, nil
}

// whole reports whether the viewer holds p at the org.
func (v *viewer) whole(p td.Permission) bool { return v.c.Can(p, td.OrgPath(v.c.Org)) }

// covers reports whether the viewer holds p for a row about agents: every
// agent in its scope, or the org for a row about none. A malformed agent
// id makes the row org-level.
func (v *viewer) covers(ctx context.Context, p td.Permission, agents []string) (bool, error) {
	parsed, ok := parseAgents(agents)
	if !ok {
		return v.whole(p), nil
	}
	return v.coversIDs(ctx, p, parsed)
}

// parseAgents parses agent ids; false when one is malformed.
func parseAgents(agents []string) ([]ids.UUID, bool) {
	out := make([]ids.UUID, 0, len(agents))
	for _, a := range agents {
		id, err := ids.ParseUUID(a)
		if err != nil {
			return nil, false
		}
		out = append(out, id)
	}
	return out, true
}

func (v *viewer) coversIDs(ctx context.Context, p td.Permission, agents []ids.UUID) (bool, error) {
	if len(agents) == 0 {
		return v.whole(p), nil
	}
	sc, err := v.scope(ctx, p)
	if err != nil {
		return false, err
	}
	if sc.All {
		return true, nil
	}
	if sc.Restricted {
		return false, nil
	}
	in := make(map[ids.UUID]bool, len(sc.Agents))
	for _, a := range sc.Agents {
		in[a] = true
	}
	for _, a := range agents {
		if !in[a] {
			return false, nil
		}
	}
	return true, nil
}

// read runs fn in a read-only tenant transaction for the operator.
func (s *Service) read(ctx context.Context, fn func(ctx context.Context, v *viewer) error) error {
	c, err := operator(ctx)
	if err != nil {
		return err
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		return fn(ctx, &viewer{c: c, q: dbq.New(tx), scopes: map[td.Permission]search.Scope{}})
	}, db.ReadOnly())
}

// never turns the queries' epoch sentinel into "never seen".
func never(t time.Time) *time.Time {
	if !t.After(time.Unix(0, 0)) {
		return nil
	}
	u := t.UTC()
	return &u
}
