// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// Errors of assignment.
var (
	ErrNotDecider  = pcerr.New(pcerr.PermissionDenied, "NOT_ELIGIBLE", "only a person who can decide this entry may take it")
	ErrEntryClosed = pcerr.New(pcerr.FailedPrecondition, "WAITLIST_ENTRY_CLOSED", "the entry is no longer open")
)

// Writer changes waitlist entries. Entries are decided by the service that
// owns their subject; here they are only assigned.
type Writer struct{ pool *db.Pool }

// NewWriter returns the waitlist writes.
func NewWriter(pool *db.Pool) *Writer { return &Writer{pool: pool} }

// Assign marks the calling person as working on an open entry, or clears
// the mark (HR-177). Assignment only shows who is working on an entry and
// never changes who may decide it; only a person who can decide the entry
// may take it or clear it. Anyone who may not read the entry gets "not
// found" (T-037).
func (w *Writer) Assign(ctx context.Context, id ids.UUID, unassign bool) (Entry, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Entry{}, err
	}
	var out Entry
	err = w.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetWaitlistEntry(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrEntryNotFound
		} else if err != nil {
			return err
		}
		path := td.OrgPath(c.Org)
		if r.AgentID != nil {
			a, err := q.GetAgent(ctx, c.Org, *r.AgentID)
			if err != nil {
				return err
			}
			if path, err = agents.PathOf(ctx, q, a); err != nil {
				return err
			}
		}
		if !c.Can(td.PermWaitlistRead, path) {
			return ErrEntryNotFound
		}
		ok, err := decides(ctx, q, c, r, path)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotDecider
		}
		var assignee *ids.UUID
		name := "waitlist.unassigned"
		if !unassign {
			assignee, name = &c.Principal.ID, "waitlist.assigned"
		}
		n, err := q.AssignWaitlistEntry(ctx, assignee, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrEntryClosed
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: name, Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "waitlist_entry", ID: id.String()}, Details: map[string]string{"kind": r.Kind},
		}); err != nil {
			return err
		}
		if r, err = q.GetWaitlistEntry(ctx, c.Org, id); err != nil {
			return err
		}
		out, err = view(r)
		return err
	})
	return out, err
}

// decides reports whether the calling person can decide the entry: under
// the approval rules for a hold (HR-170), as an agent.restore holder other
// than the requester for a restoration (decision 11), and otherwise by the
// kind's permission on the entry's scope path.
func decides(ctx context.Context, q *dbq.Queries, c tenancy.Caller, r dbq.PcWaitlistEntry, path td.Path) (bool, error) {
	if !c.Human() {
		return false, nil
	}
	switch r.Kind {
	case wdomain.KindActionHold:
		e, err := pgapprovals.LoadEligibility(ctx, q, c.Org, r.SubjectID, []ids.UUID{c.Principal.ID})
		if err != nil {
			return false, err
		}
		for _, req := range e.Requirements {
			if ok, _ := apdomain.MayRespond(req, e.People[c.Principal.ID], e.Context); ok {
				return true, nil
			}
		}
		return false, nil
	case wdomain.KindRestoration:
		return c.Can(td.PermAgentRestore, path) && (r.RequestedBy == nil || *r.RequestedBy != c.Principal.String()), nil
	}
	p, ok := wdomain.DeciderPermission(r.Kind)
	return ok && c.Can(p, path), nil
}
