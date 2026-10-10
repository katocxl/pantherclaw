// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app reads the Agent Waitlist (Pass; PN-004.1, G0 M3). M3 has
// ADMISSION entries only; M5 adds the other entry types, deciders,
// escalation and wait handles. Reading an entry needs waitlist.read where
// its agent lives. Entries are decided by the service that owns their
// subject, never here.
package app

import (
	"context"
	"encoding/json/v2"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// ErrEntryNotFound is returned for unknown or unreadable entries.
var ErrEntryNotFound = pcerr.New(pcerr.NotFound, "WAITLIST_ENTRY_NOT_FOUND", "waitlist entry not found")

// Entry is one waitlist entry. Evidence was established by PantherClaw;
// Untrusted was reported by a workload or observed at a gateway and is
// never used to decide.
type Entry struct {
	ID             ids.UUID
	Kind           string
	SubjectType    string
	SubjectID      ids.UUID
	AgentID        ids.UUID
	State          string
	Evidence       map[string]string
	Untrusted      map[string]string
	DeadlineAt     time.Time
	DecidedBy      string
	DecidedAt      *time.Time
	DecisionReason string
	CreatedAt      time.Time
	// Priority runs from 1 (most urgent) to 4 (HR-177). Assignee is who
	// is working on the entry, if anyone; it decides nothing.
	Priority   int
	Assignee   ids.UUID
	AssignedAt *time.Time
	// Run, transaction and requester, when the kind has them; routing
	// health, escalation steps taken and when the next one is due.
	RunID, TransactionID ids.UUID
	RequestedBy          string
	RoutingHealth        string
	EscalationStep       int
	NextStepAt           *time.Time
	FirstResponseAt      *time.Time
}

// Page is one page of entries.
type Page struct {
	Items []Entry
	Next  string
	// Scopes are the caller's bindings of roles holding waitlist.read: an
	// empty page means nothing is waiting there (F626).
	Scopes []td.Binding
}

// Filter narrows List.
type Filter struct {
	// States default to OPEN.
	States     []string
	Agent      ids.UUID
	Kinds      []string
	Priorities []int
	// AssignedToMe keeps the entries assigned to the caller; Overdue the
	// open ones past their next escalation step or within a tenth of their
	// deadline.
	AssignedToMe, Overdue bool
}

// Reader serves the waitlist reads.
type Reader struct {
	pool *db.Pool
	ents Entitlements
}

// NewReader returns the waitlist reads.
func NewReader(pool *db.Pool) *Reader { return &Reader{pool: pool} }

// evidence is the stored shape of waitlist_entries.evidence.
type evidence struct {
	Trusted   map[string]string `json:"trusted,omitzero"`
	Untrusted map[string]string `json:"untrusted,omitzero"`
}

func view(r dbq.PcWaitlistEntry) (Entry, error) {
	e := Entry{
		ID: r.ID, Kind: r.Kind, SubjectType: r.SubjectType, SubjectID: r.SubjectID, AgentID: agentOf(r), State: r.State,
		DeadlineAt: r.DeadlineAt, DecidedAt: r.DecidedAt, DecisionReason: r.DecisionReason, CreatedAt: r.CreatedAt,
	}
	if r.DecidedBy != nil {
		e.DecidedBy = *r.DecidedBy
	}
	e.Priority, e.AssignedAt = int(r.Priority), r.AssignedAt
	if r.AssigneeUserID != nil {
		e.Assignee = *r.AssigneeUserID
	}
	if r.RunID != nil {
		e.RunID = *r.RunID
	}
	if r.TransactionID != nil {
		e.TransactionID = *r.TransactionID
	}
	if r.RequestedBy != nil {
		e.RequestedBy = *r.RequestedBy
	}
	e.RoutingHealth, e.EscalationStep, e.NextStepAt, e.FirstResponseAt = r.RoutingHealth, int(r.EscalationStep), r.NextStepAt, r.FirstResponseAt
	var ev evidence
	if err := json.Unmarshal(r.Evidence, &ev); err != nil {
		return e, err
	}
	e.Evidence, e.Untrusted = ev.Trusted, ev.Untrusted
	return e, nil
}

// agentOf returns the entry's agent, or the zero id for an entry about no
// agent (a tool review).
func agentOf(r dbq.PcWaitlistEntry) ids.UUID {
	if r.AgentID == nil {
		return ids.UUID{}
	}
	return *r.AgentID
}

// canRead reports whether the caller may read entries about agent. An
// entry about no agent (a tool review) needs waitlist.read at org scope.
func canRead(ctx context.Context, c tenancy.Caller, q *dbq.Queries, agent ids.UUID) (bool, error) {
	if agent.IsZero() {
		return c.Can(td.PermWaitlistRead, td.OrgPath(c.Org)), nil
	}
	a, err := q.GetAgent(ctx, c.Org, agent)
	if err != nil {
		return false, err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return false, err
	}
	return c.Can(td.PermWaitlistRead, path), nil
}

// List lists entries the caller may read, open ones by default, by
// priority and then deadline (HR-177), with the scopes it checked (F626).
func (rd *Reader) List(ctx context.Context, pr page.Request, f Filter) (Page, error) {
	if len(f.States) == 0 {
		f.States = []string{wdomain.StateOpen}
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Page{}, err
	}
	out := Page{}
	for _, b := range c.Bindings {
		if r, ok := td.LookupRole(b.Role); ok && r.Has(td.PermWaitlistRead) {
			out.Scopes = append(out.Scopes, b)
		}
	}
	p := dbq.ListWaitlistEntriesParams{
		OrgID: c.Org, States: f.States, Kinds: f.Kinds, Overdue: f.Overdue, PageLimit: pr.Limit(),
	}
	if p.Kinds == nil {
		p.Kinds = []string{}
	}
	p.Priorities = []int16{}
	for _, x := range f.Priorities {
		p.Priorities = append(p.Priorities, int16(x)) //nolint:gosec // 1..4
	}
	if !f.Agent.IsZero() {
		p.AgentID = &f.Agent
	}
	if f.AssignedToMe {
		p.Assignee = &c.Principal.ID
	}
	if !pr.After.IsZero() {
		p.After = &pr.After
	}
	err = rd.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListWaitlistEntries(ctx, p)
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.PcWaitlistEntry) ids.UUID { return r.ID })
		allowed := map[ids.UUID]bool{}
		for _, r := range rows {
			ok, seen := allowed[agentOf(r)]
			if !seen {
				if ok, err = canRead(ctx, c, q, agentOf(r)); err != nil {
					return err
				}
				allowed[agentOf(r)] = ok
			}
			if !ok {
				continue
			}
			e, err := view(r)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, e)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Get returns one entry.
func (rd *Reader) Get(ctx context.Context, id ids.UUID) (Entry, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Entry{}, err
	}
	var out Entry
	err = rd.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetWaitlistEntry(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrEntryNotFound
		} else if err != nil {
			return err
		}
		ok, err := canRead(ctx, c, q, agentOf(r))
		if err != nil {
			return err
		}
		if !ok {
			return td.ErrPermissionDenied(td.PermWaitlistRead)
		}
		out, err = view(r)
		return err
	}, db.ReadOnly())
	return out, err
}
