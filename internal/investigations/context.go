// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package investigations

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Context link kinds.
const (
	// LinkInternalBeforePublic: earlier in the same run the agent acted on
	// an internal destination, then this action went to a public one (F248).
	LinkInternalBeforePublic = "INTERNAL_BEFORE_PUBLIC"
)

// AuthorityChange is a grant issued, revoked or revised for the agent.
type AuthorityChange struct {
	Grant   ids.UUID
	Change  string // ISSUED, REVOKED, REVISED, REVISED_WIDER
	At      time.Time
	Grantor Party
	Parent  *ids.UUID
	Basis   Basis
}

// ToolChange is a connection created or a package pin moved for a
// connection the run used.
type ToolChange struct {
	Connection ids.UUID
	Name       string
	Package    string
	Change     string // CONNECTION_CREATED, PACKAGE_PINNED
	At         time.Time
	Basis      Basis
}

// Shared is another run that acted on the same connection and target.
// Sharing is a correlation, never a cause.
type Shared struct {
	Run, Agent ids.UUID
	Connection *ids.UUID
	TargetType string
	TargetID   string
	Actions    int64
	First      time.Time
	Last       time.Time
	Basis      Basis
}

// Link ties an earlier action of the run to the subject action.
type Link struct {
	Kind        string
	From, To    ids.UUID
	Operation   string
	Connection  *ids.UUID
	At          time.Time
	Basis       Basis
	Explanation string
}

// Preceding is the context before an action or a run (F241, F248).
type Preceding struct {
	Run, Agent  ids.UUID
	Transaction *ids.UUID
	Range       Range
	Authority   []AuthorityChange
	Tools       []ToolChange
	Shared      []Shared
	Links       []Link
	// ContentProvenance: external-content provenance is not collected for
	// agent inputs yet; the view says so instead of showing nothing.
	ContentProvenance string
	ScopeLimited      bool
}

// ProvenanceNotCollected is Preceding.ContentProvenance today.
const ProvenanceNotCollected = "NOT_COLLECTED"

// PrecedingContext assembles the context before transaction txn, or before
// the end of run when txn is nil, over rng (zero: the DefaultContext
// before the subject until the subject). Nothing in it asserts causation.
func PrecedingContext(ctx context.Context, tx db.TenantTx, s Scope, run ids.UUID, txn *ids.UUID, rng Range) (Preceding, error) {
	q := dbq.New(tx)
	var subjectAt time.Time
	var subject *dbq.InvTransactionRow
	if txn != nil {
		t, err := q.InvTransaction(ctx, tx.OrgID(), *txn)
		if db.IsNoRows(err) {
			return Preceding{}, ErrTransactionNotFound
		} else if err != nil {
			return Preceding{}, err
		}
		run, subjectAt, subject = t.RunID, t.CreatedAt, &t
	}
	r, err := q.InvRun(ctx, tx.OrgID(), run)
	if db.IsNoRows(err) {
		return Preceding{}, ErrRunNotFound
	} else if err != nil {
		return Preceding{}, err
	}
	if ok, err := s.Visible(ctx, r.AgentID); err != nil {
		return Preceding{}, err
	} else if !ok {
		if txn != nil {
			return Preceding{}, ErrTransactionNotFound
		}
		return Preceding{}, ErrRunNotFound
	}
	if txn == nil {
		subjectAt = time.Now()
		if r.EndedAt != nil {
			subjectAt = *r.EndedAt
		}
	}
	if rng.Start.IsZero() && rng.End.IsZero() {
		rng = Range{Start: subjectAt.Add(-DefaultContext), End: subjectAt.Add(time.Microsecond)}
	}
	if err := rng.check(); err != nil {
		return Preceding{}, err
	}
	p := Preceding{Run: r.ID, Agent: r.AgentID, Transaction: txn, Range: rng, ContentProvenance: ProvenanceNotCollected,
		ScopeLimited: s.Limited()}

	changes, err := q.InvGrantChanges(ctx, dbq.InvGrantChangesParams{
		OrgID: tx.OrgID(), AgentID: r.AgentID, StartTime: rng.Start, EndTime: rng.End,
	})
	if err != nil {
		return Preceding{}, err
	}
	for _, c := range changes {
		p.Authority = append(p.Authority, AuthorityChange{Grant: c.GrantID, Change: authorityDetail(c), At: c.At,
			Grantor: Party{c.GrantorKind, c.GrantorID}, Parent: c.ParentID, Basis: BasisObserved})
	}

	txns, err := runTransactions(ctx, q, tx.OrgID(), run, MaxTimelineActions)
	if err != nil {
		return Preceding{}, err
	}
	var conns []ids.UUID
	seen := map[ids.UUID]bool{}
	for _, t := range txns {
		if t.ConnectionID != nil && !seen[*t.ConnectionID] {
			seen[*t.ConnectionID] = true
			conns = append(conns, *t.ConnectionID)
		}
	}
	if len(conns) > 0 {
		tools, err := q.InvToolChanges(ctx, dbq.InvToolChangesParams{
			OrgID: tx.OrgID(), ConnectionIds: conns, StartTime: rng.Start, EndTime: rng.End,
		})
		if err != nil {
			return Preceding{}, err
		}
		for _, c := range tools {
			p.Tools = append(p.Tools, ToolChange{Connection: c.ConnectionID, Name: c.Connection, Package: c.Package,
				Change: c.Change, At: c.At, Basis: BasisObserved})
		}
	}

	shared, err := q.InvSharedTargets(ctx, dbq.InvSharedTargetsParams{
		OrgID: tx.OrgID(), RunID: run, StartTime: rng.Start, EndTime: rng.End,
	})
	if err != nil {
		return Preceding{}, err
	}
	for _, x := range shared {
		ok, err := s.Visible(ctx, x.AgentID)
		if err != nil {
			return Preceding{}, err
		}
		if !ok {
			continue
		}
		p.Shared = append(p.Shared, Shared{Run: x.RunID, Agent: x.AgentID, Connection: x.ConnectionID,
			TargetType: x.TargetType, TargetID: x.TargetID, Actions: x.Actions, First: x.FirstAt, Last: x.LastAt,
			Basis: BasisObserved})
	}

	if subject != nil && str(subject.DestinationClass) == "public" {
		for _, t := range txns {
			if !t.CreatedAt.Before(subject.CreatedAt) || t.ID == subject.ID || str(t.DestinationClass) != "internal" {
				continue
			}
			if t.CreatedAt.Before(rng.Start) {
				continue
			}
			p.Links = append(p.Links, Link{Kind: LinkInternalBeforePublic, From: t.ID, To: subject.ID, Operation: t.Operation,
				Connection: t.ConnectionID, At: t.CreatedAt, Basis: BasisInferred,
				Explanation: "an earlier action of this run used an internal destination; this is a sequence, not a proven flow"})
		}
	}
	return p, nil
}
