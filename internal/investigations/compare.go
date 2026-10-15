// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package investigations

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Destination is a connection a run acted on.
type Destination struct {
	Connection ids.UUID
	Name       string
	Class      string
	Actions    int64
}

// Comparison sets a run against the agent's other runs in a reference
// range (F234). It reports differences and the sample they rest on; it
// never labels a run malicious.
type Comparison struct {
	Run, Agent ids.UUID
	Reference  Range
	// SampleSize is the number of reference runs; 0 means nothing to
	// compare with.
	SampleSize int
	// NewDestinations: connections this run used that no reference run used.
	NewDestinations []Destination
	// NewOperations: operations no reference run performed.
	NewOperations []string
	// Actions and accepted actions of this run, and the median of the
	// reference runs.
	Actions, Accepted       int64
	ReferenceMedianActions  int64
	ReferenceMedianAccepted int64
	// PostTaskActions: actions accepted after the run ended.
	PostTaskActions int64
	Basis           Basis
	ScopeLimited    bool
}

// CompareRun compares run with the agent's runs in ref (zero: the
// DefaultReference before the run started) (Business, F234).
func CompareRun(ctx context.Context, tx db.TenantTx, s Scope, run ids.UUID, ref Range) (Comparison, error) {
	q := dbq.New(tx)
	r, err := q.InvRun(ctx, tx.OrgID(), run)
	if db.IsNoRows(err) {
		return Comparison{}, ErrRunNotFound
	} else if err != nil {
		return Comparison{}, err
	}
	if ok, err := s.Visible(ctx, r.AgentID); err != nil {
		return Comparison{}, err
	} else if !ok {
		return Comparison{}, ErrRunNotFound
	}
	if ref.Start.IsZero() && ref.End.IsZero() {
		ref = Range{Start: r.CreatedAt.Add(-DefaultReference), End: r.CreatedAt}
	}
	if err := ref.check(); err != nil {
		return Comparison{}, err
	}
	out := Comparison{Run: r.ID, Agent: r.AgentID, Reference: ref, Basis: BasisObserved, ScopeLimited: s.Limited()}

	refs, err := q.InvReferenceRuns(ctx, dbq.InvReferenceRunsParams{
		OrgID: tx.OrgID(), AgentID: r.AgentID, RunID: r.ID, StartTime: ref.Start, EndTime: ref.End, MaxRows: MaxReferenceRuns,
	})
	if err != nil {
		return Comparison{}, err
	}
	out.SampleSize = len(refs)
	rows, err := q.InvRunProfile(ctx, tx.OrgID(), append([]ids.UUID{r.ID}, refs...))
	if err != nil {
		return Comparison{}, err
	}

	refConns, refOps := map[ids.UUID]bool{}, map[string]bool{}
	perRun := map[ids.UUID][2]int64{}
	var mine []dbq.InvRunProfileRow
	for _, p := range rows {
		if p.RunID == r.ID {
			mine = append(mine, p)
			continue
		}
		if p.ConnectionID != nil {
			refConns[*p.ConnectionID] = true
		}
		refOps[p.Operation] = true
		c := perRun[p.RunID]
		perRun[p.RunID] = [2]int64{c[0] + p.Actions, c[1] + p.Accepted}
	}
	dest := map[ids.UUID]*Destination{}
	for _, p := range mine {
		out.Actions += p.Actions
		out.Accepted += p.Accepted
		if p.ConnectionID != nil && !refConns[*p.ConnectionID] {
			d := dest[*p.ConnectionID]
			if d == nil {
				d = &Destination{Connection: *p.ConnectionID, Name: p.Connection, Class: p.DestinationClass}
				dest[*p.ConnectionID] = d
			}
			d.Actions += p.Actions
		}
		if out.SampleSize > 0 && !refOps[p.Operation] && !slices.Contains(out.NewOperations, p.Operation) {
			out.NewOperations = append(out.NewOperations, p.Operation)
		}
	}
	if out.SampleSize > 0 {
		for _, d := range dest {
			out.NewDestinations = append(out.NewDestinations, *d)
		}
	}
	slices.SortFunc(out.NewDestinations, func(a, b Destination) int { return strings.Compare(a.Connection.String(), b.Connection.String()) })
	slices.Sort(out.NewOperations)

	var actions, accepted []int64
	for _, id := range refs {
		c := perRun[id] // runs without actions count as zero
		actions, accepted = append(actions, c[0]), append(accepted, c[1])
	}
	out.ReferenceMedianActions, out.ReferenceMedianAccepted = median(actions), median(accepted)

	if r.EndedAt != nil {
		txns, err := runTransactions(ctx, q, tx.OrgID(), run, MaxTimelineActions)
		if err != nil {
			return Comparison{}, err
		}
		out.PostTaskActions = postTask(txns, *r.EndedAt)
	}
	return out, nil
}

func postTask(txns []dbq.InvRunTransactionsRow, ended time.Time) int64 {
	var n int64
	for _, t := range txns {
		if t.Outcome != nil && *t.Outcome == "accepted" && t.OutcomeAt != nil && t.OutcomeAt.After(ended) {
			n++
		}
	}
	return n
}

func median(xs []int64) int64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	return s[len(s)/2]
}
