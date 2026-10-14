// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"slices"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// snapshotKind is the ledger kind of a coverage snapshot, whose body names
// the closure it was computed from.
const snapshotKind = bundle.SnapshotKind

// closures collects the sandbox.closure entries of closures (HR-227), after
// checking evidence.read where each closure's agent lives, as for a
// transaction.
func (s *Service) closures(ctx context.Context, c tenancy.Caller, q *dbq.Queries, closures []ids.UUID) ([]chained, error) {
	want := make([]string, 0, len(closures))
	for _, id := range closures {
		want = append(want, id.String())
	}
	refs, err := q.ClosureEntryRefs(ctx, c.Org, want)
	if err != nil {
		return nil, err
	}
	found := map[string]bool{}
	for _, r := range refs {
		found[r.ClosureID] = true
	}
	for _, w := range want {
		if !found[w] {
			return nil, ErrClosureNotFound
		}
	}
	return s.refEntries(ctx, c, q, refs)
}

// probeRunEntries collects the sandbox.closure entries that record probe runs
// (the probe steps of a range, HR-224), after the same permission check. Runs
// no closure records are left out.
func (s *Service) probeRunEntries(ctx context.Context, c tenancy.Caller, q *dbq.Queries, runs []ids.UUID) ([]chained, error) {
	want := make([]string, 0, len(runs))
	for _, id := range runs {
		want = append(want, id.String())
	}
	refs, err := q.ClosureEntryRefsOfRuns(ctx, c.Org, want)
	if err != nil {
		return nil, err
	}
	conv := make([]dbq.ClosureEntryRefsRow, len(refs))
	for i, r := range refs {
		conv[i] = dbq.ClosureEntryRefsRow(r)
	}
	return s.refEntries(ctx, c, q, conv)
}

// refEntries checks evidence.read where each closure's agent lives and reads
// the closures' chained entries.
func (s *Service) refEntries(ctx context.Context, c tenancy.Caller, q *dbq.Queries, refs []dbq.ClosureEntryRefsRow) ([]chained, error) {
	var entryIDs []ids.UUID
	checked := map[string]bool{}
	for _, r := range refs {
		entryIDs = append(entryIDs, r.EntryID)
		if checked[r.AgentID] {
			continue
		}
		checked[r.AgentID] = true
		agent, err := ids.ParseUUID(r.AgentID)
		if err != nil {
			return nil, ErrClosureNotFound
		}
		a, err := q.GetAgent(ctx, c.Org, agent)
		if db.IsNoRows(err) {
			return nil, ErrClosureNotFound
		} else if err != nil {
			return nil, err
		}
		path, err := agents.PathOf(ctx, q, a)
		if err != nil {
			return nil, err
		}
		if err := c.Require(td.PermEvidenceRead, path); err != nil {
			return nil, err
		}
	}
	return chainedOf(ctx, q, c.Org, entryIDs)
}

// chainedOf reads the chained entries with ids.
func chainedOf(ctx context.Context, q *dbq.Queries, org ids.OrgID, entryIDs []ids.UUID) ([]chained, error) {
	rows, err := q.ChainedEntriesByID(ctx, org, entryIDs)
	if err != nil {
		return nil, err
	}
	entries := make([]chained, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, chained{
			seq: r.Seq, prevHash: r.PrevHash, entryHash: r.EntryHash, id: r.ID, kind: r.Kind, actorType: r.ActorType,
			actorID: r.ActorID, occurredAt: r.OccurredAt, body: r.Body, removedAt: r.BodyRemovedAt, policy: r.RemovedByPolicy,
		})
	}
	return entries, nil
}

// withClosures adds the sandbox.closure entries that the coverage snapshot
// entries of entries name, so a bundle of a transaction whose receipt's
// coverage claim names a snapshot carries the closure that snapshot was
// computed from (HR-227). Their reports are added by probeReports.
func withClosures(ctx context.Context, q *dbq.Queries, org ids.OrgID, entryIDs []ids.UUID, entries []chained) ([]chained, error) {
	var closureIDs []string
	for _, e := range entries {
		if e.kind != snapshotKind || e.removedAt != nil {
			continue
		}
		var body struct {
			Closure string `json:"closure"`
		}
		if json.Unmarshal(e.body, &body) == nil && body.Closure != "" && !slices.Contains(closureIDs, body.Closure) {
			closureIDs = append(closureIDs, body.Closure)
		}
	}
	if len(closureIDs) == 0 {
		return entries, nil
	}
	refs, err := q.ClosureEntryRefs(ctx, org, closureIDs)
	if err != nil {
		return nil, err
	}
	for _, r := range refs {
		entryIDs = append(entryIDs, r.EntryID)
	}
	return chainedOf(ctx, q, org, entryIDs)
}

// probeReports returns the signed probe reports that the sandbox.closure
// entries among entries name, as stored (HR-227).
func probeReports(ctx context.Context, q *dbq.Queries, org ids.OrgID, entries []chained) ([]bundle.ProbeReport, error) {
	var runs []ids.UUID
	for _, e := range entries {
		if e.kind != bundle.ClosureKind || e.removedAt != nil {
			continue
		}
		var body struct {
			Reports []struct {
				Run string `json:"run"`
			} `json:"reports"`
		}
		if json.Unmarshal(e.body, &body) != nil {
			continue
		}
		for _, r := range body.Reports {
			if id, err := ids.ParseUUID(r.Run); err == nil && !slices.Contains(runs, id) {
				runs = append(runs, id)
			}
		}
	}
	if len(runs) == 0 {
		return nil, nil
	}
	rows, err := q.ProbeRunReports(ctx, org, runs)
	if err != nil {
		return nil, err
	}
	out := make([]bundle.ProbeReport, 0, len(rows))
	for _, r := range rows {
		out = append(out, bundle.ProbeReport{Run: r.ID.String(), Report: r.Report})
	}
	return out, nil
}
