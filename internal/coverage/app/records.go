// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// ReasonNotAssessed is the reason of a scope without a snapshot yet.
const ReasonNotAssessed = domain.ReasonNotAssessed

// ReasonLapsed prefixes the reason a lapsed record names: "expired" or
// the kind of the change its snapshot did not see.
const ReasonLapsed = "lapsed"

// Record is one scope's coverage as it reads now (HR-211). While its
// current snapshot holds, it reads as recorded. Once the snapshot expired
// or a change it did not see arrived, the scope is recomputed from current
// evidence and read at most PARTIAL, possibly lower, with the last valid
// record (F442) and why it lapsed.
type Record struct {
	Scope domain.Scope
	State domain.State
	// Computed is the snapshot's state.
	Computed domain.State
	Reasons  []string
	// Snapshot is nil for a scope not assessed yet.
	Snapshot *dbq.PcCoverageSnapshot
	Body     Snapshot
	// Recomputed is the recomputation of a lapsed record.
	Recomputed *domain.Result
	// LastValid is the last ENFORCED snapshot when this record is a
	// downgrade, and Lapse why it lapsed.
	LastValid *dbq.PcCoverageSnapshot
	Lapse     string
	// Changes are the changes to the scope the snapshot did not see.
	Changes    []dbq.PcCoverageInvalidation
	Exclusions []dbq.PcCoverageExclusion
}

// lapses are the reasons a recorded downgrade names its cause by.
var lapses = []string{domain.ReasonClosureExpired, domain.ReasonClosureRebound, domain.ReasonClosureFailed, domain.ReasonInvalidated}

func lapseOf(reasons []string) string {
	for _, r := range reasons {
		for _, l := range lapses {
			if strings.HasPrefix(r, l) {
				return r
			}
		}
	}
	return "changed"
}

// unseenChanges are the changes to a scope its snapshot row did not see:
// a change the computation read, made before it, is in the snapshot.
func unseenChanges(changes []dbq.PcCoverageInvalidation, row *dbq.PcCoverageSnapshot, seen []string) []domain.Change {
	unseen := make([]domain.Change, 0, len(changes))
	for _, ch := range changes {
		if ch.OccurredAt.Before(row.ComputedAt) && slices.Contains(seen, ch.ID.String()) {
			continue
		}
		unseen = append(unseen, domain.Change{ID: ch.ID, Kind: domain.InvalidationKind(ch.Kind), OccurredAt: ch.OccurredAt})
	}
	return unseen
}

// Lapsed reports why a scope's current snapshot no longer holds at now:
// it expired, or a change it did not see arrived (HR-211); "" while it
// holds. It reads in the caller's transaction and checks no permission:
// the promotion checks read it (G0 M11 part 2, D39).
func Lapsed(ctx context.Context, q *dbq.Queries, row dbq.PcCoverageSnapshot, now time.Time) (string, error) {
	var body Snapshot
	if err := json.Unmarshal(row.Body, &body); err != nil {
		return "", err
	}
	changes, err := q.CoverageChangesPending(ctx, row.OrgID, row.ConnectionID, &row.AgentID)
	if err != nil {
		return "", err
	}
	return domain.Lapse(row.ExpiresAt, unseenChanges(changes, &row, body.Seen), now), nil
}

// record reads one scope's record at now from its current snapshot (nil
// when none); full adds the exclusions that apply.
func (s *Service) record(ctx context.Context, tx db.TenantTx, sc domain.Scope, row *dbq.PcCoverageSnapshot, full bool,
	pkgs packages, now time.Time,
) (Record, error) {
	q, org := dbq.New(tx), tx.OrgID()
	r := Record{Scope: sc, State: domain.Unknown, Computed: domain.Unknown, Reasons: []string{ReasonNotAssessed}, Snapshot: row}
	if full {
		var err error
		if r.Exclusions, err = q.CoverageExclusionsForScope(ctx, dbq.CoverageExclusionsForScopeParams{
			OrgID: org, ConnectionID: sc.Connection, AgentID: &sc.Agent, Operation: sc.Operation,
		}); err != nil {
			return r, err
		}
	}
	if row == nil {
		return r, nil
	}
	if err := json.Unmarshal(row.Body, &r.Body); err != nil {
		return r, err
	}
	r.Computed, _ = domain.ParseState(row.State)
	var err error
	if r.Changes, err = q.CoverageChangesPending(ctx, org, sc.Connection, &sc.Agent); err != nil {
		return r, err
	}
	r.Lapse = domain.Lapse(row.ExpiresAt, unseenChanges(r.Changes, row, r.Body.Seen), now)
	if r.Lapse == "" {
		r.State, r.Reasons = r.Computed, r.Body.Reasons
		if row.LastValidID != nil {
			lv, err := q.GetCoverageSnapshot(ctx, org, *row.LastValidID)
			if err != nil {
				return r, err
			}
			r.LastValid, r.Lapse = &lv, lapseOf(r.Body.Reasons)
		}
		return r, nil
	}
	e, err := s.evidence(ctx, tx, sc, now, pkgs)
	if err != nil {
		return r, err
	}
	res := domain.Compute(e)
	r.Recomputed = &res
	r.State = domain.Cap(res.State)
	r.Reasons = append([]string{ReasonLapsed + ":" + r.Lapse}, res.Reasons...)
	switch {
	case r.Computed == domain.Enforced:
		r.LastValid = row
	case row.LastValidID != nil:
		lv, err := q.GetCoverageSnapshot(ctx, org, *row.LastValidID)
		if err != nil {
			return r, err
		}
		r.LastValid = &lv
	}
	return r, nil
}

// GetCoverage returns one scope's record as it reads now; the caller
// needs coverage.read over the agent.
func (s *Service) GetCoverage(ctx context.Context, sc domain.Scope) (Record, error) {
	var out Record
	err := s.read(ctx, func(ctx context.Context, r *readers) error {
		if ok, err := r.can(ctx, &sc.Agent); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil || !ok {
			return orNotFound(err)
		}
		row, err := r.q.CurrentCoverageSnapshot(ctx, dbq.CurrentCoverageSnapshotParams{
			OrgID: r.c.Org, AgentID: sc.Agent, ConnectionID: sc.Connection, Operation: sc.Operation,
		})
		var cur *dbq.PcCoverageSnapshot
		if err == nil {
			cur = &row
		} else if !db.IsNoRows(err) {
			return err
		}
		out, err = s.record(ctx, r.tx, sc, cur, true, packages{}, s.now())
		return err
	})
	return out, err
}

// scopeToken encodes the last scope of a page.
func scopeToken(sc domain.Scope) string {
	b := append(append(append([]byte{}, sc.Agent[:]...), sc.Connection[:]...), sc.Operation...)
	return base64.RawURLEncoding.EncodeToString(b)
}

func parseScopeToken(token string) (*domain.Scope, error) {
	if token == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(b) < 33 || len(b) > 32+128 {
		return nil, page.ErrBadToken
	}
	var sc domain.Scope
	copy(sc.Agent[:], b[:16])
	copy(sc.Connection[:], b[16:32])
	sc.Operation = string(b[32:])
	return &sc, nil
}

// ListCoverage lists the current record of every scope the caller may
// read, by agent, connection and operation.
func (s *Service) ListCoverage(ctx context.Context, f Filter, size int32, token string) ([]Record, string, error) {
	p, err := page.Parse(size, "")
	if err != nil {
		return nil, "", err
	}
	after, err := parseScopeToken(token)
	if err != nil {
		return nil, "", err
	}
	var out []Record
	var next string
	pkgs := packages{}
	err = s.read(ctx, func(ctx context.Context, r *readers) error {
		params := dbq.ListCurrentCoverageSnapshotsPageParams{
			OrgID: r.c.Org, ConnectionID: f.Connection, AgentID: f.Agent, MaxRows: p.Limit(),
		}
		if after != nil {
			params.AfterAgent, params.AfterConnection, params.AfterOperation = &after.Agent, &after.Connection, &after.Operation
		}
		rows, err := r.q.ListCurrentCoverageSnapshotsPage(ctx, params)
		if err != nil {
			return err
		}
		if len(rows) > p.Size {
			rows = rows[:p.Size]
			last := rows[len(rows)-1]
			next = scopeToken(domain.Scope{Agent: last.AgentID, Connection: last.ConnectionID, Operation: last.Operation})
		}
		for i := range rows {
			row := rows[i]
			if ok, err := r.can(ctx, &row.AgentID); err != nil {
				return err
			} else if !ok {
				continue
			}
			sc := domain.Scope{Agent: row.AgentID, Connection: row.ConnectionID, Operation: row.Operation}
			rec, err := s.record(ctx, r.tx, sc, &row, false, pkgs, s.now())
			if err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, next, err
}
