// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"strings"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// ReasonNotAssessed is the reason of a scope without a snapshot yet.
const ReasonNotAssessed = domain.ReasonNotAssessed

// Record is one scope's coverage as it reads now (HR-211): the current
// snapshot, downgraded to PARTIAL when it was ENFORCED and lapsed or a
// change since invalidated it, with the last valid record (F442).
type Record struct {
	Scope    domain.Scope
	State    domain.State
	Computed domain.State
	Reasons  []string
	// Snapshot is nil for a scope not assessed yet.
	Snapshot *dbq.PcCoverageSnapshot
	Body     Snapshot
	// LastValid is the last ENFORCED snapshot when this record is a
	// downgrade, and why it lapsed.
	LastValid *dbq.PcCoverageSnapshot
	Lapse     string
	// Changes are the invalidating changes after the snapshot.
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

// record reads one scope's record from its current snapshot (nil when
// none); full adds the exclusions that apply.
func (s *Service) record(ctx context.Context, q *dbq.Queries, org ids.OrgID, sc domain.Scope, row *dbq.PcCoverageSnapshot,
	full bool,
) (Record, error) {
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
	if r.Changes, err = q.CoverageInvalidationsSince(ctx, dbq.CoverageInvalidationsSinceParams{
		OrgID: org, ConnectionID: sc.Connection, AgentID: &sc.Agent, Since: row.ComputedAt,
	}); err != nil {
		return r, err
	}
	var why string
	r.State, why = domain.ReadAt(r.Computed, row.ExpiresAt, len(r.Changes), s.now())
	r.Reasons = r.Body.Reasons
	switch {
	case why != "":
		if why == domain.ReasonInvalidated {
			why += ":" + r.Changes[0].Kind
		}
		r.Reasons = append([]string{why}, r.Reasons...)
		r.LastValid, r.Lapse = row, why
	case row.LastValidID != nil:
		lv, err := q.GetCoverageSnapshot(ctx, org, *row.LastValidID)
		if err != nil {
			return r, err
		}
		r.LastValid, r.Lapse = &lv, lapseOf(r.Body.Reasons)
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
		out, err = s.record(ctx, r.q, r.c.Org, sc, cur, true)
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
			rec, err := s.record(ctx, r.q, r.c.Org, sc, &row, false)
			if err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, next, err
}
