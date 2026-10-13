// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
)

// SnapshotRecord is a recorded snapshot with its full record.
type SnapshotRecord struct {
	dbq.PcCoverageSnapshot
	Body Snapshot
}

func snapshotRecord(row dbq.PcCoverageSnapshot) (SnapshotRecord, error) {
	s := SnapshotRecord{PcCoverageSnapshot: row}
	return s, json.Unmarshal(row.Body, &s.Body)
}

// GetSnapshot returns one recorded snapshot; the caller needs
// coverage.read over its agent.
func (s *Service) GetSnapshot(ctx context.Context, id ids.UUID) (SnapshotRecord, error) {
	var out SnapshotRecord
	err := s.read(ctx, func(ctx context.Context, r *readers) error {
		row, err := r.q.GetCoverageSnapshot(ctx, r.c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if ok, err := r.can(ctx, &row.AgentID); err != nil || !ok {
			return orNotFound(err)
		}
		out, err = snapshotRecord(row)
		return err
	})
	return out, err
}

// ListSnapshots lists a scope's snapshots newest first, its coverage
// history; the caller needs coverage.read over the agent.
func (s *Service) ListSnapshots(ctx context.Context, sc domain.Scope, size int32, token string) ([]SnapshotRecord, string, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []SnapshotRecord
	var next string
	err = s.read(ctx, func(ctx context.Context, r *readers) error {
		if ok, err := r.can(ctx, &sc.Agent); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil || !ok {
			return orNotFound(err)
		}
		rows, err := r.q.ListCoverageSnapshotsPage(ctx, dbq.ListCoverageSnapshotsPageParams{
			OrgID: r.c.Org, AgentID: sc.Agent, ConnectionID: sc.Connection, Operation: sc.Operation, Before: cursor(p),
			MaxRows: p.Limit(),
		})
		if err != nil {
			return err
		}
		rows, next = page.Finish(p, rows, func(x dbq.PcCoverageSnapshot) ids.UUID { return x.ID })
		for _, row := range rows {
			rec, err := snapshotRecord(row)
			if err != nil {
				return err
			}
			out = append(out, rec)
		}
		return nil
	})
	return out, next, err
}
