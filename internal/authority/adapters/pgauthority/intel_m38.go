// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	intelapp "github.com/katocxl/pantherclaw/internal/intel/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var (
	_ pipeline.IntelMatches = (*Reader)(nil)
	_ pipeline.IntelMatches = (*snapshot)(nil)
)

// IntelMatches implements pipeline.IntelMatches.
func (r *Reader) IntelMatches(ctx context.Context, org ids.OrgID, conn ids.UUID, tool string) (pipeline.IntelState, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (pipeline.IntelState, error) {
		return s.IntelMatches(ctx, org, conn, tool)
	})
}

// IntelMatches implements pipeline.IntelMatches: the org's consume mode
// and, when it consumes, the current indicators matching the connection's
// upstream server (its reported name and version, its pinned package) and
// the description its upstream server last listed for tool (G0 M38 D1104).
// The server's word is matched, never trusted as its identity (HR-822).
func (s *snapshot) IntelMatches(ctx context.Context, org ids.OrgID, conn ids.UUID, tool string) (pipeline.IntelState, error) {
	q := dbq.New(s.tx)
	st, err := intelapp.ReadSettings(ctx, q, org)
	if err != nil {
		return pipeline.IntelState{}, err
	}
	out := pipeline.IntelState{Mode: string(st.Consume)}
	if !st.Consume.Consumes() || conn.IsZero() {
		return out, nil
	}
	hits, err := intelapp.ServerHits(ctx, q, org, conn)
	if err != nil {
		return out, err
	}
	if tool != "" {
		desc, err := q.IntelToolDescription(ctx, org, conn, tool)
		switch {
		case err == nil:
			more, err := intelapp.DescriptionHits(ctx, q, desc)
			if err != nil {
				return out, err
			}
			hits = append(hits, more...)
		case !db.IsNoRows(err):
			return out, err
		}
	}
	for _, h := range hits {
		out.Hits = append(out.Hits, pipeline.IntelHit{ID: h.ID, Kind: string(h.Kind)})
	}
	return out, nil
}
