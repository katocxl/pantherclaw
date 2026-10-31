// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports is what the ranked posture queue reads through (G0 M24 D204).
package ports

import (
	"context"
	"slices"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/postureview/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Reach is what a viewer may read under one permission: every agent (All) or
// the listed ones, and with org scope (Org) the records that have no agent.
type Reach struct {
	All    bool
	Agents []ids.UUID
	Org    bool
}

// Has reports whether the reach covers a record of agent; a nil agent needs
// org scope, like a posture finding with no agent.
func (r Reach) Has(agent *ids.UUID) bool {
	if agent == nil {
		return r.Org
	}
	return r.All || slices.Contains(r.Agents, *agent)
}

// Intersect is what both reaches cover.
func (r Reach) Intersect(o Reach) Reach {
	out := Reach{All: r.All && o.All, Org: r.Org && o.Org}
	if out.All {
		return out
	}
	out.Agents = []ids.UUID{}
	switch {
	case r.All:
		out.Agents = slices.Clone(o.Agents)
	case o.All:
		out.Agents = slices.Clone(r.Agents)
	default:
		for _, a := range r.Agents {
			if slices.Contains(o.Agents, a) {
				out.Agents = append(out.Agents, a)
			}
		}
	}
	return out
}

// Viewer is who a read is for, resolved before any source runs (HR-580).
// Posture is the reach of posture.read, which the whole queue needs. Under
// reports the reach of another permission, for a source whose own records
// need one (agent.read for discovery changes, grant.read for suggestions):
// the queue never shows what the source's own read would refuse, so such a
// source returns only what Posture and Under both cover. The daily rollup
// reads as the org: its viewer reaches everything.
type Viewer struct {
	Org     ids.OrgID
	Posture Reach
	Under   func(ctx context.Context, p td.Permission) (Reach, error)
}

// Source is one source of findings. Findings reads under v and returns at
// most domain.MaxPerSource findings, and whether it had more; truncation is
// shown, never silent. It returns only what v may read; the service checks
// that again before it ranks. A source that does not apply to the caller
// returns a permission-denied or EDITION_REQUIRED error, which the read shows
// as a state of the source, never as empty.
type Source interface {
	Name() domain.Source
	Findings(ctx context.Context, v Viewer, f domain.Filter) ([]domain.Finding, bool, error)
}
