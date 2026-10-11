// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// packages caches decoded package versions for one reassessment.
type packages map[ids.UUID]*defs.Package

func (p packages) get(ctx context.Context, q *dbq.Queries, org ids.OrgID, version ids.UUID) (*defs.Package, error) {
	if pkg, ok := p[version]; ok {
		return pkg, nil
	}
	raw, err := q.GetPackageVersionRaw(ctx, org, version)
	if err != nil {
		return nil, err
	}
	pkg, err := manifest.Decode(raw)
	if err != nil {
		return nil, err
	}
	p[version] = pkg
	return pkg, nil
}

// routeModes are the current modes of the package routes that carry an
// operation, per channel: a route without a mode of its own has the
// connection's default, and a channel with routes in both modes is in
// monitor mode. The SDK face maps through any of the package's mappings
// (G0 M8 decision 1), so it takes the weakest mode of them all. A channel
// without a mapping has no mode: it never counts as enforced.
func routeModes(pkg *defs.Package, operation, defaultMode string, routes []dbq.PcConnectionRoute) map[domain.Channel]string {
	set := map[string]string{}
	for _, r := range routes {
		set[r.Route] = r.Mode
	}
	out := map[domain.Channel]string{}
	weaken := func(ch domain.Channel, mode string) {
		if out[ch] == "" || mode == "monitor" {
			out[ch] = mode
		}
	}
	for _, d := range pkg.Definitions {
		if d.Operation != operation {
			continue
		}
		for _, m := range d.Mappings {
			mode := defaultMode
			if v, ok := set[m.Route]; ok {
				mode = v
			}
			weaken(domain.Channel(m.Channel), mode)
			weaken(domain.ChannelSDK, mode)
		}
	}
	return out
}

// evidence loads what domain.Compute reads for one scope, at now.
func evidence(ctx context.Context, q *dbq.Queries, org ids.OrgID, sc domain.Scope, now time.Time, pkgs packages) (domain.Evidence, error) {
	e := domain.Evidence{Scope: sc, Now: now}
	b, err := q.CoverageBinding(ctx, org, sc.Connection)
	if err != nil {
		return e, err
	}
	e.Connection = domain.Connection{Kind: b.Kind, State: b.State, Revision: b.Revision, Gateway: b.GatewayID}
	if b.PackageVersionID != nil {
		e.Connection.PackageVersion = *b.PackageVersionID
		pkg, err := pkgs.get(ctx, q, org, *b.PackageVersionID)
		if err != nil {
			return e, err
		}
		routes, err := q.ListConnectionRoutes(ctx, org, sc.Connection)
		if err != nil {
			return e, err
		}
		e.Connection.RouteModes = routeModes(pkg, sc.Operation, b.DefaultMode, routes)
	}
	rows, err := q.CoverageRoutesForScope(ctx, dbq.CoverageRoutesForScopeParams{
		OrgID: org, ConnectionID: sc.Connection, AgentID: &sc.Agent, Operation: sc.Operation,
	})
	if err != nil {
		return e, err
	}
	for _, r := range rows {
		if r.Kind == string(domain.KindChannel) {
			if r.Observation == "observed" && r.Source == "gateway" && r.Channel != nil && r.Mode != nil {
				e.Traffic = append(e.Traffic, domain.Traffic{Channel: domain.Channel(*r.Channel), Mode: *r.Mode})
			}
			continue
		}
		e.Routes = append(e.Routes, domain.Route{
			ID: r.ID, Kind: domain.RouteKind(r.Kind), Locator: deref(r.Locator), Observation: r.Observation,
		})
	}
	since := time.Time{}
	switch c, err := q.LatestCoverageClosure(ctx, org, sc.Agent, sc.Connection); {
	case err == nil:
		rec := &domain.ClosureRecord{
			ID: c.ID, Agent: c.AgentID, Connection: c.ConnectionID, SessionStartedAt: c.SessionStartedAt,
			ObservedAt: c.ObservedAt, ExpiresAt: c.ExpiresAt, Revision: c.ConnectionRevision, Gateway: c.GatewayID,
			PackageVersion: c.PackageVersionID,
		}
		if err := json.Unmarshal(c.Probes, &rec.Probes); err != nil {
			return e, err
		}
		e.Closure, since = rec, c.SessionStartedAt
	case !db.IsNoRows(err):
		return e, err
	}
	changes, err := q.CoverageInvalidationsSince(ctx, dbq.CoverageInvalidationsSinceParams{
		OrgID: org, ConnectionID: sc.Connection, AgentID: &sc.Agent, Since: since,
	})
	if err != nil {
		return e, err
	}
	for _, ch := range changes {
		e.Changes = append(e.Changes, domain.Change{ID: ch.ID, Kind: domain.InvalidationKind(ch.Kind), OccurredAt: ch.OccurredAt})
	}
	exclusions, err := q.CoverageExclusionsForScope(ctx, dbq.CoverageExclusionsForScopeParams{
		OrgID: org, ConnectionID: sc.Connection, AgentID: &sc.Agent, Operation: sc.Operation,
	})
	if err != nil {
		return e, err
	}
	for _, x := range exclusions {
		e.Exclusions = append(e.Exclusions, domain.Exclusion{ID: x.ID, Kind: domain.RouteKind(deref(x.RouteKind))})
	}
	return e, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
