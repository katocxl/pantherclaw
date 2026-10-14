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

// TargetVerifier reads M8's target-verifier connection tests (HR-202,
// HR-210). Coverage reads it through this interface until the connection
// tests are wired in.
type TargetVerifier interface {
	// LastPassed returns when the latest passing target-verifier test of
	// operation on the connection ran, or nil when none passed. A test
	// vouches only for the operation it ran (founder decision N15): in M9
	// that is the package's `test: true` read.
	LastPassed(ctx context.Context, tx db.TenantTx, connection ids.UUID, operation string) (*time.Time, error)
}

// evidence loads what domain.Compute reads for one scope, at now.
func (s *Service) evidence(ctx context.Context, tx db.TenantTx, sc domain.Scope, now time.Time, pkgs packages) (domain.Evidence, error) {
	q, org := dbq.New(tx), tx.OrgID()
	e := domain.Evidence{Scope: sc, Now: now, TTL: s.Freshness.EnforcedTTL}
	b, err := q.CoverageBinding(ctx, org, sc.Connection)
	if err != nil {
		return e, err
	}
	e.Connection = domain.Connection{
		Kind: b.Kind, State: b.State, Revision: b.Revision, Gateway: b.GatewayID, CredentialVersion: b.CredentialVersion,
		AccessMode: b.AccessMode, RouteMode: b.DefaultMode,
	}
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
		e.ReadOnly = readOnly(pkg, sc.Operation)
	}
	rows, err := q.CoverageRoutesForScope(ctx, dbq.CoverageRoutesForScopeParams{
		OrgID: org, ConnectionID: sc.Connection, AgentID: &sc.Agent, Operation: sc.Operation,
	})
	if err != nil {
		return e, err
	}
	for _, r := range rows {
		e.Routes = append(e.Routes, domain.Route{
			ID: r.ID, Kind: domain.RouteKind(r.Kind), Channel: domain.Channel(deref(r.Channel)), Locator: deref(r.Locator),
			Observation: r.Observation,
		})
	}
	switch c, err := q.LatestCoverageClosure(ctx, org, sc.Agent, sc.Connection); {
	case err == nil:
		rec, err := closureRecord(c)
		if err != nil {
			return e, err
		}
		e.Closure = rec
		changes, err := q.CoverageInvalidationsSince(ctx, dbq.CoverageInvalidationsSinceParams{
			OrgID: org, ConnectionID: sc.Connection, AgentID: &sc.Agent, Since: c.SessionStartedAt,
		})
		if err != nil {
			return e, err
		}
		for _, ch := range changes {
			e.Changes = append(e.Changes, domain.Change{ID: ch.ID, Kind: domain.InvalidationKind(ch.Kind), OccurredAt: ch.OccurredAt})
		}
	case !db.IsNoRows(err):
		return e, err
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
	instances, err := q.CoverageInstancesOfAgent(ctx, org, sc.Agent)
	if err != nil {
		return e, err
	}
	for _, i := range instances {
		inst := domain.Instance{ID: i.ID}
		if i.SandboxSessionID != "" {
			session, err := ids.ParseUUID(i.SandboxSessionID)
			if err != nil {
				return e, err
			}
			inst.SandboxSession = &session
		}
		e.Instances = append(e.Instances, inst)
	}
	if s.Verifier != nil {
		if e.VerifiedAt, err = s.Verifier.LastPassed(ctx, tx, sc.Connection, sc.Operation); err != nil {
			return e, err
		}
	}
	return e, nil
}

// readOnly reports whether the package defines the operation, and only as a
// read. A scope of any other operation is never lifted by a
// target-verifier test in M9 (founder decision N15).
func readOnly(pkg *defs.Package, operation string) bool {
	found := false
	for _, d := range pkg.Definitions {
		if d.Operation == operation {
			if d.Access != defs.AccessRead {
				return false
			}
			found = true
		}
	}
	return found
}

// closureRecord is a stored closure as the calculus reads it.
func closureRecord(c dbq.PcCoverageClosure) (*domain.ClosureRecord, error) {
	rec := &domain.ClosureRecord{
		ID: c.ID, Agent: c.AgentID, Connection: c.ConnectionID, SandboxSession: c.SandboxSessionID,
		SessionStartedAt: c.SessionStartedAt, ObservedAt: c.ObservedAt, ExpiresAt: c.ExpiresAt,
		Bound: domain.Bound{
			ConnectionRevision: c.ConnectionRevision, Gateway: c.GatewayID, PackageVersion: c.PackageVersionID,
			CredentialVersion: c.CredentialVersion,
		},
	}
	if err := json.Unmarshal(c.Probes, &rec.Probes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(c.ConfigChecks, &rec.ConfigChecks); err != nil {
		return nil, err
	}
	return rec, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
