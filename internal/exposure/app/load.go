// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app computes and reads breach radius (G0 M10 D27–D31): it loads
// what the exposure domain reads from the org's grants, published policy,
// coverage, connections and credentials, materialises snapshots, and
// serves reads filtered by the viewer's permissions before anything is
// assembled or counted (D8, HR-254).
package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Loaded is what one computation read, with what posture derivation reads
// besides the rights.
type Loaded struct {
	Inputs domain.Inputs
	// Agents and their ownership; operations that are irreversible or have
	// no verifier; grant facts; lineage.
	Agents       []domain.AgentInfo
	Irreversible map[string]bool
	Unverified   map[string]bool
	Grants       []GrantFacts
	Descendants  map[ids.UUID][]ids.UUID
	Overreach    []dbq.ExposureOverreachRow
	Credentials  []dbq.PostureCredentialsRow
}

// GrantFacts is what posture reads of a grant.
type GrantFacts struct {
	ID        ids.UUID
	Unbounded []string
	CreatedAt time.Time
}

// Load reads the org's inputs in tx at the database's time.
func Load(ctx context.Context, tx db.TenantTx) (Loaded, error) {
	q, org := dbq.New(tx), tx.OrgID()
	now, err := q.DBNow(ctx)
	if err != nil {
		return Loaded{}, err
	}
	l := Loaded{
		Inputs:       domain.Inputs{Now: now, Coverage: map[domain.CoverageKey]domain.Coverage{}},
		Irreversible: map[string]bool{}, Unverified: map[string]bool{}, Descendants: map[ids.UUID][]ids.UUID{},
	}
	if err := l.grants(ctx, q, org); err != nil {
		return Loaded{}, err
	}
	if err := l.connections(ctx, q, org); err != nil {
		return Loaded{}, err
	}
	l.Inputs.Policy, err = policy(ctx, q, org)
	if err != nil {
		return Loaded{}, err
	}
	cov, err := q.ExposureCoverage(ctx, org)
	if err != nil {
		return Loaded{}, err
	}
	for _, c := range cov {
		state := domain.Coverage(c.State)
		// An ENFORCED snapshot past its expiry no longer vouches (HR-211).
		if state == domain.CoverageEnforced && c.ExpiresAt != nil && !c.ExpiresAt.After(now) {
			state = domain.CoveragePartial
		}
		l.Inputs.Coverage[domain.CoverageKey{Agent: c.AgentID, Connection: c.ConnectionID, Operation: c.Operation}] = state
	}
	routes, err := q.ExposureOutsideRoutes(ctx, org)
	if err != nil {
		return Loaded{}, err
	}
	for _, r := range routes {
		op := ""
		if r.Operation != nil {
			op = *r.Operation
		}
		l.Inputs.Routes = append(l.Inputs.Routes, domain.Route{Agent: r.AgentID, Connection: r.ConnectionID, Kind: r.Kind, Operation: op})
	}
	ds, err := q.ExposureDispatches(ctx, org)
	if err != nil {
		return Loaded{}, err
	}
	for _, d := range ds {
		l.Inputs.Dispatches = append(l.Inputs.Dispatches, domain.Dispatch{
			Agent: d.AgentID, Connection: d.ConnectionID, Operation: d.Operation, Count: int(d.Dispatches), Last: d.LastAt,
		})
	}
	agents, err := q.ExposureAgents(ctx, org)
	if err != nil {
		return Loaded{}, err
	}
	for _, a := range agents {
		l.Agents = append(l.Agents, domain.AgentInfo{ID: a.ID, Owned: a.Owned})
	}
	lin, err := q.ExposureGrantLineage(ctx, org)
	if err != nil {
		return Loaded{}, err
	}
	for _, x := range lin {
		l.Descendants[x.AncestorID] = append(l.Descendants[x.AncestorID], x.GrantID)
	}
	if l.Credentials, err = q.PostureCredentials(ctx, org); err != nil {
		return Loaded{}, err
	}
	return l, nil
}

func (l *Loaded) grants(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	rows, err := q.ExposureGrants(ctx, org)
	if err != nil {
		return err
	}
	for _, g := range rows {
		var b gdomain.Bounds
		if err := json.Unmarshal(g.Bounds, &b); err != nil {
			// An unreadable bounds document restricts nothing we can
			// show: count the grant as unbounded (more reach, never less).
			b = gdomain.Bounds{}
		}
		l.Inputs.Grants = append(l.Inputs.Grants, domain.Grant{
			ID: g.ID, Agent: g.AgentID, Bounds: b, NotBefore: g.NotBefore, ExpiresAt: g.ExpiresAt,
			DelegationDepth: int(g.DelegationDepth), CreatedAt: g.CreatedAt,
		})
		f := GrantFacts{ID: g.ID, CreatedAt: g.CreatedAt}
		if b.Operations == nil {
			f.Unbounded = append(f.Unbounded, "operations")
		}
		if b.Access == nil {
			f.Unbounded = append(f.Unbounded, "access")
		}
		if b.Targets == nil {
			f.Unbounded = append(f.Unbounded, "targets")
		}
		// Unbounded only when every dimension is open: a grant bounded on
		// operations alone is the normal shape.
		if len(f.Unbounded) < 3 {
			f.Unbounded = nil
		}
		l.Grants = append(l.Grants, f)
	}
	return nil
}

// operations reads a package's definitions; ok is false when it cannot.
func operations(raw []byte) ([]domain.Operation, []defs.Definition, bool) {
	if len(raw) == 0 {
		return nil, nil, false
	}
	doc, err := manifest.ToJSON(raw)
	if err != nil {
		return nil, nil, false
	}
	var p struct {
		Definitions []defs.Definition `json:"definitions"`
	}
	if err := json.Unmarshal(doc, &p); err != nil || len(p.Definitions) == 0 {
		return nil, nil, false
	}
	out := make([]domain.Operation, 0, len(p.Definitions))
	for _, d := range p.Definitions {
		out = append(out, domain.OperationOf(d))
	}
	return out, p.Definitions, true
}

func (l *Loaded) connections(ctx context.Context, q *dbq.Queries, org ids.OrgID) error {
	rows, err := q.ExposureConnections(ctx, org)
	if err != nil {
		return err
	}
	routeAgents, err := q.ExposureRouteAgents(ctx, org)
	if err != nil {
		return err
	}
	over, err := q.ExposureOverreach(ctx, org)
	if err != nil {
		return err
	}
	l.Overreach = over
	for _, r := range rows {
		c := domain.Connection{
			ID: r.ID, Name: r.Name, State: r.State, AccessMode: r.AccessMode, DestinationClass: r.DestinationClass,
		}
		var ds []defs.Definition
		c.Operations, ds, c.Known = operations(r.PackageRaw)
		for _, d := range ds {
			if d.Reversibility == defs.Irreversible {
				l.Irreversible[d.Operation] = true
			}
			if d.Verifier == nil {
				l.Unverified[d.Operation] = true
			}
		}
		for _, a := range routeAgents {
			if a.ConnectionID == r.ID {
				c.RouteAgents = append(c.RouteAgents, a.AgentID)
			}
		}
		if r.CredentialKind != nil {
			cr := &domain.CredentialInfo{Kind: *r.CredentialKind}
			if r.CredentialVersion != nil {
				cr.Version = *r.CredentialVersion
			}
			if r.CredentialCreatedAt != nil {
				cr.CreatedAt = *r.CredentialCreatedAt
			}
			// A GitHub App installation read at least once has a known
			// scope; anything else is uncertain (HR-253).
			if r.GithubReadAt != nil && len(r.GithubPermissions) > 0 {
				var perms map[string]string
				if json.Unmarshal(r.GithubPermissions, &perms) == nil {
					cr.Scopes, cr.ScopeKnown = perms, true
				}
			}
			for _, f := range over {
				if f.ConnectionID != nil && *f.ConnectionID == r.ID {
					cr.Overreach = append(cr.Overreach, f.Excess...)
				}
			}
			c.Credential = cr
		}
		c.Capabilities = capabilities(r.Capabilities)
		l.Inputs.Connections = append(l.Inputs.Connections, c)
	}
	return nil
}

// capabilities reads an approved capability declaration's held levels:
// top-level members whose value is read, write or admin.
func capabilities(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	var out []string
	for k, v := range m {
		if s, ok := v.(string); ok && slices.Contains([]string{"read", "write", "admin"}, s) {
			out = append(out, k+":"+s)
		}
	}
	slices.Sort(out)
	return out
}

func policy(ctx context.Context, q *dbq.Queries, org ids.OrgID) (domain.Policy, error) {
	v, err := q.GetPublishedPolicy(ctx, org)
	if db.IsNoRows(err) {
		return domain.Policy{Known: true}, nil // nothing published: no rule restricts
	} else if err != nil {
		return domain.Policy{}, err
	}
	var b pdomain.Bundle
	if err := json.Unmarshal(v.Bundle, &b); err != nil {
		return domain.Policy{Known: false}, nil
	}
	p := domain.Policy{Known: true}
	for _, r := range b.Rules {
		p.Rules = append(p.Rules, domain.PolicyRule{
			ID: r.ID, Kind: string(r.Kind), Operations: r.Operations,
			Unconditional: (r.When == "" || r.When == "true") && len(r.Environments) == 0 && len(r.Facts) == 0,
		})
	}
	return p, nil
}

// ErrNoSnapshot reports an org with no snapshot yet.
var ErrNoSnapshot = errors.New("exposure: no snapshot computed yet")
