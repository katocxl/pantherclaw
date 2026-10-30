// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"net/url"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Entitlements reports the current edition (billing.Service).
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// ErrEdition is what an edition without the coverage graph gets, the code
// the breach radius gate answers with.
var ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
	"the coverage graph needs the Team edition or above")

// Graph node kinds and route controls (F277).
const (
	NodeAgent  = "AGENT"
	NodeScope  = "SCOPE"
	NodeRoute  = "ROUTE"
	NodeTarget = "TARGET"

	ControlTested     = "TESTED"
	ControlPossible   = "POSSIBLE"
	ControlExcluded   = "EXCLUDED"
	ControlUnverified = "UNVERIFIED"

	// BoundaryUnknown is the boundary state of a graph the caller cannot
	// see whole: a hidden scope could be weaker (HR-402).
	BoundaryUnknown = "UNKNOWN"
)

// MaxGraphScopes caps the scopes a graph reads; a graph cut there is
// scope-limited.
const MaxGraphScopes = 200

// RouteControl is what a route's status says about its control (F277):
// mediated or closed routes are tested, and anything the evidence does not
// establish is unverified, never controlled (HR-402).
func RouteControl(status string) string {
	switch domain.RouteStatus(status) {
	case domain.StatusMediated, domain.StatusClosed:
		return ControlTested
	case domain.StatusPossible:
		return ControlPossible
	case domain.StatusExcluded:
		return ControlExcluded
	case domain.StatusMonitored, domain.StatusCooperative, domain.StatusOpaque, domain.StatusNotObserved, domain.StatusProposed:
		return ControlUnverified
	default:
		return ControlUnverified
	}
}

// GraphNode is one node of a coverage graph.
type GraphNode struct {
	ID, Kind, Label                          string
	RouteKind, RouteStatus, Control, Closure string
}

// GraphEdge joins two nodes.
type GraphEdge struct{ From, To string }

// Graph is an agent's coverage as a graph (F277).
type Graph struct {
	Nodes         []GraphNode
	Edges         []GraphEdge
	BoundaryState string
	ScopeLimited  bool
}

// GraphTarget is where a connection's routes go: its base URL's host, or
// the connection itself when it has none.
type GraphTarget struct{ ID, Label string }

// GraphScope is one scope's record as a graph reads it.
type GraphScope struct {
	Scope    domain.Scope
	State    domain.State
	Excluded bool
	Routes   []SnapshotRoute
	Target   GraphTarget
}

// AssembleGraph builds an agent's graph from its scopes. Scopes the caller
// may not read are dropped before any node or state is built (HR-402);
// dropping one, or a cut list, makes the graph scope-limited and its
// boundary state UNKNOWN.
func AssembleGraph(agent ids.UUID, scopes []GraphScope, readable func(domain.Scope) bool, cut bool) Graph {
	shown := make([]GraphScope, 0, len(scopes))
	for _, sc := range scopes {
		if readable(sc.Scope) {
			shown = append(shown, sc)
		}
	}
	g := Graph{ScopeLimited: cut || len(shown) < len(scopes), Nodes: []GraphNode{}, Edges: []GraphEdge{}}
	seen := map[string]bool{}
	node := func(n GraphNode) {
		if !seen[n.ID] {
			seen[n.ID] = true
			g.Nodes = append(g.Nodes, n)
		}
	}
	root := "agent:" + agent.String()
	node(GraphNode{ID: root, Kind: NodeAgent, Label: agent.String()})
	states, excluded := make([]domain.State, 0, len(shown)), make([]bool, 0, len(shown))
	for _, sc := range shown {
		states, excluded = append(states, sc.State), append(excluded, sc.Excluded)
		scope := "scope:" + sc.Scope.Connection.String() + "/" + sc.Scope.Operation
		node(GraphNode{ID: scope, Kind: NodeScope, Label: sc.Scope.Operation})
		g.Edges = append(g.Edges, GraphEdge{From: root, To: scope})
		target := "target:" + sc.Target.ID
		node(GraphNode{ID: target, Kind: NodeTarget, Label: sc.Target.Label})
		for _, rt := range sc.Routes {
			key := rt.Route
			if key == "" {
				key = rt.Kind
			}
			id := "route:" + sc.Scope.Connection.String() + "/" + sc.Scope.Operation + "/" + key
			label := rt.Channel
			if label == "" {
				label = rt.Kind
			}
			node(GraphNode{
				ID: id, Kind: NodeRoute, Label: label, RouteKind: rt.Kind, RouteStatus: rt.Status,
				Control: RouteControl(rt.Status), Closure: rt.Closure,
			})
			g.Edges = append(g.Edges, GraphEdge{From: scope, To: id}, GraphEdge{From: id, To: target})
		}
	}
	g.BoundaryState = string(Protection(states, excluded))
	if g.ScopeLimited {
		g.BoundaryState = BoundaryUnknown
	}
	return g
}

// GraphFilter narrows a graph to one connection and/or operation.
type GraphFilter struct {
	Connection *ids.UUID
	Operation  *string
}

// GetCoverageGraph returns an agent's coverage graph (F277; Team edition
// and above). The caller needs coverage.read over the agent; each scope is
// read as its record reads now.
func (s *Service) GetCoverageGraph(ctx context.Context, agent ids.UUID, f GraphFilter) (Graph, error) {
	if s.Ents == nil {
		return Graph{}, ErrEdition
	}
	ent, err := s.Ents.Current(ctx)
	if err != nil {
		return Graph{}, err
	}
	if !ent.CoverageGraph() {
		return Graph{}, ErrEdition
	}
	var out Graph
	err = s.read(ctx, func(ctx context.Context, r *readers) error {
		if ok, err := r.can(ctx, &agent); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil || !ok {
			return orNotFound(err)
		}
		rows, err := r.q.ListCurrentCoverageSnapshotsPage(ctx, dbq.ListCurrentCoverageSnapshotsPageParams{
			OrgID: r.c.Org, ConnectionID: f.Connection, AgentID: &agent, Operation: f.Operation, MaxRows: MaxGraphScopes + 1,
		})
		if err != nil {
			return err
		}
		cut := len(rows) > MaxGraphScopes
		if cut {
			rows = rows[:MaxGraphScopes]
		}
		// Readable before assembly (HR-402): the scopes are the agent's,
		// whose coverage.read was checked above; each is checked again so
		// nothing unreadable reaches a node or the boundary state.
		readable := map[ids.UUID]bool{}
		for _, row := range rows {
			if _, ok := readable[row.AgentID]; !ok {
				ok, err := r.can(ctx, &row.AgentID)
				if err != nil {
					return err
				}
				readable[row.AgentID] = ok
			}
		}
		pkgs, now, targets := packages{}, s.now(), map[ids.UUID]GraphTarget{}
		var scopes []GraphScope
		for i := range rows {
			row := rows[i]
			sc := domain.Scope{Agent: row.AgentID, Connection: row.ConnectionID, Operation: row.Operation}
			if !readable[row.AgentID] {
				scopes = append(scopes, GraphScope{Scope: sc})
				continue
			}
			rec, err := s.record(ctx, r.tx, sc, &row, false, pkgs, now)
			if err != nil {
				return err
			}
			routes := rec.Body.Routes
			if rec.Recomputed != nil {
				routes = snapshotOf(sc, *rec.Recomputed, nil).Routes
			}
			target, ok := targets[sc.Connection]
			if !ok {
				if target, err = graphTarget(ctx, r.q, r.c.Org, sc.Connection); err != nil {
					return err
				}
				targets[sc.Connection] = target
			}
			scopes = append(scopes, GraphScope{
				Scope: sc, State: rec.State, Excluded: len(rec.Body.Exclusions) > 0, Routes: routes, Target: target,
			})
		}
		out = AssembleGraph(agent, scopes, func(sc domain.Scope) bool { return readable[sc.Agent] }, cut)
		return nil
	})
	return out, err
}

// graphTarget is a connection's target: its base URL's host, or the
// connection, named, when it has none. A route's locator is never used: it
// is untrusted text.
func graphTarget(ctx context.Context, q *dbq.Queries, org ids.OrgID, connection ids.UUID) (GraphTarget, error) {
	c, err := q.GetConnection(ctx, org, connection)
	if err != nil {
		return GraphTarget{}, err
	}
	if c.BaseUrl != nil {
		if u, err := url.Parse(*c.BaseUrl); err == nil && u.Hostname() != "" {
			return GraphTarget{ID: u.Hostname(), Label: u.Hostname()}, nil
		}
	}
	return GraphTarget{ID: connection.String(), Label: c.Name}, nil
}
